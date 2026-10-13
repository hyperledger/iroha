//! Engine tests that need more than the shared scenarios: durable files, custody, observers.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{
    contract::{WorkflowErrorCode, WorkflowKindV1, WorkflowStage, WorkflowStatusV1},
    engine::{
        BuiltStepPayload, CommittedOutcome, DispatchOutcome, RoundContext, RoundRecovery,
        RoundReport, RoundStatusReport, StepContext, StepFailure, SystemWorkflowClock,
        WorkflowAccount, WorkflowClock, WorkflowDriver, WorkflowEngine, WorkflowFuture,
        WorkflowLedger, WorkflowObserver, WorkflowRunOptions,
    },
    journal::{
        CustodyHandleV1, Digest32, DriverIdentityV1, StepDescriptorV1, TransactionIdentityV1,
        TransactionInputV1, WorkflowBindingV1, WorkflowId, WorkflowJournalV1, WorkflowPlanV1,
        WorkflowProgressV1,
    },
    journal_tests::encode_unchecked,
    storage::{
        FileWorkflowStorage, MemoryWorkflowStorage, WorkflowRunnerLease, WorkflowStorage,
        WorkflowStorageDurability, WorkflowStorageError, WorkflowStorageErrorKind,
    },
    testing::{
        FakeDispatch, FakeSign, FakeStatus, FakeWorkflowWorld, fixture_digest,
        run_until_interrupted,
    },
};

fn binding() -> WorkflowBindingV1 {
    WorkflowBindingV1 {
        network: "fixture-network".to_owned(),
        authority: "fixture-authority".to_owned(),
    }
}

fn driver_identity() -> DriverIdentityV1 {
    DriverIdentityV1 {
        id: "engine-test-driver".to_owned(),
        schema_version: 1,
    }
}

fn plan(steps: Vec<StepDescriptorV1>) -> WorkflowPlanV1 {
    WorkflowPlanV1 {
        kind: WorkflowKindV1::Dkg,
        instance: "engine-test".to_owned(),
        driver: driver_identity(),
        request_context_digest: fixture_digest("context:engine-test"),
        steps,
    }
}

fn single_transaction() -> WorkflowPlanV1 {
    plan(vec![StepDescriptorV1::transaction(
        "register",
        fixture_digest("intent:register"),
    )])
}

fn engine(world: &Arc<FakeWorkflowWorld>, storage: Arc<dyn WorkflowStorage>) -> WorkflowEngine {
    let account: Arc<dyn WorkflowAccount> = world.clone();
    let ledger: Arc<dyn WorkflowLedger> = world.clone();
    let clock: Arc<dyn WorkflowClock> = world.clone();
    WorkflowEngine::new(storage, account, ledger, clock)
}

fn world() -> Arc<FakeWorkflowWorld> {
    Arc::new(FakeWorkflowWorld::new(binding()))
}

#[test]
fn journal_read_refusal_preserves_stored_custody_and_cancellation_retries() {
    let world = world();
    let storage = Arc::new(MemoryWorkflowStorage::new());
    let mut journal = WorkflowJournalV1::new(&single_transaction(), &binding(), 7).unwrap();
    journal.sequence = 1;
    let id = journal.id();
    let original = journal.encode_record().unwrap();
    storage.compare_and_store(&id, None, &original).unwrap();
    let storage_owner: Arc<dyn WorkflowStorage> = storage.clone();
    let engine = engine(&world, storage_owner);
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let (progress, usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || engine.progress_by_id(id));
    assert_eq!(progress.unwrap(), Some(journal.progress()));
    assert!(usage.total_allocated_bytes() > 0);
    for allocation in [0, usage.total_allocated_bytes() - 1] {
        let read_error = norito::with_decode_limits_scope(limits(allocation), || {
            engine
                .progress_by_id(id)
                .expect_err("original journal refusal")
        });
        let cancel_error = norito::with_decode_limits_scope(limits(allocation), || {
            engine
                .cancel_by_id(id)
                .expect_err("cancellation must first read its exact journal")
        });
        for error in [read_error, cancel_error] {
            assert_eq!(error.code, WorkflowErrorCode::LocalResourceUnavailable);
            assert!(error.is_resumable());
            assert!(error.progress.is_none());
            norito::with_decode_limits_scope(limits(allocation), || {
                assert!(error.is_resumable());
            });
        }
        assert_eq!(storage.load(&id).unwrap(), Some(original.clone()));
        assert_eq!(engine.progress_by_id(id).unwrap(), Some(journal.progress()));
    }
    let cancelled = engine
        .cancel_by_id(id)
        .expect("same journal retries cancellation");
    assert!(cancelled.cancel_requested);
    assert_eq!(cancelled.sequence, 2);
}

fn options() -> WorkflowRunOptions {
    WorkflowRunOptions {
        observation_timeout: Duration::ZERO,
        ..WorkflowRunOptions::default()
    }
}

/// A dealer that keeps its secret share in its own custody and returns only a reference.
struct CustodyDriver {
    secret_share: Vec<u8>,
    custody: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl WorkflowDriver for CustodyDriver {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }

    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            // The public transcript of the earlier round is available to later steps.
            let public = context
                .journal
                .steps
                .iter()
                .filter_map(|step| step.round.as_ref())
                .filter_map(|round| round.transcript.as_ref())
                .count();
            Ok(BuiltStepPayload {
                intent_digest: context.descriptor.intent_digest,
                unsigned_payload: FakeWorkflowWorld::payload(&format!(
                    "{}#{}+{public}",
                    context.step_index, context.identity_ordinal
                )),
            })
        })
    }

    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            let reference = b"keystore://dkg/share/1".to_vec();
            self.custody
                .lock()
                .expect("custody")
                .push((reference.clone(), self.secret_share.clone()));
            let mut participants = vec![
                fixture_digest("participant:p1"),
                fixture_digest("participant:p2"),
            ];
            participants.sort_unstable();
            Ok(RoundReport::Completed {
                status: RoundStatusReport {
                    round_id: context.round_id,
                    context_digest: context.descriptor.intent_digest,
                    participants,
                },
                transcript: b"public commitments of the dealing round".to_vec(),
                custody_handles: vec![CustodyHandleV1 {
                    label: "share".to_owned(),
                    reference,
                }],
            })
        })
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_secret_held_by_the_driver_never_reaches_the_durable_journal() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = temporary.path().join("journals");
    let storage: Arc<dyn WorkflowStorage> =
        Arc::new(FileWorkflowStorage::open_or_create(&directory).expect("storage"));
    let world = world();
    let secret_share = b"SECRET-SHARE-0f3a9c5e7b1d-never-on-disk".to_vec();
    let driver = CustodyDriver {
        secret_share: secret_share.clone(),
        custody: Mutex::new(Vec::new()),
    };
    let handle = engine(&world, storage)
        .workflow(plan(vec![
            StepDescriptorV1::offchain_round("deal", fixture_digest("intent:deal"), true, 2, 1),
            StepDescriptorV1::transaction("publish", fixture_digest("intent:publish")),
        ]))
        .expect("handle");
    // Stop while the publication is unresolved so the journal still holds signed bytes.
    world.script(
        vec![FakeSign::Ok],
        vec![FakeDispatch::Outcome(DispatchOutcome::Ambiguous {
            detail: "timeout".to_owned(),
        })],
        vec![FakeStatus::Outcome(CommittedOutcome::ExactAbsence)],
    );
    let error = run_until_interrupted(&world, handle.run(&driver, &options()))
        .expect("not interrupted")
        .expect_err("unknown outcome");
    assert_eq!(error.code, WorkflowErrorCode::SubmissionOutcomeUnknown);
    assert_eq!(
        world.take_trace(),
        ["sign:1#1+1", "dispatch:1#1+1", "status:1#1+1"]
    );
    assert_eq!(driver.custody.lock().expect("custody").len(), 1);

    let mut files = 0;
    let mut directories = vec![directory];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).expect("file");
            assert!(
                !contains(&bytes, &secret_share),
                "{} must not contain the secret share",
                path.display()
            );
            if path.file_name().is_some_and(|name| name == "journal") {
                files += 1;
                // What is persisted: the custody reference, the public transcript, signed bytes.
                assert!(contains(&bytes, b"keystore://dkg/share/1"));
                assert!(contains(&bytes, b"public commitments of the dealing round"));
                assert!(contains(&bytes, b"signed:1#1+1"));
            }
        }
    }
    assert_eq!(files, 1);
    let rendered = norito::json::to_string(&error.progress.expect("progress").to_json())
        .expect("progress JSON");
    assert!(!rendered.contains("SECRET-SHARE"));
    assert!(!format!("{:?}", handle.progress()).contains("SECRET-SHARE"));
}

#[test]
fn a_file_backed_workflow_resumes_in_a_new_process_without_resubmitting() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = temporary.path().join("journals");
    let driver = CustodyDriver {
        secret_share: Vec::new(),
        custody: Mutex::new(Vec::new()),
    };
    let id = {
        // First process: the submission times out and the process exits.
        let storage: Arc<dyn WorkflowStorage> =
            Arc::new(FileWorkflowStorage::open_or_create(&directory).expect("storage"));
        assert_eq!(storage.durability(), WorkflowStorageDurability::Durable);
        let world = world();
        let handle = engine(&world, storage)
            .workflow(single_transaction())
            .expect("handle");
        world.script(
            vec![FakeSign::Ok],
            vec![FakeDispatch::Outcome(DispatchOutcome::Ambiguous {
                detail: "timeout".to_owned(),
            })],
            vec![FakeStatus::Outcome(CommittedOutcome::ExactAbsence)],
        );
        let error = run_until_interrupted(&world, handle.run(&driver, &options()))
            .expect("not interrupted")
            .expect_err("unknown");
        assert_eq!(error.code, WorkflowErrorCode::SubmissionOutcomeUnknown);
        assert!(error.transaction.is_some());
        handle.id()
    };
    // Second process: nothing is shared but the directory. The same plan and account
    // rebuild the same handle, and the first effect is a read of the original identity.
    let storage: Arc<dyn WorkflowStorage> =
        Arc::new(FileWorkflowStorage::open_or_create(&directory).expect("storage"));
    let world = world();
    let handle = engine(&world, storage)
        .workflow(single_transaction())
        .expect("handle");
    assert_eq!(handle.id(), id);
    let before = handle.progress().expect("progress").expect("journal");
    assert_eq!(before.steps[0].state, "outcome_unknown");
    assert!(before.is_partially_complete());
    world.script(
        Vec::new(),
        Vec::new(),
        vec![FakeStatus::Outcome(CommittedOutcome::Applied {
            block_height: Some(11),
        })],
    );
    let progress = run_until_interrupted(&world, handle.run(&driver, &options()))
        .expect("not interrupted")
        .expect("completed");
    assert_eq!(progress.status, WorkflowStatusV1::Completed);
    // No build, no sign, no dispatch: only the read-only reconciliation.
    assert_eq!(world.take_trace(), ["status:unknown-identity"]);
    let attempt = &progress.steps[0].identities[0];
    assert_eq!(attempt.dispatch_ordinal, 1);
    assert_eq!(
        attempt
            .evidence
            .as_ref()
            .and_then(|evidence| evidence.block_height),
        Some(11)
    );
}

#[derive(Default)]
struct Sequences(Mutex<Vec<(u64, &'static str)>>);

impl WorkflowObserver for Sequences {
    fn on_progress(&self, progress: &WorkflowProgressV1) {
        self.0
            .lock()
            .expect("sequences")
            .push((progress.sequence, progress.steps[0].state));
    }
}

#[test]
fn the_observer_sees_every_stored_record_in_order() {
    let world = world();
    let observer = Arc::new(Sequences::default());
    let reporting: Arc<dyn WorkflowObserver> = observer.clone();
    let handle = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .with_observer(reporting)
        .workflow(single_transaction())
        .expect("handle");
    assert_eq!(handle.progress().expect("progress"), None);
    world.script(
        vec![FakeSign::Ok],
        vec![FakeDispatch::Outcome(DispatchOutcome::Accepted)],
        vec![FakeStatus::Outcome(CommittedOutcome::Applied {
            block_height: None,
        })],
    );
    let driver = CustodyDriver {
        secret_share: Vec::new(),
        custody: Mutex::new(Vec::new()),
    };
    run_until_interrupted(&world, handle.run(&driver, &options()))
        .expect("not interrupted")
        .expect("completed");
    assert_eq!(
        *observer.0.lock().expect("sequences"),
        [
            (1, "planned"),
            (2, "prepared"),
            (3, "proving"),
            (4, "ready_to_sign"),
            (5, "signed"),
            (6, "submitting"),
            (7, "pending"),
            (8, "finalized"),
        ]
    );
    // The same plan and account give the same handle; another instance does not.
    let again = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(single_transaction())
        .expect("handle");
    assert_eq!(again.id(), handle.id());
    assert_eq!(again.plan(), handle.plan());
    let mut other = single_transaction();
    other.instance = "another".to_owned();
    let other = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(other)
        .expect("handle");
    assert_ne!(other.id(), handle.id());
    let debug = format!("{handle:?}");
    assert!(debug.contains("NonDurable") && debug.contains("fixture-authority"));
}

/// A driver that implements no capability.
struct NoCapabilities;

impl WorkflowDriver for NoCapabilities {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
}

#[test]
fn a_driver_without_capabilities_reports_unsupported_operation() {
    let world = world();
    let transaction = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(single_transaction())
        .expect("handle");
    let error = run_until_interrupted(&world, transaction.run(&NoCapabilities, &options()))
        .expect("not interrupted")
        .expect_err("unsupported");
    assert_eq!(
        (error.code, error.stage, error.step_index),
        (
            WorkflowErrorCode::UnsupportedOperation,
            WorkflowStage::Prove,
            Some(0)
        )
    );
    let progress = error.progress.expect("progress");
    assert_eq!(progress.steps[0].state, "prepared");
    assert_eq!(progress.status, WorkflowStatusV1::InProgress);

    let round = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(plan(vec![StepDescriptorV1::offchain_round(
            "deal",
            fixture_digest("intent:deal"),
            true,
            2,
            0,
        )]))
        .expect("handle");
    for _ in 0..2 {
        // First the start, then the recovery of the persisted round: both unsupported.
        let error = run_until_interrupted(&world, round.run(&NoCapabilities, &options()))
            .expect("not interrupted")
            .expect_err("unsupported");
        assert_eq!(
            (error.code, error.stage),
            (
                WorkflowErrorCode::UnsupportedOperation,
                WorkflowStage::Round
            )
        );
        assert_eq!(
            error.progress.expect("progress").steps[0].state,
            "round_started"
        );
    }
    assert!(world.take_trace().is_empty());
}

#[test]
fn calls_are_validated_before_any_journal_is_touched() {
    let world = world();
    let handle = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(single_transaction())
        .expect("handle");
    let zero = WorkflowRunOptions {
        poll_interval: Duration::ZERO,
        ..WorkflowRunOptions::default()
    };
    let error = run_until_interrupted(&world, handle.run(&NoCapabilities, &zero))
        .expect("not interrupted")
        .expect_err("zero poll interval");
    assert_eq!(error.code, WorkflowErrorCode::InvalidInput);
    assert_eq!(handle.progress().expect("progress"), None);

    // Read-only recovery and cancellation never create a journal.
    let error = run_until_interrupted(&world, handle.recover(None, &options()))
        .expect("not interrupted")
        .expect_err("no journal");
    assert_eq!(
        (error.code, error.stage),
        (WorkflowErrorCode::InvalidInput, WorkflowStage::Load)
    );
    let error = handle.cancel().expect_err("no journal");
    assert_eq!(
        (error.code, error.stage),
        (WorkflowErrorCode::InvalidInput, WorkflowStage::Cancel)
    );
    assert_eq!(handle.progress().expect("progress"), None);

    // An invalid plan or binding never yields a handle.
    let mut invalid = single_transaction();
    invalid.steps.clear();
    assert_eq!(
        engine(&world, Arc::new(MemoryWorkflowStorage::new()))
            .workflow(invalid)
            .expect_err("invalid plan")
            .code,
        WorkflowErrorCode::InvalidInput
    );
    let defaults = WorkflowRunOptions::default();
    assert_eq!(defaults.observation_timeout, Duration::from_secs(30));
    assert_eq!(defaults.poll_interval, Duration::from_millis(500));
    assert!(!defaults.retransmit_identical_bytes && !defaults.retry_rejected_step);
}

#[test]
fn retained_bytes_that_do_not_hash_to_their_identity_are_corruption() {
    let world = world();
    let storage = Arc::new(MemoryWorkflowStorage::new());
    let journal_storage: Arc<dyn WorkflowStorage> = storage.clone();
    let handle = engine(&world, journal_storage)
        .workflow(single_transaction())
        .expect("handle");
    // A self-consistent journal whose signed bytes belong to another identity.
    let mut journal =
        WorkflowJournalV1::new(&single_transaction(), &binding(), 1).expect("journal");
    journal.sequence = 1;
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::BuildStarted,
        TransactionInputV1::PayloadBuilt {
            payload: FakeWorkflowWorld::payload("0#1"),
        },
        TransactionInputV1::Signed {
            signed_transaction: b"signed:0#1".to_vec(),
            identity: TransactionIdentityV1 {
                signed_transaction_hash: fixture_digest("another transaction"),
                entrypoint_hash: fixture_digest("another entrypoint"),
            },
        },
    ] {
        journal.apply_transaction(0, input).expect("transition");
    }
    storage.overwrite_unchecked(&handle.id(), journal.encode_record().expect("record"));
    for result in [
        run_until_interrupted(&world, handle.run(&NoCapabilities, &options()))
            .expect("not interrupted"),
        run_until_interrupted(&world, handle.recover(None, &options())).expect("not interrupted"),
        handle.cancel(),
    ] {
        let error = result.expect_err("corrupted");
        assert_eq!(
            (error.code, error.stage, error.step_index),
            (
                WorkflowErrorCode::StorageCorrupted,
                WorkflowStage::Load,
                Some(0)
            )
        );
        assert!(error.progress.is_none());
        assert!(!error.is_resumable());
    }
    assert!(
        world.take_trace().is_empty(),
        "nothing is dispatched or read"
    );

    // Bytes that are not a signed transaction at all are corruption too.
    let mut foreign = journal;
    foreign.steps[0]
        .transaction
        .as_mut()
        .expect("operation")
        .signed_transaction = Some(b"garbage".to_vec());
    storage.overwrite_unchecked(&handle.id(), encode_unchecked(&foreign));
    assert_eq!(
        handle.progress().expect_err("corrupted").code,
        WorkflowErrorCode::StorageCorrupted
    );
}

/// A store that cannot be read.
struct Offline;

impl WorkflowStorage for Offline {
    fn durability(&self) -> WorkflowStorageDurability {
        WorkflowStorageDurability::Durable
    }

    fn load(&self, _id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        Err(WorkflowStorageError::new(
            WorkflowStorageErrorKind::Unavailable,
            "offline",
        ))
    }

    fn compare_and_store(
        &self,
        _id: &WorkflowId,
        _expected: Option<&Digest32>,
        _record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        Err(WorkflowStorageError::new(
            WorkflowStorageErrorKind::Unavailable,
            "offline",
        ))
    }

    fn acquire_runner(
        &self,
        _id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        struct Lease;
        impl WorkflowRunnerLease for Lease {}
        Ok(Box::new(Lease))
    }
}

#[test]
fn an_unreadable_store_is_a_local_resource_failure_not_an_empty_workflow() {
    let world = world();
    let handle = engine(&world, Arc::new(Offline))
        .workflow(single_transaction())
        .expect("handle");
    let error = run_until_interrupted(&world, handle.run(&NoCapabilities, &options()))
        .expect("not interrupted")
        .expect_err("offline");
    assert_eq!(
        (error.code, error.stage),
        (
            WorkflowErrorCode::LocalResourceUnavailable,
            WorkflowStage::Store
        )
    );
    assert!(error.progress.is_none());
    assert_eq!(
        handle.progress().expect_err("offline").code,
        WorkflowErrorCode::LocalResourceUnavailable
    );
    assert!(world.take_trace().is_empty());
}

#[tokio::test]
async fn the_system_clock_is_monotonic_and_sleeps_on_the_timer() {
    let clock = SystemWorkflowClock::default();
    let before = clock.now_unix_ms();
    assert!(before > 1_600_000_000_000, "Unix milliseconds");
    clock.sleep(Duration::from_millis(5)).await;
    let after = clock.now_unix_ms();
    assert!(after >= before + 5);
    assert!(SystemWorkflowClock::new().now_unix_ms() >= before);
}

/// A recovery that reports a waiting round as never started contradicts the journal.
struct Contradiction;

impl WorkflowDriver for Contradiction {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }

    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            Ok(RoundReport::Waiting(RoundStatusReport {
                round_id: context.round_id,
                context_digest: context.descriptor.intent_digest,
                participants: vec![fixture_digest("participant:p1")],
            }))
        })
    }

    fn recover_round<'a>(
        &'a self,
        _context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundRecovery, StepFailure>> {
        Box::pin(async { Ok(RoundRecovery::NotStarted) })
    }
}

/// A driver with another identity than the plan is bound to.
struct Other;

impl WorkflowDriver for Other {
    fn identity(&self) -> DriverIdentityV1 {
        DriverIdentityV1 {
            id: "other".to_owned(),
            schema_version: 1,
        }
    }
}

#[test]
fn a_waiting_round_cannot_be_recovered_as_never_started() {
    let world = world();
    let handle = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
        .workflow(plan(vec![StepDescriptorV1::offchain_round(
            "deal",
            fixture_digest("intent:deal"),
            true,
            2,
            0,
        )]))
        .expect("handle");
    let pending = run_until_interrupted(&world, handle.run(&Contradiction, &options()))
        .expect("not interrupted")
        .expect_err("waiting");
    assert_eq!(pending.code, WorkflowErrorCode::RoundPending);
    assert!(pending.detail.contains("1 of 2"));
    let error = run_until_interrupted(&world, handle.run(&Contradiction, &options()))
        .expect("not interrupted")
        .expect_err("contradiction");
    assert_eq!(
        (error.code, error.stage),
        (WorkflowErrorCode::BindingMismatch, WorkflowStage::Round)
    );
    // The recorded participant is kept: a restart never replaces a round by a fresh one.
    let progress = error.progress.expect("progress");
    assert_eq!(progress.steps[0].state, "round_waiting");
    assert_eq!(progress.steps[0].participants_received, 1);
    // A driver bound to another identity cannot recover this workflow.
    let error = run_until_interrupted(&world, handle.recover(Some(&Other), &options()))
        .expect("not interrupted")
        .expect_err("wrong driver");
    assert_eq!(error.code, WorkflowErrorCode::BindingMismatch);
}

#[path = "round_continuation_tests.rs"]
mod round_continuation_tests;
