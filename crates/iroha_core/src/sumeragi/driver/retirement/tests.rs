//! Admission, original refusal and physical join ownership of retired publication.

use super::*;
use std::{
    sync::{atomic::AtomicUsize, mpsc},
    thread::JoinHandle,
    time::Instant,
};

struct Publication {
    instance: Hash32,
    budget: AllocationBudget,
    owner: std::sync::OnceLock<OriginalPublicationOwner>,
    operation: Box<dyn Fn() -> Result<(), Attempt<io::Error>> + Send + Sync>,
}
impl RetiredPublication for Publication {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }
    fn bind_owner(&self, owner: OriginalPublicationOwner) -> io::Result<()> {
        owner.require_binding_thread()?;
        if !owner.belongs_to(self.instance, &self.budget) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "foreign original owner",
            ));
        }
        self.owner
            .set(owner)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "owner already bound"))
    }
    fn resume(&self, owner: &OriginalPublicationOwner) -> Result<(), Attempt<io::Error>> {
        assert!(
            self.owner
                .get()
                .is_some_and(|original| original.same_owner(owner))
        );
        owner.require_resume()?;
        (self.operation)()
    }
}
fn publication(
    budget: &AllocationBudget,
    operation: impl Fn() -> Result<(), Attempt<io::Error>> + Send + Sync + 'static,
) -> Arc<Publication> {
    Arc::new(Publication {
        instance: Hash32([17; 32]),
        budget: budget.clone(),
        owner: std::sync::OnceLock::new(),
        operation: Box::new(operation),
    })
}
fn admit(
    store: &Arc<Publication>,
    budget: &AllocationBudget,
) -> Result<(RetirementControl, RetirementJob), DriverError> {
    RetirementJob::admit(store.clone(), store.instance, budget, Backoff::default())
}
fn finished(thread: &JoinHandle<()>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    thread.is_finished()
}

#[test]
fn retired_publication_controls_require_exact_pool_identity_and_full_prepaid_capacity() {
    let bytes = ChargedShared::<Control>::allocation_layout()
        .size()
        .checked_add(ReleaseRegistration::allocation_layout().size())
        .unwrap();
    assert_eq!(RetirementJob::admission_bytes().unwrap(), bytes);
    let budget = AllocationBudget::new(bytes - 1);
    let store = publication(&budget, || panic!("admission must not perform publication"));
    assert!(
        matches!(admit(&store, &budget), Err(DriverError::Admission(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes })) if requested_bytes == bytes && limit_bytes == bytes - 1)
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let foreign = AllocationBudget::new(bytes);
    assert!(matches!(
        admit(&store, &foreign),
        Err(DriverError::RetirementIdentity)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert!(matches!(
        RetirementJob::admit(store.clone(), Hash32([18; 32]), &budget, Backoff::default()),
        Err(DriverError::RetirementIdentity)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(bytes);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    assert!(
        matches!(admit(&store, &budget), Err(DriverError::Admission(AllocationRefusal::Capacity { requested_bytes, reserved_bytes, limit_bytes, .. })) if requested_bytes == bytes && reserved_bytes == 1 && limit_bytes == bytes)
    );
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let (control, job) = admit(&store, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(Arc::strong_count(&store), 3);
    drop(job);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    assert_eq!(
        Arc::strong_count(&store),
        2,
        "the coordinator retains the original store after worker failure"
    );
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(Arc::strong_count(&store), 1);
}

#[test]
fn retired_publication_capacity_keeps_original_refusal_until_its_actual_release_and_retry() {
    let bytes = RetirementJob::admission_bytes().unwrap();
    let budget = AllocationBudget::new(bytes + 1);
    let store = publication(&budget, || Ok(()));
    let (control, mut job) = admit(&store, &budget).unwrap();
    job.bind_current();
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &refusal else {
        panic!("original occupied pool")
    };
    let original = release.clone();
    job.retry
        .refuse(Attempt::Deferred(refusal.into()), 42, Backoff::default());
    assert_eq!(job.retry.source(), Some(&original));
    assert!(
        !job.retry.ready(Millis::MAX),
        "elapsed time must not discharge original occupied capacity"
    );
    let other = AllocationBudget::new(1);
    drop(other.try_reserve_bytes(1).unwrap());
    assert!(
        !job.retry.ready(Millis::MAX),
        "a foreign pool release must not authorize this retry"
    );
    assert_eq!(budget.reserved_bytes(), bytes + 1);
    drop(held);
    assert!(job.retry.ready(0));
    assert_eq!(
        job.retry.source(),
        Some(&original),
        "the exact non-Clone refusal survives until the actual retry result"
    );
    control.retire();
    job.run();
    assert!(control.complete());
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retired_publication_source_less_refusals_use_existing_backoff_without_fabricated_wakes() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let store = publication(&budget, || Ok(()));
    let (control, mut job) = admit(&store, &budget).unwrap();
    let backoff = Backoff {
        initial: 10,
        max: 40,
    };
    job.retry.refuse(
        Attempt::Rejected(io::Error::new(
            io::ErrorKind::WouldBlock,
            "original store state is busy",
        )),
        20,
        backoff,
    );
    assert!(job.retry.source().is_none());
    assert!(!job.retry.ready(29));
    assert!(job.retry.ready(30));
    assert!(
        matches!(&job.retry.error, Some(Attempt::Rejected(error)) if error.kind() == io::ErrorKind::WouldBlock && error.to_string() == "original store state is busy")
    );
    job.retry.refuse(
        Attempt::Deferred(
            AllocationRefusal::ExceedsLimit {
                requested_bytes: 2,
                limit_bytes: 1,
            }
            .into(),
        ),
        30,
        backoff,
    );
    assert!(job.retry.source().is_none());
    assert!(!job.retry.ready(49));
    assert!(job.retry.ready(50));
    drop(job);
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct StopOnDrop<'a>(&'a RetirementControl);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[test]
fn original_joiner_physically_joins_workers_before_running_exact_publication() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let worker_ended = Arc::new(AtomicBool::new(false));
    let worker_seen = Arc::clone(&worker_ended);
    let (called, calls) = mpsc::sync_channel(1);
    let store = publication(&budget, move || {
        called
            .send((
                std::thread::current().id(),
                worker_seen.load(Ordering::Acquire),
            ))
            .unwrap();
        Ok(())
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let stop_guard = StopOnDrop(&control);
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    let original_joiner = joiner.thread.thread().id();
    let (release, wait) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = wait.recv();
        worker_ended.store(true, Ordering::Release);
    });
    control.retire();
    let thread = match joiner.handoff(vec![worker]) {
        Ok(thread) => thread,
        Err(failed) => {
            drop(release);
            for worker in failed.workers {
                let _ = worker.join();
            }
            let _ = failed.thread.join();
            panic!("original handoff");
        }
    };
    let early = calls.recv_timeout(Duration::from_millis(30));
    let premature = early.is_ok();
    let _ = release.send(());
    let call = early.or_else(|_| calls.recv_timeout(Duration::from_secs(5)));
    control.stop();
    let joined = thread.join();
    assert!(joined.is_ok());
    assert!(control.complete());
    drop(stop_guard);
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        !premature && call.as_ref() == Ok(&(original_joiner, true)),
        "original publication must wait for every successful physical worker join"
    );
    assert!(
        !premature,
        "publication cannot precede the original physical worker join"
    );
    assert_eq!(call.unwrap(), (original_joiner, true));
}

#[test]
fn final_shutdown_wakes_original_capacity_wait_and_releases_exact_retained_owners() {
    let bytes = RetirementJob::admission_bytes().unwrap();
    let budget = AllocationBudget::new(bytes + 1);
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&attempts);
    let source = budget.clone();
    let (refused, observation) = mpsc::sync_channel(1);
    let store = publication(&budget, move || {
        calls.fetch_add(1, Ordering::SeqCst);
        let refusal = source.try_reserve_bytes(1).unwrap_err();
        refused.send(()).unwrap();
        Err(Attempt::Deferred(refusal.into()))
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let stop_guard = StopOnDrop(&control);
    let held = budget.try_reserve_bytes(1).unwrap();
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    control.retire();
    let thread = joiner.handoff(Vec::new()).ok().unwrap();
    let observed = observation.recv_timeout(Duration::from_secs(5));
    control.stop();
    let stopped = finished(&thread);
    // Cleanup does not depend on the wake under test, and precedes assertions.
    thread.thread().unpark();
    let joined = thread.join();
    assert!(observed.is_ok());
    assert!(
        stopped,
        "final shutdown must wake the original joiner without an invented capacity release"
    );
    assert!(joined.is_ok());
    assert!(
        !control.complete(),
        "cancellation cannot claim synchronized publication"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size() + 1
    );
    drop(stop_guard);
    drop(control);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size() + 1
    );
    drop(held);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct RefusalDrop {
    callback: Box<dyn Fn() + Send + Sync>,
}
impl std::fmt::Debug for RefusalDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original refusal drop")
    }
}
impl std::fmt::Display for RefusalDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original refusal drop")
    }
}
impl std::error::Error for RefusalDrop {}
impl Drop for RefusalDrop {
    fn drop(&mut self) {
        (self.callback)();
    }
}

#[test]
fn replacement_refusal_callback_can_reenter_original_stop_without_a_completion_lock() {
    let bytes = RetirementJob::admission_bytes().unwrap();
    let budget = AllocationBudget::new(bytes + 1);
    let store = publication(&budget, || Ok(()));
    let (control, mut job) = admit(&store, &budget).unwrap();
    let reentry = control.clone();
    let called = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&called);
    let callback_budget = budget.clone();
    let refusal = io::Error::other(RefusalDrop {
        callback: Box::new(move || {
            // Actual admission/refund and shutdown reentry execute during old-error destruction.
            let admitted = callback_budget.try_reserve_bytes(1).unwrap();
            reentry.stop();
            drop(admitted);
            observed.store(true, Ordering::Release);
        }),
    });
    job.retry
        .refuse(Attempt::Rejected(refusal), 0, Backoff::default());
    assert!(!called.load(Ordering::Acquire));
    job.retry.refuse(
        Attempt::Rejected(io::Error::other("retry result")),
        10,
        Backoff::default(),
    );
    assert!(called.load(Ordering::Acquire));
    assert!(job.control.stop.load(Ordering::Acquire));
    assert!(
        matches!(&job.retry.error, Some(Attempt::Rejected(error)) if error.to_string() == "retry result")
    );
    drop(job);
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(Arc::strong_count(&store), 1);
}

#[test]
fn final_shutdown_before_handoff_joins_original_workers_without_starting_publication() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let store = publication(&budget, || {
        panic!("cancelled retirement must not start I/O")
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let worker_done = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&worker_done);
    let worker = std::thread::spawn(move || done.store(true, Ordering::Release));
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    control.stop();
    joiner.finish(vec![worker], false);
    assert!(worker_done.load(Ordering::Acquire));
    assert!(!control.complete());
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn panicking_publication_cannot_claim_completion_or_release_the_original_store_owner() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let store = publication(&budget, || panic!("original publication callback unwind"));
    let (control, job) = admit(&store, &budget).unwrap();
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    control.retire();
    let thread = joiner.handoff(Vec::new()).ok().unwrap();
    let joined = thread.join();
    assert!(joined.is_err());
    assert!(!control.complete());
    assert!(
        store.owner.get().unwrap().admit_append().is_err(),
        "publication unwind must leave its exact original owner terminal"
    );
    assert_eq!(
        Arc::strong_count(&store),
        2,
        "the lifecycle observer retains exact store custody across worker unwind"
    );
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_joiner_retries_capacity_only_after_real_release_on_the_same_thread() {
    for release_before_refusal_returns in [true, false] {
        let bytes = RetirementJob::admission_bytes().unwrap();
        let budget = AllocationBudget::new(bytes + 1);
        let source = budget.clone();
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&attempts);
        let (refused, refusal_seen) = mpsc::sync_channel(1);
        let (resume, resumed) = mpsc::sync_channel(1);
        let resumed = parking_lot::Mutex::new(resumed);
        let (completed, completion_seen) = mpsc::sync_channel(1);
        let store = publication(&budget, move || {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            let result = source.try_reserve_bytes(1);
            if attempt == 0 {
                refused
                    .send((std::thread::current().id(), result.is_err()))
                    .unwrap();
                // Exercise both release-before-registration and ordinary parked retry.
                // A failed parent observation still cannot leave this worker blocked.
                let _ = resumed.lock().recv_timeout(Duration::from_secs(5));
            }
            match result {
                Ok(original) => {
                    drop(original);
                    completed.send(std::thread::current().id()).unwrap();
                    Ok(())
                }
                Err(original) => Err(Attempt::Deferred(original.into())),
            }
        });
        let (control, job) = admit(&store, &budget).unwrap();
        let stop_guard = StopOnDrop(&control);
        let held = budget.try_reserve_bytes(1).unwrap();
        let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
        let original_thread = joiner.thread.thread().id();
        control.retire();
        let thread = joiner.handoff(Vec::new()).ok().unwrap();
        let first = refusal_seen.recv_timeout(Duration::from_secs(5));
        let (premature, attempts_before_release) = if release_before_refusal_returns {
            let pending = completion_seen.try_recv();
            let count = attempts.load(Ordering::SeqCst);
            drop(held);
            let _ = resume.send(());
            (pending.is_ok(), count)
        } else {
            let _ = resume.send(());
            // Longer than the configured initial backoff; only actual release is eligible.
            let pending = completion_seen.recv_timeout(Duration::from_millis(30));
            let count = attempts.load(Ordering::SeqCst);
            drop(held);
            (pending.is_ok(), count)
        };
        let completion = completion_seen.recv_timeout(Duration::from_secs(5));
        control.stop();
        // Independent cleanup unpark cannot manufacture a successful assertion below.
        thread.thread().unpark();
        let joined = thread.join();
        assert_eq!(first.unwrap(), (original_thread, true));
        assert!(!premature);
        assert_eq!(
            attempts_before_release, 1,
            "the original occupied pool must suppress native retries even after a timer deadline"
        );
        assert_eq!(
            completion.unwrap(),
            original_thread,
            "actual release must resume the same prestarted joiner"
        );
        assert!(joined.is_ok());
        assert!(control.complete());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        drop(stop_guard);
        drop(control);
        assert_eq!(Arc::strong_count(&store), 1);
        assert_eq!(
            budget.reserved_bytes(),
            ChargedShared::<Control>::allocation_layout().size()
        );
        drop(store);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_worker_panic_never_authorizes_publication_or_retirement_success() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let store = publication(&budget, move || {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    let (panicked, observed) = mpsc::sync_channel(1);
    let first = std::thread::spawn(move || {
        panicked.send(()).unwrap();
        panic!("original physical worker panic");
    });
    let (release, resume) = mpsc::sync_channel(1);
    let last = std::thread::spawn(move || {
        let _ = resume.recv();
    });
    control.retire();
    let thread = joiner.handoff(vec![first, last]).ok().unwrap();
    let first_ended = observed.recv_timeout(Duration::from_secs(5));
    let pending_last_join = !thread.is_finished();
    let calls_before_join = calls.load(Ordering::SeqCst);
    let _ = release.send(());
    let joined = thread.join();
    let original_failure = joined.as_ref().err().is_some_and(|error| {
        error.downcast_ref::<&str>() == Some(&"original physical worker panic")
    });
    let completed = control.complete();
    let refused_append = store.owner.get().unwrap().admit_append().is_err();
    let calls_after_join = calls.load(Ordering::SeqCst);
    let retained_original = Arc::strong_count(&store) == 2;
    drop(joined);
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(first_ended.is_ok() && pending_last_join);
    assert_eq!(calls_before_join, 0);
    assert!(retained_original);
    assert!(
        refused_append,
        "failed physical joins must close original append admission"
    );
    assert!(
        original_failure && !completed && calls_after_join == 0,
        "a failed original worker join must retain failure and never authorize publication"
    );
}

#[test]
fn retirement_waits_for_every_original_append_permit_before_native_continuation() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let (called, calls) = mpsc::sync_channel(1);
    let store = publication(&budget, move || {
        called.send(std::thread::current().id()).unwrap();
        Ok(())
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
    control.wait_bound().unwrap();
    let original_thread = joiner.thread.thread().id();
    let owner = store.owner.get().unwrap().clone();
    let first = owner.admit_append().unwrap();
    let last = owner.admit_append().unwrap();
    control.retire();
    let closed = owner.admit_append().is_err();
    let thread = joiner.handoff(Vec::new()).ok().unwrap();
    let early = calls.recv_timeout(Duration::from_millis(30));
    let complete_with_both = control.complete();
    drop(first);
    let after_one = calls.recv_timeout(Duration::from_millis(30));
    let complete_with_last = control.complete();
    drop(last);
    let actual = calls.recv_timeout(Duration::from_secs(5));
    control.stop();
    let joined = thread.join();
    drop(owner);
    drop(control);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(joined.is_ok());
    assert!(closed);
    assert!(
        early.is_err()
            && after_one.is_err()
            && !complete_with_both
            && !complete_with_last
            && actual == Ok(original_thread),
        "original retirement must wait for every admitted append permit before native continuation"
    );
}

#[derive(Debug)]
struct OriginalBindingFailure(Arc<()>);
impl std::fmt::Display for OriginalBindingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original native binding refusal")
    }
}
impl std::error::Error for OriginalBindingFailure {}

struct RefusedBinding {
    budget: AllocationBudget,
    source: Arc<()>,
    panic_after_binding: bool,
}
impl RetiredPublication for RefusedBinding {
    fn instance(&self) -> Hash32 {
        Hash32([17; 32])
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }
    fn bind_owner(&self, owner: OriginalPublicationOwner) -> io::Result<()> {
        owner.require_binding_thread()?;
        if self.panic_after_binding {
            panic!("original binding panic");
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            OriginalBindingFailure(self.source.clone()),
        ))
    }
    fn resume(&self, _: &OriginalPublicationOwner) -> Result<(), Attempt<io::Error>> {
        panic!("refused binding cannot authorize publication")
    }
}

#[test]
fn original_binding_refusal_and_panic_wake_readiness_without_losing_their_source() {
    for panics in [false, true] {
        let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
        let source = Arc::new(());
        let store = Arc::new(RefusedBinding {
            budget: budget.clone(),
            source: source.clone(),
            panic_after_binding: panics,
        });
        let (control, job) =
            RetirementJob::admit(store.clone(), store.instance(), &budget, Backoff::default())
                .unwrap();
        let super::super::DriverJoiner { workers, thread } =
            super::super::DriverJoiner::start(Some(job)).unwrap();
        let result = control.wait_bound();
        let exact = match &result {
            Err(DriverError::RetirementBinding(error)) if panics => {
                error.kind() == io::ErrorKind::BrokenPipe
            }
            Err(DriverError::RetirementBinding(error)) => error
                .get_ref()
                .and_then(|source| source.downcast_ref::<OriginalBindingFailure>())
                .is_some_and(|original| Arc::ptr_eq(&original.0, &source)),
            _ => false,
        };
        drop(workers);
        let joined = thread.join();
        let original_panic = joined
            .as_ref()
            .err()
            .is_some_and(|error| error.downcast_ref::<&str>() == Some(&"original binding panic"));
        assert!(!control.complete());
        drop((result, joined, control, store));
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            exact,
            "readiness retains the actual binding refusal or original joiner panic boundary"
        );
        assert_eq!(original_panic, panics);
        assert_eq!(Arc::strong_count(&source), 1);
    }
}

struct HeldBinding {
    original: Arc<Publication>,
    entered: mpsc::SyncSender<()>,
    release: parking_lot::Mutex<mpsc::Receiver<()>>,
}
impl RetiredPublication for HeldBinding {
    fn instance(&self) -> Hash32 {
        self.original.instance
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.original.budget.same_pool(budget)
    }
    fn bind_owner(&self, owner: OriginalPublicationOwner) -> io::Result<()> {
        self.original.bind_owner(owner)?;
        self.entered.send(()).map_err(io::Error::other)?;
        self.release.lock().recv().map_err(io::Error::other)
    }
    fn resume(&self, owner: &OriginalPublicationOwner) -> Result<(), Attempt<io::Error>> {
        self.original.resume(owner)
    }
}

#[test]
fn stop_before_or_during_original_binding_never_acknowledges_live_append_readiness() {
    for stop_before_bind in [true, false] {
        let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
        let original = publication(&budget, || panic!("stopped binding cannot publish"));
        let (entered, observed) = mpsc::sync_channel(1);
        let (release, resumed) = mpsc::sync_channel(1);
        let store = Arc::new(HeldBinding {
            original: original.clone(),
            entered,
            release: parking_lot::Mutex::new(resumed),
        });
        let (control, job) =
            RetirementJob::admit(store.clone(), store.instance(), &budget, Backoff::default())
                .unwrap();
        if stop_before_bind {
            control.stop();
        }
        let joiner = super::super::DriverJoiner::start(Some(job)).unwrap();
        let entered = observed.recv_timeout(Duration::from_secs(5));
        let before_ready = original
            .owner
            .get()
            .is_some_and(|owner| owner.admit_append().is_err());
        if !stop_before_bind {
            control.stop();
        }
        // Complete only the actual original binding; stop never fabricates Ready.
        let _ = release.send(());
        let readiness = control.wait_bound();
        let stopped = matches!(&readiness, Err(DriverError::RetirementBinding(error))
            if error.kind() == io::ErrorKind::Interrupted);
        let thread = joiner.handoff(Vec::new()).ok().unwrap();
        let joined = thread.join();
        let terminal = original.owner.get().unwrap().admit_append().is_err();
        assert!(!control.complete());
        drop((readiness, control, store));
        assert_eq!(
            budget.reserved_bytes(),
            ChargedShared::<Control>::allocation_layout().size()
        );
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(joined.is_ok());
        assert!(
            entered.is_ok() && before_ready && stopped && terminal,
            "stop around original binding must preserve completion ordering and terminal append ownership"
        );
    }
}

#[test]
fn final_stop_drains_original_append_permit_without_retrying_publication() {
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let store = publication(&budget, move || {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let (ended, observed) = mpsc::sync_channel(1);
    let joiner = super::super::DriverJoiner::start_with(move |receive| {
        super::super::DriverJoiner::join_workers(receive, Some(job));
        let _ = ended.send(());
    })
    .unwrap();
    control.wait_bound().unwrap();
    let owner = store.owner.get().unwrap().clone();
    let original = owner.admit_append().unwrap();
    control.stop();
    let rejects_new = owner.admit_append().is_err();
    let thread = joiner.handoff(Vec::new()).ok().unwrap();
    let early = observed.recv_timeout(Duration::from_secs(5));
    let premature = early.is_ok();
    let calls_while_held = calls.load(Ordering::SeqCst);
    drop(original);
    let ended = early.or_else(|_| observed.recv_timeout(Duration::from_secs(5)));
    let joined = thread.join();
    let resumed = control.complete() || calls.load(Ordering::SeqCst) != 0;
    drop((owner, control));
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(joined.is_ok() && ended.is_ok());
    assert!(rejects_new);
    assert_eq!(calls_while_held, 0);
    assert!(
        !premature && !resumed,
        "final stop must drain every admitted append permit without retrying publication"
    );
}

#[test]
fn original_worker_panics_keep_secondary_payloads_until_every_physical_join_finishes() {
    use crate::sumeragi::driver::worker_panic::tests::{
        PanicWorkers, join_barrier, with_before_join,
    };
    let mut workers = PanicWorkers::new();
    let budget = AllocationBudget::new(RetirementJob::admission_bytes().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let store = publication(&budget, move || {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let (control, job) = admit(&store, &budget).unwrap();
    let (hook, observed, release_hook) = join_barrier();
    let joiner = super::super::DriverJoiner::start_with(move |receive| {
        with_before_join(hook, || {
            super::super::DriverJoiner::join_workers(receive, Some(job))
        });
    })
    .unwrap();
    control.retire();
    let thread = joiner
        .handoff(std::mem::take(&mut workers.handles))
        .ok()
        .unwrap();
    let entered = observed.recv_timeout(Duration::from_secs(5));
    let early = workers.premature.load(Ordering::SeqCst);
    let retained = workers.budget.reserved_bytes();
    let uncompleted = !thread.is_finished();
    workers.release();
    let _ = release_hook.send(());
    let joined = thread.join();
    let exact_first = joined
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<Arc<()>>())
        .is_some_and(|error| Arc::ptr_eq(error, &workers.original));
    let exact_box = joined.as_ref().err().is_some_and(|error| {
        std::ptr::from_ref(error.as_ref()).cast::<()>() as usize == workers.original_address
    });
    let completed = control.complete();
    let append_refused = store.owner.get().unwrap().admit_append().is_err();
    let publication_calls = calls.load(Ordering::SeqCst);
    drop(joined);
    drop(control);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        ChargedShared::<Control>::allocation_layout().size()
    );
    drop(store);
    assert_eq!(budget.reserved_bytes(), 0);
    workers.assert_clean();
    assert!(entered.is_ok() && uncompleted);
    assert!(
        exact_first && exact_box,
        "complete cleanup must preserve the first original panic identity"
    );
    assert!(!completed && append_refused && publication_calls == 0);
    assert!(
        !early && retained == 1,
        "secondary panic payloads must remain owned until every original worker physically joins"
    );
}
