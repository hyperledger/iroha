//! Original State index contention and joint physical cleanup controls.

use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

fn state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        World::default(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    ))
}

fn contents(state: &State) -> Vec<(&'static str, String)> {
    macro_rules! snapshot {
        ($($field:ident: $ty:ty,)*) => {{
            vec![$((stringify!($field), format!("{:?}", &*state.$field.read())),)*]
        }};
    }
    effect_indexes!(snapshot)
}

/// Observe every original physical index and the outer State writer without
/// assertions, blocking, publishing, or creating replacement lock owners.
struct Probe {
    state: Arc<State>,
    calls: AtomicUsize,
    indexes_free: AtomicUsize,
    fence_free: AtomicUsize,
}

impl Probe {
    fn new(state: &Arc<State>) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::clone(state),
            calls: AtomicUsize::new(0),
            indexes_free: AtomicUsize::new(0),
            fence_free: AtomicUsize::new(0),
        })
    }

    fn inspect(&self) {
        macro_rules! probe {
            ($($field:ident: $ty:ty,)*) => {{
                let mut free = 0;
                $(free += usize::from(self.state.$field.try_write().is_some());)*
                free
            }};
        }
        let free = effect_indexes!(probe);
        self.indexes_free.fetch_add(free, Ordering::SeqCst);
        self.fence_free.fetch_add(
            usize::from(self.state.state_write_lock.try_lock().is_some()),
            Ordering::SeqCst,
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn assert_originals_released(&self) {
        assert_eq!(self.calls.load(Ordering::SeqCst), 1);
        assert_eq!(self.indexes_free.load(Ordering::SeqCst), 9);
        assert_eq!(self.fence_free.load(Ordering::SeqCst), 1);
    }
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.inspect();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.inspect();
    }
}

fn assert_physical_prefix(slot: &StateEffectLocks<'_>, blocked_index: usize) {
    macro_rules! inspect {
        ($($field:ident: $ty:ty,)*) => {{
            let mut index = 0;
            $(
                assert_eq!(slot.$field.is_some(), index < blocked_index, "retained {}", stringify!($field));
                assert_eq!(slot.target.$field.try_write().is_none(), index <= blocked_index, "physical {}", stringify!($field));
                index += 1;
            )*
            index
        }};
    }
    assert_eq!(effect_indexes!(inspect), 9);
    assert!(!slot.complete);
}

fn refusal<G>(
    state: &Arc<State>,
    blocker: G,
    expected: iroha_allocation::release::ReleaseWait,
    field: &'static str,
    blocked_index: usize,
    before: &[(&'static str, String)],
    blocker_registration: &mut iroha_allocation::release::ReleaseRegistration,
    prefix_registration: &mut iroha_allocation::release::ReleaseRegistration,
) {
    // Retained cleanup precedes the outer fence, as in the real publisher.
    let mut cleanup = StateEffectLocks::new(state);
    let fence = state.state_write_lock.lock();
    let generation = state.state_view_generation();
    let (actual_field, wait) = cleanup.try_prepare().expect_err("actual original blocker");
    assert_eq!(actual_field, field);
    assert_eq!(
        wait, expected,
        "refusal must return the exact blocking source and observation"
    );
    assert_physical_prefix(&cleanup, blocked_index);
    let mut blocker_wait = wait.wait_for_release(blocker_registration);
    assert!(
        Pin::new(&mut blocker_wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let probe = Probe::new(state);
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut prefix_wait = if blocked_index > 0 {
        let mut pending = state
            .latest_block_header
            .try_write_or_wait()
            .expect_err("actual first original writer retained")
            .wait_for_release(prefix_registration);
        assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
        Some(pending)
    } else {
        None
    };
    cleanup.release_writers();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    if let Some(pending) = &mut prefix_wait {
        assert!(Pin::new(pending).poll(&mut context).is_pending());
    }
    assert!(
        Pin::new(&mut blocker_wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "earlier acquired releases cannot substitute for the actual blocker"
    );
    drop(blocker);
    assert_eq!(
        Pin::new(&mut blocker_wait).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(())
    );
    drop(fence);
    drop(cleanup);
    if let Some(pending) = &mut prefix_wait {
        probe.assert_originals_released();
        assert_eq!(Pin::new(pending).poll(&mut context), Poll::Ready(()));
    } else {
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "unacquired prefix emits no release"
        );
    }
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(
        contents(state).as_slice(),
        before,
        "refusal cannot mutate any original index"
    );
}

#[test]
fn every_effect_reader_and_writer_refusal_retains_original_prefix_and_wait() {
    let state = state();
    let mut blocker_registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let mut prefix_registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let before = contents(&state);
    macro_rules! check {
        ($($field:ident: $ty:ty,)*) => {{
            let mut index = 0;
            $(
                let held = state.$field.read();
                let expected = state.$field.try_write_or_wait().err().expect("actual original reader");
                refusal(&state, held, expected, stringify!($field), index, &before, &mut blocker_registration, &mut prefix_registration);
                let held = state.$field.write();
                let expected = state.$field.try_write_or_wait().err().expect("actual original writer");
                refusal(&state, held, expected, stringify!($field), index, &before, &mut blocker_registration, &mut prefix_registration);
                index += 1;
            )*
            index
        }};
    }
    assert_eq!(effect_indexes!(check), 9);
}

fn complete_scope(unwind: bool) {
    let state = state();
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let before = contents(&state);
    let generation = state.state_view_generation();
    let probe = Probe::new(&state);
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut cleanup = StateEffectLocks::new(&state);
    let fence = state.state_write_lock.lock();
    cleanup
        .try_prepare()
        .expect("all original physical indexes available");
    assert!(cleanup.complete);
    macro_rules! held {
        ($($field:ident: $ty:ty,)*) => { $(assert!(state.$field.try_write().is_none(), "{} held", stringify!($field));)* };
    }
    effect_indexes!(held);
    let mut pending = state
        .latest_block_header
        .try_write_or_wait()
        .expect_err("original index writer")
        .wait_for_release(&mut registration);
    assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let scope = cleanup.physical_scope();
        assert!(scope.complete);
        assert!(!unwind, "actual enclosing preparation unwind");
        drop(scope);
    }));
    assert_eq!(result.is_err(), unwind);
    assert!(!cleanup.complete);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert!(Pin::new(&mut pending).poll(&mut context).is_pending());
    drop(fence);
    drop(cleanup);
    probe.assert_originals_released();
    assert_eq!(Pin::new(&mut pending).poll(&mut context), Poll::Ready(()));
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(contents(&state), before);
}

#[test]
fn complete_effect_scope_releases_all_indexes_before_outer_fence_callbacks() {
    complete_scope(false);
}

#[test]
fn unwinding_effect_scope_releases_all_indexes_before_outer_fence_callbacks() {
    complete_scope(true);
}

#[test]
fn synchronous_effect_preparation_releases_prefix_while_waiting_for_the_last_original_index() {
    use std::{sync::mpsc, time::Duration};

    let state = state();
    let before = contents(&state);
    let blocker = state.da_indexes_hydrated.write();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let worker_state = Arc::clone(&state);
    let worker = std::thread::spawn(move || {
        let mut cleanup = StateEffectLocks::new(&worker_state);
        let mut registration =
            crate::unit_test_support::release_registration(&worker_state.ivm_execution_budget());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let _ = started_tx.send(());
        while let Err((_, wait)) = cleanup.try_prepare() {
            // The caller waits only after releasing its actual acquired prefix.
            // Retry keeps the same cleanup owner and exact source observation.
            cleanup.release_writers();
            runtime.block_on(wait.wait_for_release(&mut registration));
        }
        let complete = cleanup.complete;
        drop(cleanup);
        let _ = done_tx.send(complete);
    });
    // Record every observation before assertions. Regardless of a channel
    // timeout, release the only external blocker and join the original worker.
    let started = started_rx.recv_timeout(Duration::from_secs(5));
    let early = done_rx.recv_timeout(Duration::from_millis(50));
    macro_rules! free_prefix {
        ($($field:ident: $ty:ty,)*) => { [$(state.$field.try_write().is_some(),)*] };
    }
    let prefix = effect_indexes!(free_prefix);
    drop(blocker);
    let completed = if early.is_ok() {
        early.clone()
    } else {
        done_rx.recv_timeout(Duration::from_secs(5))
    };
    let joined = worker.join();
    assert!(started.is_ok());
    assert_eq!(early, Err(mpsc::RecvTimeoutError::Timeout));
    let (last, released_prefix) = prefix.split_last().expect("effect indexes");
    assert!(released_prefix.iter().all(|free| *free));
    assert!(
        !last,
        "the external blocker still holds the last original index"
    );
    assert_eq!(completed, Ok(true));
    assert!(joined.is_ok());
    assert_eq!(contents(&state), before);
}
