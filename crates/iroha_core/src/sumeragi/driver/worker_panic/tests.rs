//! Exact panic identity, complete physical joins and funded destructor cleanup.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationReservation};
use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

thread_local! {
    static BEFORE_JOIN: RefCell<Option<Box<dyn FnMut(usize)>>> = const { RefCell::new(None) };
}

pub(super) fn before_join(index: usize) {
    BEFORE_JOIN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(index);
        }
    });
}

/// Install only this original joining thread's deterministic observation.
pub(in crate::sumeragi::driver) fn with_before_join<R>(
    hook: impl FnMut(usize) + 'static,
    operation: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<Box<dyn FnMut(usize)>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BEFORE_JOIN.with(|hook| *hook.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(BEFORE_JOIN.with(|current| current.replace(Some(Box::new(hook)))));
    operation()
}

struct ReplacementDrop(Arc<AtomicUsize>);
impl Drop for ReplacementDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct FundedPanic {
    charge: Option<AllocationReservation>,
    drops: Arc<AtomicUsize>,
    replacement_drops: Arc<AtomicUsize>,
    completed: Arc<AtomicBool>,
    premature: Arc<AtomicBool>,
    panic_on_drop: bool,
}
impl Drop for FundedPanic {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::SeqCst) {
            self.premature.store(true, Ordering::SeqCst);
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
        drop(self.charge.take());
        if self.panic_on_drop {
            std::panic::panic_any(ReplacementDrop(self.replacement_drops.clone()));
        }
    }
}

/// Three actual workers: an identity panic, a funded destructor panic and a held last worker.
pub(in crate::sumeragi::driver) struct PanicWorkers {
    pub(in crate::sumeragi::driver) handles: Vec<JoinHandle<()>>,
    pub(in crate::sumeragi::driver) original: Arc<()>,
    pub(in crate::sumeragi::driver) original_address: usize,
    pub(in crate::sumeragi::driver) budget: AllocationBudget,
    pub(in crate::sumeragi::driver) drops: Arc<AtomicUsize>,
    pub(in crate::sumeragi::driver) replacement_drops: Arc<AtomicUsize>,
    pub(in crate::sumeragi::driver) premature: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    release: mpsc::Sender<()>,
}
impl PanicWorkers {
    pub(in crate::sumeragi::driver) fn new() -> Self {
        let original = Arc::new(());
        let budget = AllocationBudget::new(1);
        let drops = Arc::new(AtomicUsize::new(0));
        let replacement_drops = Arc::new(AtomicUsize::new(0));
        let premature = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let first: Box<dyn Any + Send> = Box::new(original.clone());
        let original_address = std::ptr::from_ref(first.as_ref()).cast::<()>() as usize;
        let second = FundedPanic {
            charge: Some(budget.try_reserve_bytes(1).unwrap()),
            drops: drops.clone(),
            replacement_drops: replacement_drops.clone(),
            completed: completed.clone(),
            premature: premature.clone(),
            panic_on_drop: true,
        };
        let (release, resume) = mpsc::channel();
        let last = completed.clone();
        let handles = vec![
            std::thread::spawn(move || std::panic::resume_unwind(first)),
            std::thread::spawn(move || std::panic::panic_any(second)),
            std::thread::spawn(move || {
                let _ = resume.recv();
                last.store(true, Ordering::SeqCst);
            }),
        ];
        Self {
            handles,
            original,
            original_address,
            budget,
            drops,
            replacement_drops,
            premature,
            completed,
            release,
        }
    }

    pub(in crate::sumeragi::driver) fn release(&self) {
        let _ = self.release.send(());
    }

    pub(in crate::sumeragi::driver) fn assert_clean(&self) {
        assert!(self.completed.load(Ordering::SeqCst));
        assert_eq!(self.drops.load(Ordering::SeqCst), 1);
        assert_eq!(self.replacement_drops.load(Ordering::SeqCst), 1);
        assert_eq!(self.budget.reserved_bytes(), 0);
        assert_eq!(Arc::strong_count(&self.original), 1);
    }
}
impl Drop for PanicWorkers {
    fn drop(&mut self) {
        self.release();
        drop(join_original_workers(std::mem::take(&mut self.handles)));
    }
}

/// A finite barrier before the third physical join; cleanup always releases it.
pub(in crate::sumeragi::driver) fn join_barrier() -> (
    impl FnMut(usize) + Send,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    (
        move |index| {
            if index == 2 {
                let _ = entered.send(());
                let _ = resume.recv();
            }
        },
        observed,
        release,
    )
}

#[test]
fn ordinary_and_panicking_payload_cleanup_releases_exact_original_funding() {
    for panic_on_drop in [false, true] {
        let budget = AllocationBudget::new(1);
        let drops = Arc::new(AtomicUsize::new(0));
        let replacement_drops = Arc::new(AtomicUsize::new(0));
        let payload = FundedPanic {
            charge: Some(budget.try_reserve_bytes(1).unwrap()),
            drops: drops.clone(),
            replacement_drops: replacement_drops.clone(),
            completed: Arc::new(AtomicBool::new(true)),
            premature: Arc::new(AtomicBool::new(false)),
            panic_on_drop,
        };
        discard_join_result(Err(Box::new(payload)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            replacement_drops.load(Ordering::SeqCst),
            usize::from(panic_on_drop)
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn suppressed_payload_panic_preserves_existing_unwind_and_releases_funding() {
    let budget = AllocationBudget::new(1);
    let drops = Arc::new(AtomicUsize::new(0));
    let replacement_drops = Arc::new(AtomicUsize::new(0));
    let payload = FundedPanic {
        charge: Some(budget.try_reserve_bytes(1).unwrap()),
        drops: drops.clone(),
        replacement_drops: replacement_drops.clone(),
        completed: Arc::new(AtomicBool::new(true)),
        premature: Arc::new(AtomicBool::new(false)),
        panic_on_drop: true,
    };
    let original = Arc::new(());
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _retained = OriginalWorkerPanic::new(Box::new(payload));
        std::panic::panic_any(original.clone());
    }));
    assert!(
        outcome
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Arc<()>>())
            .is_some_and(|error| Arc::ptr_eq(error, &original))
    );
    drop(outcome);
    assert_eq!(Arc::strong_count(&original), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(replacement_drops.load(Ordering::SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn failed_handoff_joins_every_worker_before_discarding_panic_payloads() {
    let mut workers = PanicWorkers::new();
    let handles = std::mem::take(&mut workers.handles);
    let (hook, observed, release_hook) = join_barrier();
    let cleanup = std::thread::spawn(move || {
        let (send, receive) = mpsc::sync_channel(1);
        drop(receive); // Deterministic original receiver failure before handoff.
        let thread = std::thread::spawn(|| panic!("original joining thread failed"));
        let joiner = super::super::DriverJoiner {
            workers: send,
            thread,
        };
        with_before_join(hook, || joiner.finish(handles, false));
    });
    let entered = observed.recv_timeout(Duration::from_secs(5));
    let held = workers.budget.reserved_bytes();
    let early = workers.premature.load(Ordering::SeqCst);
    workers.release();
    let _ = release_hook.send(());
    let joined = cleanup.join();
    assert!(entered.is_ok());
    assert!(joined.is_ok());
    workers.assert_clean();
    assert!(
        !early && held == 1,
        "failed handoff must join every original worker before panic-payload destruction"
    );
}
