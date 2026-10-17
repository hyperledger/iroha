//! Crate-local producer-entry observations for native owner tests only.
//!
//! The probe cannot inject randomness. Production builds contain neither the
//! module nor its calls. OS seed draws and failures are tested at the PLONK owner.

use iroha_pasta::CancellationToken;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{cell::RefCell, marker::PhantomData, rc::Rc, sync::Arc};

struct State {
    entries: AtomicUsize,
    cancel: Option<CancellationToken>,
}
thread_local! {
    static ACTIVE: RefCell<Option<Arc<State>>> = const { RefCell::new(None) };
}

/// Own one thread's observations; a guard cannot move to another worker.
pub struct Guard {
    state: Arc<State>,
    thread: PhantomData<Rc<()>>,
}
impl Guard {
    pub(crate) fn new(cancel: Option<CancellationToken>) -> Self {
        let state = Arc::new(State {
            entries: AtomicUsize::new(0),
            cancel,
        });
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            assert!(active.is_none(), "one native producer probe per thread");
            *active = Some(state.clone());
        });
        Self {
            state,
            thread: PhantomData,
        }
    }
    pub(crate) fn entries(&self) -> usize {
        self.state.entries.load(Ordering::SeqCst)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(state, &self.state))
            {
                active.take();
            }
        });
    }
}

/// Mark the actual point after admitted reconstruction and witness assignment.
pub fn reached() {
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow().as_ref() {
            state.entries.fetch_add(1, Ordering::SeqCst);
            if let Some(cancel) = &state.cancel {
                cancel.cancel();
            }
        }
    });
}

#[test]
fn guard_counts_and_cancels_only_at_real_entry_and_clears_on_unwind() {
    let cancel = CancellationToken::new();
    let guard = Guard::new(Some(cancel.clone()));
    assert_eq!(guard.entries(), 0);
    assert!(!cancel.is_cancelled());
    reached();
    assert_eq!(guard.entries(), 1);
    assert!(cancel.is_cancelled());
    drop(guard);
    let outcome = std::panic::catch_unwind(|| {
        let _guard = Guard::new(None);
        panic!("probe unwind control");
    });
    assert!(outcome.is_err());
    let next = Guard::new(None);
    assert_eq!(next.entries(), 0);
    reached();
    assert_eq!(next.entries(), 1);
}

/// Exercise the actual owner boundary with no public randomness injection seam.
/// Both cancelled attempts must return an error, hence issue no proof. The
/// caller then performs a fresh successful attempt with the same metadata.
pub fn assert_owner_cancellation<T, E: core::fmt::Debug>(
    mut attempt: impl FnMut(&CancellationToken) -> Result<T, E>,
    is_cancelled: impl Fn(&E) -> bool,
) {
    let early = CancellationToken::new();
    early.cancel();
    let guard = Guard::new(None);
    let error = attempt(&early)
        .err()
        .expect("pre-cancelled owner issued no proof");
    assert!(is_cancelled(&error), "{error:?}");
    assert_eq!(
        guard.entries(),
        0,
        "pre-cancelled owner never entered prover"
    );
    drop(guard);
    let late = CancellationToken::new();
    let guard = Guard::new(Some(late.clone()));
    let error = attempt(&late)
        .err()
        .expect("late-cancelled owner issued no proof");
    assert!(is_cancelled(&error), "{error:?}");
    assert_eq!(guard.entries(), 1, "one actual post-rebuild/witness entry");
    assert!(late.is_cancelled());
}

#[test]
fn boundary_assertion_requires_no_early_entry_and_one_cancelled_late_entry() {
    assert_owner_cancellation(
        |token| {
            CancellationToken::checkpoint(Some(token))?;
            reached();
            CancellationToken::checkpoint(Some(token))
        },
        |_| true,
    );
    let next = Guard::new(None);
    assert_eq!(next.entries(), 0, "both assertion guards released");
}
