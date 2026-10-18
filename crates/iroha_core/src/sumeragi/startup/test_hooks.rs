//! One-shot original-owner observations for genesis resource regressions.
//!
//! Test callbacks run on the invoking fixture thread, after actual construction or
//! execution and before the named owner. They do not replace validation/execution.

use crate::state::CapturedExecWitness;
use iroha_allocation::AllocationBudget;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Validation,
    LaneProof,
    ResultPreimage,
    Certificate,
}
type Hook = Box<dyn FnOnce(&AllocationBudget, Option<&mut CapturedExecWitness>)>;
thread_local! {
    static HOOK: RefCell<Option<(Phase, Hook)>> = const { RefCell::new(None) };
}
pub(crate) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        HOOK.with(|hook| {
            hook.borrow_mut().take();
        });
    }
}
pub(crate) fn install(
    phase: Phase,
    hook: impl FnOnce(&AllocationBudget, Option<&mut CapturedExecWitness>) + 'static,
) -> Guard {
    HOOK.with(|current| {
        assert!(
            current.borrow().is_none(),
            "one original genesis observation per thread"
        );
        *current.borrow_mut() = Some((phase, Box::new(hook)));
    });
    Guard
}
pub(crate) fn run(
    phase: Phase,
    budget: &AllocationBudget,
    witness: Option<&mut CapturedExecWitness>,
) {
    let original = HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(expected, _)| *expected == phase)
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = original {
        hook(budget, witness);
    }
}
