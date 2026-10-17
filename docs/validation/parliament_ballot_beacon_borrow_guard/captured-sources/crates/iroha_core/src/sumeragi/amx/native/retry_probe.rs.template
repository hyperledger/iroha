//! Allocation-free test observation of real decoder completion and original-pool refusal.

use super::*;
use iroha_allocation::AllocationReservation;
use iroha_data_model::{account::AccountController, sumeragi_amx::AmxTransferLegV1};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    pub(crate) source: (usize, usize),
    pub(crate) keys: (usize, usize),
    pub(crate) retained_bytes: usize,
}
#[derive(Default)]
struct State {
    active: bool,
    completions: usize,
    first: Option<Sample>,
    borrowed: usize,
    occupy: bool,
    blocker: Option<AllocationReservation>,
    candidate: Option<iroha_allocation::AllocationRefusal>,
    partial_replay: bool,
    terminal_visits: usize,
    terminal_cause: Option<String>,
    first_terminal_bytes: Option<usize>,
}
thread_local! { static PROBE: RefCell<State> = RefCell::new(State::default()); }

fn keys(leg: &AmxTransferLegV1) -> (usize, usize) {
    fn first(account: &AccountId) -> usize {
        match account.controller() {
            AccountController::Single(key) => key.to_bytes().1.as_ptr() as usize,
            AccountController::Multisig(policy) => {
                policy.members()[0].public_key().to_bytes().1.as_ptr() as usize
            }
        }
    }
    (first(leg.source.account()), first(&leg.destination))
}
pub(super) fn decoded(
    bytes: &[u8],
    leg: &AmxTransferLegV1,
    retained: usize,
    budget: &AllocationBudget,
) {
    PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        if !probe.active {
            return;
        }
        probe.completions += 1;
        if probe.first.is_none() {
            probe.first = Some(Sample {
                source: (bytes.as_ptr() as usize, bytes.len()),
                keys: keys(leg),
                retained_bytes: retained,
            });
        }
        if probe.occupy {
            probe.occupy = false;
            probe.blocker = Some(
                budget
                    .try_reserve_bytes(
                        budget
                            .limit_bytes()
                            .checked_sub(budget.reserved_bytes())
                            .unwrap(),
                    )
                    .unwrap(),
            );
        }
    });
}
pub(super) fn borrowed(leg: &AmxTransferLegV1) {
    PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        if probe.active {
            probe.borrowed += 1;
            if probe.completions == 1 {
                assert_eq!(
                    keys(leg),
                    probe.first.unwrap().keys,
                    "retry borrows the exact original physical compact-key backing"
                );
            }
        }
    });
}

pub(super) fn candidate_refused(error: &GraphError) {
    PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        if probe.active
            && let GraphError::Admission(original) = error
        {
            assert!(
                probe.candidate.is_none(),
                "only the first original Candidate refuses"
            );
            probe.candidate = Some(original.clone());
        }
    });
}

pub(super) fn retained_attempt(
    result: &Result<
        iroha_data_model::sumeragi_amx::CompletedAmxTransferLegDecodeV1,
        AmxLegDecodeErrorV1,
    >,
    before: usize,
    budget: &AllocationBudget,
) {
    PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        if !probe.partial_replay { return; }
        match result {
            Err(AmxLegDecodeErrorV1::Decode(error)) if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid => {
                probe.terminal_visits += 1;
                let cause = error.to_string();
                if let Some(original) = probe.terminal_cause.as_ref() {
                    assert_eq!(&cause, original, "replayed original rejection preserves the canonical cause");
                    assert_eq!(budget.reserved_bytes(), before, "replayed terminal prefix does not allocate replacement original-pool backing");
                } else {
                    probe.first_terminal_bytes = Some(budget.reserved_bytes().checked_sub(before).unwrap());
                    probe.terminal_cause = Some(cause);
                }
            }
            _ => {}
        }
    });
}

/// One thread-confined resource fixture; Drop resets it even during unwind.
pub(crate) struct Observation;
impl Observation {
    pub(crate) fn occupy_after_first_completion() -> Self {
        PROBE.with(|probe| {
            assert!(!probe.borrow().active);
            *probe.borrow_mut() = State {
                active: true,
                occupy: true,
                ..State::default()
            };
        });
        Self
    }
    /// Observe actual canonical rejection and retained prefix without injecting an error.
    pub(crate) fn observe_rejected_prefix() -> Self {
        PROBE.with(|probe| {
            assert!(!probe.borrow().active);
            *probe.borrow_mut() = State {
                active: true,
                partial_replay: true,
                ..State::default()
            };
        });
        Self
    }
    pub(crate) fn partial_snapshot(&self) -> (usize, Option<String>, Option<usize>) {
        PROBE.with(|probe| {
            let probe = probe.borrow();
            (
                probe.terminal_visits,
                probe.terminal_cause.clone(),
                probe.first_terminal_bytes,
            )
        })
    }
    pub(crate) fn snapshot(&self) -> (usize, usize, Option<Sample>) {
        PROBE.with(|probe| {
            let probe = probe.borrow();
            (probe.completions, probe.borrowed, probe.first)
        })
    }
    pub(crate) fn original_candidate_refusal(&self) -> Option<iroha_allocation::AllocationRefusal> {
        PROBE.with(|probe| probe.borrow().candidate.clone())
    }
    pub(crate) fn release_original_blocker(&self) {
        let blocker = PROBE.with(|probe| probe.borrow_mut().blocker.take());
        assert!(blocker.is_some());
        drop(blocker);
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        PROBE.with(|probe| *probe.borrow_mut() = State::default());
    }
}
