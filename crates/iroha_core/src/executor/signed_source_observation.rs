//! Passive test observations at the actual signed execution boundary.
use std::cell::RefCell;

use iroha_data_model::transaction::SignedTransaction;

#[derive(Debug, PartialEq, Eq)]
struct Source {
    transaction: usize,
    executable: usize,
    metadata: usize,
    fee_intent: usize,
}

impl Source {
    fn of(transaction: &SignedTransaction) -> Self {
        Self {
            transaction: std::ptr::from_ref(transaction) as usize,
            executable: std::ptr::from_ref(transaction.instructions()) as usize,
            metadata: std::ptr::from_ref(transaction.metadata()) as usize,
            fee_intent: std::ptr::from_ref(transaction.fee_payment_intent()) as usize,
        }
    }
}

struct Observation {
    expected: Source,
    calls: usize,
}

thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

/// Expect one exact signed owner at the real executor boundary on this test thread.
/// This observes input addresses and never replaces validation or execution.
pub(crate) struct Probe;

impl Probe {
    /// Start a scoped observation of the original accepted or reveal-inner owner.
    pub(crate) fn new(transaction: &SignedTransaction) -> Self {
        OBSERVATION.with_borrow_mut(|slot| {
            assert!(
                slot.is_none(),
                "signed-source observations must not overlap"
            );
            *slot = Some(Observation {
                expected: Source::of(transaction),
                calls: 0,
            });
        });
        Self
    }

    /// Prove the actual executor observed this source exactly once.
    pub(crate) fn assert_observed_once(&self) {
        OBSERVATION.with_borrow(|slot| {
            assert_eq!(slot.as_ref().expect("active observation").calls, 1);
        });
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        OBSERVATION.with_borrow_mut(|slot| *slot = None);
    }
}

pub(super) fn record(transaction: &SignedTransaction) {
    OBSERVATION.with_borrow_mut(|slot| {
        if let Some(observation) = slot {
            assert_eq!(Source::of(transaction), observation.expected);
            observation.calls += 1;
        }
    });
}
