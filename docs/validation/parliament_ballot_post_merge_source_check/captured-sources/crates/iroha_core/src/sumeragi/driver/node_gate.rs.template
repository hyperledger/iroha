//! Permanent node-wide admission latch for native consensus storage faults.
//!
//! Kura creates the gate before startup. Global and lane instances retain that exact gate;
//! closure is irreversible for its storage owner. Entry linearizes before closure or fails.
//! An already admitted operation retains its original owner until it returns; closure does
//! not interrupt publication or invent a replacement execution. Every later kernel step,
//! worker operation and output dispatch must enter again, so buffered effects cannot escape.

use std::sync::atomic::{AtomicUsize, Ordering};

const CLOSED: usize = 1;
const OPERATION: usize = 2;

/// Shared admission state for every native instance using one canonical storage owner.
#[derive(Debug, Default)]
pub struct NodeGate {
    state: AtomicUsize,
}
impl NodeGate {
    /// Construct the storage owner's initially open gate, before any instance starts.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    /// Whether canonical storage has permanently stopped new consensus operations.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) & CLOSED != 0
    }

    /// Close without waiting on an operation that may itself be reporting a storage fault.
    pub(crate) fn close(&self) {
        self.state.fetch_or(CLOSED, Ordering::AcqRel);
    }

    /// Admit one operation before closure, with a stack-only owner that cannot reopen it.
    pub(crate) fn enter(&self) -> Option<Operation<'_>> {
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & CLOSED != 0 {
                    return None;
                }
                state.checked_add(OPERATION)
            })
            .ok()
            .map(|_| Operation(self))
    }
}

pub(crate) struct Operation<'gate>(&'gate NodeGate);
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.state.fetch_sub(OPERATION, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn original_operation_finishes_without_reopening_closed_gate() {
        let gate = NodeGate::new();
        let original = gate.enter().expect("admit original operation");
        assert!(!gate.is_closed());
        gate.close();
        gate.close();
        assert!(gate.is_closed());
        assert!(gate.enter().is_none());
        assert_eq!(gate.state.load(Ordering::Acquire), OPERATION + CLOSED);
        drop(original);
        assert_eq!(gate.state.load(Ordering::Acquire), CLOSED);
        assert!(gate.enter().is_none());
    }

    #[test]
    fn every_instance_observes_closure_even_if_its_handle_is_obtained_later() {
        let gate = Arc::new(NodeGate::new());
        let global = Arc::clone(&gate);
        let lane = Arc::clone(&gate);
        let original = lane.enter().unwrap();
        global.close();
        assert!(lane.enter().is_none());
        assert!(Arc::clone(&gate).enter().is_none());
        drop(original);
        assert!(gate.is_closed());
    }

    #[test]
    fn concurrent_completion_and_closure_preserve_closed_bit() {
        for _ in 0..64 {
            let gate = Arc::new(NodeGate::new());
            let original = gate.enter().unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let peer_gate = Arc::clone(&gate);
            let peer_barrier = Arc::clone(&barrier);
            let closer = std::thread::spawn(move || {
                peer_barrier.wait();
                peer_gate.close();
            });
            barrier.wait();
            drop(original);
            closer.join().unwrap();
            assert_eq!(gate.state.load(Ordering::Acquire), CLOSED);
            assert!(gate.enter().is_none());
        }
    }

    #[test]
    fn saturated_operation_count_refuses_without_wraparound() {
        let gate = NodeGate {
            state: AtomicUsize::new(usize::MAX - 1),
        };
        assert!(gate.enter().is_none());
        assert!(!gate.is_closed());
        gate.close();
        assert!(gate.is_closed());
        assert!(gate.enter().is_none());
    }
}
