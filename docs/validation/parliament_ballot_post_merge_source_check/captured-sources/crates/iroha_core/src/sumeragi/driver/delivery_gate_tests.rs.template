//! Retained transport ownership cannot bypass a later node-wide storage stop.

use super::*;
use std::sync::atomic::AtomicUsize;

struct Retry {
    attempts: Arc<AtomicUsize>,
    remaining: usize,
}

impl PendingSend for Retry {
    fn retry(mut self: Box<Self>) -> SendOutcome {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.remaining == 0 {
            SendOutcome::Admitted
        } else {
            self.remaining -= 1;
            SendOutcome::Backpressured(self)
        }
    }
}

fn pending(gate: &Arc<NodeGate>, attempts: &Arc<AtomicUsize>) -> Box<dyn PendingSend> {
    let outcome = gate_send(
        SendOutcome::Backpressured(Box::new(Retry {
            attempts: Arc::clone(attempts),
            remaining: 1,
        })),
        gate,
    );
    let SendOutcome::Backpressured(pending) = outcome else {
        panic!("original send remains pending");
    };
    pending
}

#[test]
fn original_pending_send_progresses_through_repeated_pressure() {
    let gate = Arc::new(NodeGate::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let SendOutcome::Backpressured(retry) = pending(&gate, &attempts).retry() else {
        panic!("first exact occurrence stays under pressure");
    };
    assert!(matches!(retry.retry(), SendOutcome::Admitted));
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
}

#[test]
fn closed_gate_cancels_original_pending_send_without_another_attempt() {
    let gate = Arc::new(NodeGate::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let SendOutcome::Backpressured(retry) = pending(&gate, &attempts).retry() else {
        panic!("first exact occurrence stays under pressure");
    };
    gate.close();
    assert!(matches!(retry.retry(), SendOutcome::Closed));
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
}
