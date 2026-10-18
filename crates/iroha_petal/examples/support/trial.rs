//! Bounded concurrent trial allocation for camera example workers.
use std::sync::atomic::{AtomicUsize, Ordering};

/// Claim one trial without wrapping after exhaustion, even at `usize::MAX`.
pub fn next_trial(next: &AtomicUsize, trials: usize) -> Option<usize> {
    next.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |trial| {
        (trial < trials).then(|| trial + 1)
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_trial_allocation_does_not_wrap() {
        let next = AtomicUsize::new(0);
        assert_eq!(next_trial(&next, 0), None);
        assert_eq!(next_trial(&next, 2), Some(0));
        assert_eq!(next_trial(&next, 2), Some(1));
        assert_eq!(next_trial(&next, 2), None);
        let next = AtomicUsize::new(usize::MAX - 1);
        assert_eq!(next_trial(&next, usize::MAX), Some(usize::MAX - 1));
        assert_eq!(next_trial(&next, usize::MAX), None);
        assert_eq!(next_trial(&next, usize::MAX), None);
        assert_eq!(next.load(Ordering::SeqCst), usize::MAX);
    }
}
