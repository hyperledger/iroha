//! Explicit cooperative cancellation shared by arithmetic and proof callers.
//!
//! A token belongs to one operation. Cancellation is permanent, and cloning
//! shares only that operation's signal. Kernels join all Rayon work before
//! reporting cancellation; the token never owns or spawns a worker.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A caller-owned, one-way cancellation signal for one operation.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

/// The caller cancelled an operation before it produced a complete result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

impl core::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operation cancelled")
    }
}
impl std::error::Error for Cancelled {}

impl CancellationToken {
    /// Creates a fresh, uncancelled operation signal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels this operation and every clone of its signal permanently.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether the caller has cancelled this operation.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Checks a cooperative boundary.
    ///
    /// # Errors
    /// Returns [`Cancelled`] after this operation has been cancelled.
    pub fn check(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }

    /// Checks an optional caller signal; absence never cancels work.
    ///
    /// # Errors
    /// Returns [`Cancelled`] when the supplied signal has been cancelled.
    pub fn checkpoint(token: Option<&Self>) -> Result<(), Cancelled> {
        token.map_or(Ok(()), Self::check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_is_shared_permanent_and_operation_local() {
        let first = CancellationToken::new();
        let clone = first.clone();
        let separate = CancellationToken::new();
        assert_eq!(first.check(), Ok(()));
        clone.cancel();
        clone.cancel();
        assert!(first.is_cancelled());
        assert_eq!(first.check(), Err(Cancelled));
        assert_eq!(CancellationToken::checkpoint(Some(&first)), Err(Cancelled));
        assert_eq!(CancellationToken::checkpoint(Some(&separate)), Ok(()));
        assert_eq!(CancellationToken::checkpoint(None), Ok(()));
    }
}
