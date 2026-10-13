//! Explicit panic-recovery boundaries for daemon-owned provider work.
//!
//! These helpers are limited to operations whose contracts deliberately map a
//! provider or reconciliation panic to a controlled error. Consensus and
//! supervisor infrastructure must stay on ordinary, unsuppressed tasks.

use std::{io, thread};

use tokio::task::{JoinError, JoinHandle};

/// Opaque failure returned when a recoverable operation panicked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverablePanic;

/// Run blocking provider work with suppression installed on its physical worker.
pub fn spawn_blocking_recoverable<F, T>(operation: F) -> JoinHandle<thread::Result<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || iroha_panic_hook::catch_unwind_suppressed(operation))
}

/// Decode a completed recoverable Tokio task.
///
/// The nested unwind is an expected provider failure. A raw [`JoinError`]
/// means cancellation or failure outside the physical recovery boundary and
/// remains an unsuppressed daemon invariant panic.
pub fn recover_joined<T>(
    joined: Result<thread::Result<T>, JoinError>,
) -> Result<T, RecoverablePanic> {
    match joined {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(RecoverablePanic),
        Err(error) => {
            panic!("recoverable blocking task failed outside its panic boundary: {error}")
        }
    }
}

/// Join an explicitly recoverable blocking task without exposing its panic payload.
pub async fn join_recoverable<T>(
    task: JoinHandle<thread::Result<T>>,
) -> Result<T, RecoverablePanic> {
    recover_joined(task.await)
}

/// Spawn a named OS thread with suppression installed inside that physical thread.
pub fn spawn_thread_recoverable<F, T>(
    builder: thread::Builder,
    operation: F,
) -> io::Result<thread::JoinHandle<thread::Result<T>>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    builder.spawn(move || iroha_panic_hook::catch_unwind_suppressed(operation))
}

/// Join an explicitly recoverable OS thread without exposing its panic payload.
///
/// The outer join can fail only if the recovery wrapper itself failed, so it
/// remains an unsuppressed daemon invariant panic.
pub fn join_thread_recoverable<T>(
    thread: thread::JoinHandle<thread::Result<T>>,
) -> Result<T, RecoverablePanic> {
    thread
        .join()
        .unwrap_or_else(|_| panic!("recoverable OS thread failed outside its panic boundary"))
        .map_err(|_| RecoverablePanic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_panic_is_controlled_and_suppression_clears() {
        let task = spawn_blocking_recoverable(|| {
            assert!(iroha_panic_hook::is_suppressed());
            panic!("injected recoverable blocking panic");
        });
        assert_eq!(join_recoverable(task).await, Err(RecoverablePanic));
        let stale = tokio::task::spawn_blocking(iroha_panic_hook::is_suppressed)
            .await
            .expect("blocking worker probe must join");
        assert!(!stale, "suppression must clear before worker reuse");
    }

    #[test]
    fn os_thread_panic_is_controlled_and_suppression_clears() {
        let task = spawn_thread_recoverable(thread::Builder::new(), || {
            assert!(iroha_panic_hook::is_suppressed());
            panic!("injected recoverable OS-thread panic");
        })
        .expect("spawn recoverable test thread");
        assert_eq!(join_thread_recoverable(task), Err(RecoverablePanic));
        assert!(!iroha_panic_hook::is_suppressed());
    }

    #[tokio::test]
    async fn raw_join_failure_remains_an_unsuppressed_invariant() {
        let task = tokio::spawn(async { std::future::pending::<thread::Result<()>>().await });
        task.abort();
        let joined = task.await;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(!iroha_panic_hook::is_suppressed());
            let _ = recover_joined(joined);
        }));
        assert!(panic.is_err());
        assert!(!iroha_panic_hook::is_suppressed());
    }

    #[test]
    fn ordinary_invariant_panics_remain_unsuppressed() {
        let result = std::panic::catch_unwind(|| {
            assert!(!iroha_panic_hook::is_suppressed());
            panic!("injected invariant panic");
        });
        assert!(result.is_err());
    }
}
