//! Bounded ownership for existing synchronous certificate and carrier helpers.

use super::PrivateSettlementError;

/// Run bounded synchronous settlement work outside Tokio's inherited blocking context.
///
/// The native worker owns the original permit and artifacts through completion.
/// Dropping the awaiting future neither cancels that work nor releases its capacity early.
///
/// # Errors
/// Returns [`PrivateSettlementError::Worker`] if thread creation fails or the worker
/// unwinds before returning its result. No replacement work is started automatically.
pub async fn run_private_settlement_worker<T: Send + 'static>(
    permit: tokio::sync::OwnedSemaphorePermit,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PrivateSettlementError> {
    let (completed, result) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("iroha-private-settlement".into())
        .spawn(move || {
            let output = {
                let _original_permit = permit;
                work()
            };
            // Release completed work's capacity before waking its next phase. No
            // certificate, signer or transport call survives this completion signal.
            let _ = completed.send(output);
        })
        .map_err(|_| PrivateSettlementError::Worker)?;
    result.await.map_err(|_| PrivateSettlementError::Worker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn private_settlement_worker_leaves_runtime_and_releases_only_completed_work() {
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = permits.clone().try_acquire_owned().unwrap();
        assert!(
            run_private_settlement_worker(permit, || tokio::runtime::Handle::try_current()
                .is_err())
            .await
            .unwrap()
        );
        let permit = permits.clone().try_acquire_owned().unwrap();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let pending = tokio::spawn(run_private_settlement_worker(permit, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        }));
        entered.await.unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert!(
            permits.clone().try_acquire_owned().is_err(),
            "dropping the awaiter cannot release its original active worker"
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if permits.clone().try_acquire_owned().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed original worker returns its permit");
    }
}
