//! Supervised native payment tasks with one original absolute deadline.
//!
//! The owned task keeps proof verification off its caller's retained stack.
//! Cancellation remains cooperative and cannot undo a submitted transaction.

use eyre::{Result, ensure, eyre};
use std::time::Instant;

/// Poll the owned SDK operation on a fresh default worker stack, retaining the
/// original phase deadline and cancellation ownership. JoinSet aborts its child
/// on timeout, unwinding, or cancellation of this enclosing future; a detached
/// JoinHandle would let a payment continue after its ceremony owner disappeared.
pub(crate) async fn owned_payment_until<T, F>(deadline: Instant, payment: F) -> Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let deadline = tokio::time::Instant::from_std(deadline);
    ensure!(
        tokio::time::Instant::now() < deadline,
        "original payment deadline exhausted"
    );
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "original payment deadline exhausted"
        );
        payment.await
    });
    let joined = match tokio::time::timeout_at(deadline, tasks.join_next()).await {
        Ok(joined) => joined,
        Err(_) => {
            tasks.abort_all();
            return Err(eyre!("original payment deadline exhausted"));
        }
    };
    let completed = joined
        .ok_or_else(|| eyre!("owned payment task disappeared"))?
        .map_err(|error| eyre!("owned payment task failed: {error}"))??;
    // Tokio polls the child result before its timer. Synchronous verification
    // must not turn an already elapsed original deadline into a late success.
    ensure!(
        tokio::time::Instant::now() < deadline,
        "original payment deadline exhausted"
    );
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::oneshot;

    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn payment_is_polled_off_the_callers_stack() {
        let parent = std::thread::current().id();
        let child = owned_payment_until(Instant::now() + Duration::from_secs(5), async {
            Ok(std::thread::current().id())
        })
        .await
        .unwrap();
        assert_ne!(
            parent, child,
            "proof verification must not retain the caller stack"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_payment_returns_exact_success_error_and_task_failure() {
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            owned_payment_until(deadline, async { Ok(17_u64) })
                .await
                .unwrap(),
            17
        );
        let error = owned_payment_until::<(), _>(deadline, async {
            Err(eyre!("original verification failure"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "original verification failure");
        let error = owned_payment_until::<(), _>(deadline, async { panic!("owned task panic") })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("owned payment task failed"));
    }

    #[tokio::test]
    async fn expired_payment_deadline_never_polls_submission() {
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        let error = owned_payment_until(Instant::now(), async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original payment deadline exhausted")
        );
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn ready_payment_cannot_bypass_elapsed_original_deadline() {
        use std::{future::Future as _, task::Poll};
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let completed = Arc::new(AtomicBool::new(false));
        let observed = completed.clone();
        let (finished, finish_observed) = oneshot::channel();
        let mut owner = Box::pin(owned_payment_until(deadline.into_std(), async move {
            tokio::time::advance(Duration::from_secs(5)).await;
            observed.store(true, Ordering::SeqCst);
            let _ = finished.send(());
            Ok(())
        }));
        // Start the task and timer, then hold this owner's next poll until its
        // child has actually completed after advancing the original deadline.
        std::future::poll_fn(|cx| {
            assert!(owner.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        finish_observed.await.unwrap();
        assert!(
            completed.load(Ordering::SeqCst),
            "the payment must actually complete"
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
        let error = owner.await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original payment deadline exhausted")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_aborts_the_owned_payment_without_replenishment() {
        let (dropped, drop_observed) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let error = owned_payment_until(deadline.into_std(), async move {
            let _owner = Dropped(Some(dropped));
            std::future::pending::<Result<()>>().await
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original payment deadline exhausted")
        );
        drop_observed
            .await
            .expect("deadline must cancel the child owner");
        assert_eq!(tokio::time::Instant::now(), deadline);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_ceremony_owner_aborts_the_child_payment() {
        let (started, start_observed) = oneshot::channel();
        let (dropped, drop_observed) = oneshot::channel();
        let owner = tokio::spawn(owned_payment_until(
            Instant::now() + Duration::from_secs(30),
            async move {
                let _owner = Dropped(Some(dropped));
                let _ = started.send(());
                std::future::pending::<Result<()>>().await
            },
        ));
        start_observed.await.unwrap();
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), drop_observed)
            .await
            .expect("child must remain owned on outer cancellation")
            .unwrap();
    }
}
