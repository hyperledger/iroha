//! Sequential gossip work retaining the original envelope through local retry.
use super::{ExecutionDeferred, RetainedGossip, TransactionGossip, TransactionGossiperStartError};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use std::{sync::Arc, time::Duration};
use tokio::{runtime::RuntimeFlavor, sync::mpsc};

/// One actor owns periodic fanout and the borrowed original incoming attempt.
pub(super) trait Handler: Send + 'static {
    /// Perform periodic outgoing queue fanout.
    fn tick(&mut self);
    /// Complete admission or return its exact unfinished local cause.
    fn incoming(
        &mut self,
        message: &RetainedGossip<Arc<TransactionGossip>>,
    ) -> Result<(), ExecutionDeferred>;
}

/// Original source, transport owner and refusal, held without a second allocation.
struct PendingIncoming {
    message: RetainedGossip<Arc<TransactionGossip>>,
    original: ExecutionDeferred,
}

/// Start on a runtime capable of handing off a blocked executor core.
pub(super) fn start<H: Handler>(
    period: Duration,
    messages: mpsc::Receiver<RetainedGossip<Arc<TransactionGossip>>>,
    shutdown: ShutdownSignal,
    handle: H,
) -> Result<Child, TransactionGossiperStartError> {
    if period.is_zero() {
        return Err(TransactionGossiperStartError::ZeroPeriod);
    }
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| TransactionGossiperStartError::MissingRuntime)?;
    if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
        return Err(TransactionGossiperStartError::UnsupportedRuntime);
    }
    Ok(Child::new(
        runtime.spawn(run(period, messages, shutdown, handle)),
        OnShutdown::Drain,
    ))
}

fn attempt<H: Handler>(
    message: RetainedGossip<Arc<TransactionGossip>>,
    handle: &mut H,
) -> Option<PendingIncoming> {
    match handle.incoming(&message) {
        Ok(()) => None,
        Err(original) => Some(PendingIncoming { message, original }),
    }
}

async fn run<H: Handler>(
    period: Duration,
    mut messages: mpsc::Receiver<RetainedGossip<Arc<TransactionGossip>>>,
    shutdown: ShutdownSignal,
    mut handle: H,
) {
    let mut timer = tokio::time::interval(period);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // This inline slot exists before the first physical attempt. A refused
    // attempt neither allocates retry storage nor emits a transaction verdict.
    let mut pending: Option<PendingIncoming> = None;
    loop {
        tokio::select! {
            biased;
            () = shutdown.receive() => break,
            _ = timer.tick() => {
                tokio::task::block_in_place(|| {
                    if let Some(PendingIncoming { message, original }) = pending.take() {
                        // Keep the old cause until the same source actually starts its
                        // next physical attempt; no fabricated pool/release wait exists.
                        drop(original);
                        pending = attempt(message, &mut handle);
                    }
                    handle.tick();
                });
            }
            Some(message) = messages.recv(), if pending.is_none() => {
                pending = tokio::task::block_in_place(|| attempt(message, &mut handle));
            }
        }
        tokio::task::yield_now().await;
    }
    // Shutdown explicitly cancels the one pending source and its original cause.
    // The mailbox is dropped after active physical work has naturally returned.
    drop(pending);
    iroha_logger::debug!(
        "Shutting down transactions gossiper after cancelling pending retry and draining current work"
    );
}

#[cfg(test)]
mod tests;
