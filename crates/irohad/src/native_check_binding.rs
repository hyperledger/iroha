//! Service-local continuation of an already signed Core Check under its original deadline.
//!
//! A live local refusal stays on this stack, retaining its preparation, signed bytes and State
//! allocation owner. Waiting creates no allocation waiter and holds no State view, lock, or
//! execution lease. Only terminal errors or original expiry cross the fixed service-error boundary.

use std::time::{Duration, Instant};

use iroha_core::query::{
    final_promotion_account_custody::observation::{
        FinalPromotionAccountCheckAttemptFailureV1, FinalPromotionAccountCheckBindingFailureV1,
        PendingFinalPromotionAccountCheckV1,
    },
    final_promotion_authority::observation::{
        FinalPromotionCheckAttemptFailureV1, FinalPromotionCheckBindingFailureV1,
        PendingFinalPromotionCheckV1,
    },
    stream_token_authority::observation::{
        PendingStreamTokenCheckV1, StreamTokenCheckAttemptFailureV1,
        StreamTokenCheckBindingFailureV1,
    },
    stream_token_gateway::observation::{
        PendingStreamTokenGatewayCheckV1, StreamTokenGatewayCheckAttemptFailureV1,
        StreamTokenGatewayCheckBindingFailureV1,
    },
};

/// Metadata from the original move-only Core attempt; this exposes no signing recipe.
pub trait CheckFailure: Sized {
    /// Whether this failure is an unfinished local attempt.
    fn retryable(&self) -> bool;
    /// Absolute original preparation deadline.
    fn deadline(&self) -> Instant;
}

/// Purpose-specific binding continuation; verification supplies its own fresh-clock closure.
pub trait BindingFailure: CheckFailure {
    /// Successfully bound Check owned by Core.
    type Pending;
    /// Continue only the same signed attempt.
    fn retry(self) -> Result<Self::Pending, Self>;
}

macro_rules! binding_failure {
    ($failure:ty, $pending:ty) => {
        impl CheckFailure for $failure {
            fn retryable(&self) -> bool {
                self.error().is_retryable()
            }
            fn deadline(&self) -> Instant {
                self.deadline()
            }
        }
        impl BindingFailure for $failure {
            type Pending = $pending;
            fn retry(self) -> Result<Self::Pending, Self> {
                self.retry()
            }
        }
    };
}
binding_failure!(
    FinalPromotionCheckBindingFailureV1,
    PendingFinalPromotionCheckV1
);
binding_failure!(
    FinalPromotionAccountCheckBindingFailureV1,
    PendingFinalPromotionAccountCheckV1
);
binding_failure!(StreamTokenCheckBindingFailureV1, PendingStreamTokenCheckV1);
binding_failure!(
    StreamTokenGatewayCheckBindingFailureV1,
    PendingStreamTokenGatewayCheckV1
);

macro_rules! verification_failure {
    ($($failure:ty),+ $(,)?) => {$(
        impl CheckFailure for $failure {
            fn retryable(&self) -> bool { self.is_retryable() }
            fn deadline(&self) -> Instant { self.deadline() }
        }
    )+};
}
verification_failure!(
    FinalPromotionCheckAttemptFailureV1,
    FinalPromotionAccountCheckAttemptFailureV1,
    StreamTokenCheckAttemptFailureV1,
    StreamTokenGatewayCheckAttemptFailureV1,
);

/// Completed outcomes only: an unfinished local refusal cannot escape through this enum.
pub enum CheckTermination<F> {
    /// Completed rejection or non-local codec failure, preserving its original details.
    Terminal(F),
    /// Local service lifetime ended; this is not a transaction rejection.
    Expired,
}

/// Continue local binding refusals with bounded backoff until the original deadline.
pub fn complete_binding<F: BindingFailure>(
    attempt: Result<F::Pending, F>,
) -> Result<F::Pending, CheckTermination<F>> {
    complete_binding_waiting(attempt, |_, delay| std::thread::sleep(delay))
}

/// The same continuation with a service-owned wait callback; custody stays borrowed while waiting.
pub fn complete_binding_waiting<F: BindingFailure>(
    attempt: Result<F::Pending, F>,
    wait: impl FnMut(&F, Duration),
) -> Result<F::Pending, CheckTermination<F>> {
    complete_check_with(attempt, F::retry, Instant::now, wait)
}

/// Continue verification or a final source recheck without re-signing or resubmitting.
///
/// The closure consumes the original failure, recovers its pending Check and samples a fresh
/// clock inside verification. Core has released every view and publication lease before Err.
pub fn complete_check<T, F: CheckFailure>(
    attempt: Result<T, F>,
    retry: impl FnMut(F) -> Result<T, F>,
) -> Result<T, CheckTermination<F>> {
    complete_check_with(attempt, retry, Instant::now, |_, delay| {
        std::thread::sleep(delay)
    })
}

/// Shared continuation engine; its clock and wait are supplied by the local service.
pub fn complete_check_with<T, F: CheckFailure>(
    mut attempt: Result<T, F>,
    mut retry: impl FnMut(F) -> Result<T, F>,
    mut now: impl FnMut() -> Instant,
    mut wait: impl FnMut(&F, Duration),
) -> Result<T, CheckTermination<F>> {
    let mut delay = Duration::from_millis(1);
    loop {
        let failure = match attempt {
            Ok(pending) => return Ok(pending),
            Err(failure) => failure,
        };
        // Completed Clock/semantic outcomes retain their classification even at the deadline.
        // Only an unfinished local attempt can terminate through local expiry.
        if !failure.retryable() {
            return Err(CheckTermination::Terminal(failure));
        }
        let Some(remaining) = failure.deadline().checked_duration_since(now()) else {
            return Err(CheckTermination::Expired);
        };
        if remaining.is_zero() {
            return Err(CheckTermination::Expired);
        }
        // Backoff works for all local refusals, including ones without a release owner. The
        // original failure stays alive while waiting; neither a pool nor a waiter is invented.
        wait(&failure, delay.min(remaining));
        if now() >= failure.deadline() {
            return Err(CheckTermination::Expired);
        }
        attempt = retry(failure);
        delay = (delay * 2).min(Duration::from_millis(32));
    }
}

#[cfg(test)]
mod tests;
