//! Bounded diagnostic-only polling for payment acceptance fixtures.
//!
//! A status height schedules original proof reads; it never establishes a payment
//! outcome. This owner receives no transaction, signer or submission callback.

use eyre::{Report, Result, eyre};
use iroha::{Error, StatusFailureReason};
use iroha_torii_shared::status::Status;
use std::{future::Future, time::Duration};
use tokio::time::Instant;

const POLL_INTERVAL: Duration = Duration::from_millis(200);

// One-shot observations inherit the configured HTTP request bound. An explicitly
// unlimited request configuration still needs a finite fixture observation budget;
// only that case uses the SDK's fixed default request timeout.
fn request_deadline(timeout: Duration) -> Result<Instant> {
    let timeout = if timeout.is_zero() {
        iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT
    } else {
        timeout
    };
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| eyre!("AMX diagnostic request deadline cannot be represented"))
}

pub(crate) async fn read_once<F, Fut>(timeout: Duration, read: F) -> Result<Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Status>>,
{
    read_until(request_deadline(timeout)?, read).await
}

fn deadline_error(last: Option<Report>) -> Report {
    const MESSAGE: &str = "AMX diagnostic status observation deadline exhausted";
    last.map_or_else(|| eyre!(MESSAGE), |error| error.wrap_err(MESSAGE))
}

/// Retry only a typed local State/worker admission refusal under one caller deadline.
pub(crate) async fn read_until<F, Fut>(deadline: Instant, mut read: F) -> Result<Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Status>>,
{
    let mut last = None;
    loop {
        if Instant::now() >= deadline {
            return Err(deadline_error(last));
        }
        let result = match tokio::time::timeout_at(deadline, read()).await {
            Ok(result) => result,
            Err(_) => return Err(deadline_error(last)),
        };
        match result {
            Ok(status) => {
                if Instant::now() >= deadline {
                    return Err(deadline_error(last));
                }
                return Ok(status);
            }
            Err(error) => {
                let delay = match error.downcast_ref::<Error>() {
                    Some(Error::StatusUnavailable {
                        reason:
                            Some(
                                StatusFailureReason::StateBusy
                                | StatusFailureReason::MailboxUnavailable,
                            ),
                        retry_after,
                    }) => POLL_INTERVAL.max(retry_after.unwrap_or_default()),
                    _ => return Err(error),
                };
                last = Some(error);
                if Instant::now() >= deadline {
                    return Err(deadline_error(last));
                }
                let wake = Instant::now()
                    .checked_add(delay)
                    .unwrap_or(deadline)
                    .min(deadline);
                // Only the bounded retry timer bypasses cooperative accounting.
                // At the shared deadline it must return the retained cause before
                // a surrounding phase timeout can replace it with generic Elapsed.
                // HTTP reads retain their normal budget and the same hard deadline.
                tokio::task::unconstrained(tokio::time::sleep_until(wake)).await;
            }
        }
    }
}

/// Observe unchanged diagnostic heights for a minimum interval under one phase bound.
/// The final complete read round may straddle the observation threshold; it may
/// not cross the caller's original phase deadline or turn unavailable reads into idle proof.
pub(crate) async fn observe_idle_until<F, Fut>(
    deadline: Instant,
    minimum: Duration,
    mut read_round: F,
) -> Result<()>
where
    F: FnMut(Instant) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let observed_until = Instant::now()
        .checked_add(minimum)
        .ok_or_else(|| eyre!("AMX idle observation interval cannot be represented"))?;
    loop {
        if Instant::now() >= deadline {
            return Err(deadline_error(None));
        }
        tokio::time::timeout_at(deadline, read_round(deadline))
            .await
            .map_err(|_| deadline_error(None))??;
        if Instant::now() >= deadline {
            return Err(deadline_error(None));
        }
        if Instant::now() >= observed_until {
            return Ok(());
        }
        let wake = Instant::now()
            .checked_add(POLL_INTERVAL)
            .unwrap_or(deadline)
            .min(observed_until)
            .min(deadline);
        tokio::time::sleep_until(wake).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque, future};

    fn busy(reason: StatusFailureReason, retry_after: Option<Duration>) -> Report {
        Error::StatusUnavailable {
            reason: Some(reason),
            retry_after,
        }
        .into()
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_nested_deadline_retains_capacity_after_coop_budget_exhaustion() {
        for reason in [
            StatusFailureReason::StateBusy,
            StatusFailureReason::MailboxUnavailable,
        ] {
            let start = Instant::now();
            let deadline = start + Duration::from_secs(2);
            let reads = Cell::new(0);
            let error = observe_idle_until(deadline, Duration::from_secs(3), |read_deadline| {
                let reads = &reads;
                async move {
                    read_until(read_deadline, || {
                        reads.set(reads.get() + 1);
                        async move {
                            // The outer and HTTP deadlines are equal. Tokio polls the
                            // read first, so a ready response can exhaust the task's
                            // cooperative budget before the retry timer is polled.
                            tokio::time::sleep_until(read_deadline).await;
                            while tokio::task::coop::has_budget_remaining() {
                                tokio::task::consume_budget().await;
                            }
                            Err(busy(reason, Some(Duration::from_secs(30)))
                                .wrap_err("original final capacity response"))
                        }
                    })
                    .await?;
                    Ok(())
                }
            })
            .await
            .unwrap_err();
            assert_eq!(reads.get(), 1);
            assert_eq!(Instant::now() - start, Duration::from_secs(2));
            assert!(matches!(
                error.downcast_ref::<Error>(),
                Some(Error::StatusUnavailable {
                    reason: Some(actual),
                    retry_after: Some(delay),
                }) if *actual == reason && *delay == Duration::from_secs(30)
            ));
            assert!(format!("{error:?}").contains("original final capacity response"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_observation_allows_a_healthy_final_round_to_straddle_minimum() {
        let start = Instant::now();
        let phase_deadline = start + Duration::from_secs(10);
        let rounds = Cell::new(0);
        observe_idle_until(phase_deadline, Duration::from_secs(3), |read_deadline| {
            rounds.set(rounds.get() + 1);
            async move {
                read_until(read_deadline, || async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(Status::default())
                })
                .await?;
                Ok(())
            }
        })
        .await
        .expect("a healthy final round can finish after the minimum observation threshold");
        assert_eq!(rounds.get(), 2);
        assert_eq!(Instant::now() - start, Duration::from_millis(4_200));
        assert!(Instant::now() < phase_deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_observation_retains_one_phase_deadline_during_capacity_wait() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let error = observe_idle_until(
            start + Duration::from_secs(2),
            Duration::from_secs(3),
            |read_deadline| {
                let reads = &reads;
                async move {
                    read_until(read_deadline, || {
                        reads.set(reads.get() + 1);
                        future::ready(Err(busy(
                            StatusFailureReason::StateBusy,
                            Some(Duration::from_secs(30)),
                        )))
                    })
                    .await?;
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 1);
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::StatusUnavailable {
                reason: Some(StatusFailureReason::StateBusy),
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_observation_expires_before_another_round_and_never_swallows_auth() {
        let start = Instant::now();
        let rounds = Cell::new(0);
        let _ = observe_idle_until(start, Duration::from_secs(3), |_| {
            rounds.set(rounds.get() + 1);
            future::ready(Ok(()))
        })
        .await
        .unwrap_err();
        assert_eq!(rounds.get(), 0);
        let error = observe_idle_until(
            start + Duration::from_secs(120),
            Duration::from_secs(3),
            |_| {
                rounds.set(rounds.get() + 1);
                future::ready(Err(Error::Http {
                    operation: "diagnostic.status",
                    status: 401,
                    retry_after: None,
                    body: b"api_token_required".to_vec(),
                }
                .into()))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(rounds.get(), 1);
        assert_eq!(Instant::now(), start);
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::Http { status: 401, .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_one_shot_uses_configured_timeout_and_only_zero_uses_sdk_default() {
        let start = Instant::now();
        assert_eq!(
            request_deadline(Duration::from_secs(9)).unwrap(),
            start + Duration::from_secs(9)
        );
        assert_eq!(
            request_deadline(Duration::ZERO).unwrap(),
            start + iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT
        );
        let reads = Cell::new(0);
        let error = read_once(Duration::from_secs(3), || {
            reads.set(reads.get() + 1);
            future::ready(Err(busy(
                StatusFailureReason::StateBusy,
                Some(Duration::from_secs(30)),
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 1);
        assert_eq!(Instant::now() - start, Duration::from_secs(3));
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::StatusUnavailable {
                reason: Some(StatusFailureReason::StateBusy),
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_retries_only_typed_capacity_then_returns_success() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let mut responses = VecDeque::from([
            Err(busy(StatusFailureReason::StateBusy, None)),
            Err(busy(
                StatusFailureReason::MailboxUnavailable,
                Some(Duration::from_secs(1)),
            )),
            Ok(Status {
                blocks: 7,
                ..Status::default()
            }),
        ]);
        let status = read_until(start + Duration::from_secs(5), || {
            reads.set(reads.get() + 1);
            future::ready(responses.pop_front().expect("no extra read"))
        })
        .await
        .unwrap();
        assert_eq!(status.blocks, 7);
        assert_eq!(reads.get(), 3);
        assert_eq!(Instant::now() - start, Duration::from_millis(1_200));
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_retry_after_exhausts_original_deadline_without_extra_dispatch() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let error = read_until(start + Duration::from_secs(2), || {
            reads.set(reads.get() + 1);
            future::ready(Err(busy(
                StatusFailureReason::StateBusy,
                Some(Duration::from_secs(30)),
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 1);
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
        assert!(
            matches!(error.downcast_ref::<Error>(), Some(Error::StatusUnavailable { reason: Some(StatusFailureReason::StateBusy), retry_after: Some(delay) }) if *delay == Duration::from_secs(30))
        );
        assert!(error.to_string().contains("observation deadline exhausted"));
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_pending_http_shares_deadline_and_retains_last_capacity_cause() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let error = read_until(start + Duration::from_secs(2), || {
            reads.set(reads.get() + 1);
            let first = reads.get() == 1;
            async move {
                if first {
                    Err(busy(StatusFailureReason::MailboxUnavailable, None))
                } else {
                    future::pending::<Result<Status>>().await
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 2);
        assert_eq!(Instant::now() - start, Duration::from_secs(2));
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::StatusUnavailable {
                reason: Some(StatusFailureReason::MailboxUnavailable),
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_refuses_auth_integrity_proof_and_unclassified_errors_immediately() {
        let mut failures = [
            StatusFailureReason::Disabled,
            StatusFailureReason::ActorClosed,
            StatusFailureReason::DeadlineElapsed,
            StatusFailureReason::StateUnavailable,
            StatusFailureReason::CheckpointChanged,
            StatusFailureReason::MissingBlock,
            StatusFailureReason::JournalMismatch,
            StatusFailureReason::CounterOverflow,
            StatusFailureReason::CounterMismatch,
            StatusFailureReason::MetricsStale,
            StatusFailureReason::ProfileRestricted,
        ]
        .into_iter()
        .map(|reason| busy(reason, Some(Duration::from_secs(1))))
        .collect::<Vec<_>>();
        failures.push(
            Error::StatusUnavailable {
                reason: None,
                retry_after: None,
            }
            .into(),
        );
        for status in [401, 403, 429, 503] {
            failures.push(
                Error::Http {
                    operation: "diagnostic.status",
                    status,
                    retry_after: Some(Duration::from_secs(1)),
                    body: b"status_state_busy".to_vec(),
                }
                .into(),
            );
        }
        failures.push(
            Error::Decode {
                operation: "sumeragi.finality",
                details: "invalid original proof".into(),
            }
            .into(),
        );
        for error in failures {
            let expected = format!("{error:?}");
            let start = Instant::now();
            let reads = Cell::new(0);
            let mut original = Some(error);
            let error = read_until(start + Duration::from_secs(2), || {
                reads.set(reads.get() + 1);
                future::ready(Err(original.take().expect("terminal errors cannot retry")))
            })
            .await
            .unwrap_err();
            assert_eq!(
                format!("{error:?}"),
                expected,
                "move the original error unchanged"
            );
            assert_eq!(reads.get(), 1);
            assert_eq!(Instant::now(), start);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_expired_deadline_never_constructs_a_read() {
        let reads = Cell::new(0);
        let _ = read_until(Instant::now(), || {
            reads.set(reads.get() + 1);
            future::ready(Ok(Status::default()))
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn status_poll_rejects_success_finishing_after_deadline() {
        let start = Instant::now();
        let reads = Cell::new(0);
        let _ = read_until(start + Duration::from_secs(1), || {
            reads.set(reads.get() + 1);
            async {
                tokio::time::advance(Duration::from_secs(2)).await;
                Ok(Status::default())
            }
        })
        .await
        .unwrap_err();
        assert_eq!(reads.get(), 1);
    }
}
