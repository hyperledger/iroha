/// Return the sole supported canonical block-wire version after genesis is applied.
#[iroha_futures::telemetry_future]
pub async fn handle_version(state: Arc<CoreState>) -> Response {
    let latest_block = match std::num::NonZeroUsize::new(state.committed_height()) {
        Some(height) => match state.block_by_height(height) {
            Ok(block) => block,
            Err(error) => {
                return crate::canonical_history::canonical_attempt_error(error).into_response();
            }
        },
        None => None,
    };
    let mut resp = match latest_block {
        Some(_) => Response::new(Body::from(
            iroha_data_model::block::SignedBlock::WIRE_VERSION.to_string(),
        )),
        None => {
            let mut resp = Response::new(Body::from("genesis not applied"));
            *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            resp
        }
    };
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
// Version and status visibility helpers and regressions.
#[cfg(test)]
mod version_tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use iroha_core::{kura::Kura, query::store::LiveQueryStore, state::World};
    #[tokio::test]
    async fn handle_version_matches_applied_canonical_wire() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
            .expect("apply genuine signed genesis");
        let version = chain.committed(1).block().encode_wire().unwrap()[0];
        assert_eq!(
            version, 1,
            "first release has exactly one block-wire layout"
        );
        let response = handle_version(Arc::clone(chain.state())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            version.to_string().as_bytes()
        );
    }

    #[tokio::test]
    async fn handle_version_reports_unavailable_without_genesis() {
        let state = Arc::new(CoreState::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let response = handle_version(state).await;
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8"),
        );
        let body_bytes = body.collect().await.expect("collect body").to_bytes();
        assert_eq!(
            std::str::from_utf8(&body_bytes).expect("utf8"),
            "genesis not applied"
        );
    }
}
#[cfg(feature = "telemetry")]
fn status_visibility_failure(error: Error) -> Error {
    match error {
        Error::TelemetryProfileRestricted { endpoint, profile } => Error::AppServiceUnavailable {
            code: iroha_torii_shared::status::StatusFailureReason::ProfileRestricted.code(),
            message: format!("telemetry endpoint `{endpoint}` disabled by profile `{profile:?}`"),
        },
        other => other,
    }
}

#[cfg(feature = "telemetry")]
fn status_snapshot_failure(error: iroha_core::telemetry::StatusSnapshotError) -> Error {
    use iroha_core::telemetry::StatusSnapshotError;
    use iroha_torii_shared::status::StatusFailureReason;

    let reason = match &error {
        StatusSnapshotError::Disabled => StatusFailureReason::Disabled,
        StatusSnapshotError::MailboxUnavailable => StatusFailureReason::MailboxUnavailable,
        StatusSnapshotError::ActorClosed => StatusFailureReason::ActorClosed,
        StatusSnapshotError::DeadlineElapsed => StatusFailureReason::DeadlineElapsed,
        StatusSnapshotError::StateBusy | StatusSnapshotError::HistoryReadDeferred(_) => {
            StatusFailureReason::StateBusy
        }
        StatusSnapshotError::StateUnavailable | StatusSnapshotError::HistoryRead(_) => {
            StatusFailureReason::StateUnavailable
        }
        StatusSnapshotError::CheckpointChanged => StatusFailureReason::CheckpointChanged,
        StatusSnapshotError::MissingBlock => StatusFailureReason::MissingBlock,
        StatusSnapshotError::JournalMismatch => StatusFailureReason::JournalMismatch,
        StatusSnapshotError::CounterOverflow => StatusFailureReason::CounterOverflow,
        StatusSnapshotError::CounterMismatch => StatusFailureReason::CounterMismatch,
    };
    Error::AppServiceUnavailable {
        code: reason.code(),
        message: format!("status metrics could not reach a fresh classified frontier: {error}"),
    }
}

#[cfg(feature = "telemetry")]
fn ensure_status_metrics_match_authoritative_height(
    status: &Status,
    authoritative_block_height: u64,
) -> std::result::Result<(), Error> {
    // This height travels with the immutable actor reply, not a live/pre-await State read.
    if status.blocks != authoritative_block_height {
        return Err(Error::AppServiceUnavailable {
            code: iroha_torii_shared::status::StatusFailureReason::MetricsStale.code(),
            message: format!(
                "status metrics classified height {} while its owned State target is at height {authoritative_block_height}; retry",
                status.blocks
            ),
        });
    }
    Ok(())
}
#[cfg(all(test, feature = "telemetry"))]
mod status_block_visibility_tests {
    use super::{Error, Status, ensure_status_metrics_match_authoritative_height};
    #[test]
    fn stale_classified_height_is_retriable_instead_of_publishing_a_false_empty_gap() {
        let status = Status {
            blocks: 2,
            blocks_non_empty: 2,
            ..Status::default()
        };
        let error = ensure_status_metrics_match_authoritative_height(&status, 3)
            .expect_err("an authoritative height ahead of classification must be retriable");
        assert!(matches!(
            error,
            Error::AppServiceUnavailable {
                code: "status_metrics_stale",
                ..
            }
        ));
    }
    #[test]
    fn matching_classified_and_authoritative_heights_are_publishable() {
        let status = Status {
            blocks: 3,
            blocks_non_empty: 3,
            ..Status::default()
        };
        ensure_status_metrics_match_authoritative_height(&status, 3)
            .expect("a single classified frontier is publishable");
    }
}

#[cfg(all(test, feature = "telemetry"))]
mod status_failure_reason_tests {
    use super::{
        Error, MaybeTelemetry, Status, ensure_status_metrics_match_authoritative_height,
        handle_status, status_snapshot_failure,
    };
    use axum::{http::StatusCode, response::IntoResponse as _};
    use http_body_util::BodyExt as _;
    use iroha_core::telemetry::StatusSnapshotError;
    use iroha_torii_shared::{
        ErrorEnvelope,
        status::{BuildStatus, StatusFailureReason},
    };

    async fn assert_wire_reason(error: Error, reason: StatusFailureReason) {
        for format in [
            crate::utils::ResponseFormat::Json,
            crate::utils::ResponseFormat::Norito,
        ] {
            // Recreate the response error because Torii Error is not Clone.
            let (code, message) = match &error {
                Error::AppServiceUnavailable { code, message } => (*code, message.clone()),
                other => panic!("expected typed status failure, got {other:?}"),
            };
            let response = crate::utils::with_current_response_format(format, async {
                Error::AppServiceUnavailable { code, message }.into_response()
            })
            .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response.headers()["x-iroha-reject-code"].to_str().unwrap(),
                reason.code(),
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let envelope: ErrorEnvelope = match format {
                crate::utils::ResponseFormat::Json => norito::json::from_slice(&bytes).unwrap(),
                crate::utils::ResponseFormat::Norito => norito::decode_from_bytes(&bytes).unwrap(),
            };
            assert_eq!(envelope.code, reason.code());
        }
    }

    #[tokio::test]
    async fn snapshot_failure_reasons_match_json_norito_and_header() {
        let original_budget = iroha_allocation::AllocationBudget::new(1);
        let retained = original_budget.try_reserve_bytes(1).unwrap();
        let refusal = original_budget
            .try_reserve_bytes(1)
            .expect_err("original capacity occupied");
        let cases = [
            (
                StatusSnapshotError::HistoryReadDeferred(
                    iroha_core::execution_attempt::ExecutionDeferred::from(refusal).reason(),
                ),
                StatusFailureReason::StateBusy,
            ),
            (
                StatusSnapshotError::HistoryRead("invalid durable frame".into()),
                StatusFailureReason::StateUnavailable,
            ),
            (StatusSnapshotError::Disabled, StatusFailureReason::Disabled),
            (
                StatusSnapshotError::MailboxUnavailable,
                StatusFailureReason::MailboxUnavailable,
            ),
            (
                StatusSnapshotError::ActorClosed,
                StatusFailureReason::ActorClosed,
            ),
            (
                StatusSnapshotError::DeadlineElapsed,
                StatusFailureReason::DeadlineElapsed,
            ),
            (
                StatusSnapshotError::StateBusy,
                StatusFailureReason::StateBusy,
            ),
            (
                StatusSnapshotError::StateUnavailable,
                StatusFailureReason::StateUnavailable,
            ),
            (
                StatusSnapshotError::CheckpointChanged,
                StatusFailureReason::CheckpointChanged,
            ),
            (
                StatusSnapshotError::MissingBlock,
                StatusFailureReason::MissingBlock,
            ),
            (
                StatusSnapshotError::JournalMismatch,
                StatusFailureReason::JournalMismatch,
            ),
            (
                StatusSnapshotError::CounterOverflow,
                StatusFailureReason::CounterOverflow,
            ),
            (
                StatusSnapshotError::CounterMismatch,
                StatusFailureReason::CounterMismatch,
            ),
        ];
        for (error, reason) in cases {
            assert_wire_reason(status_snapshot_failure(error), reason).await;
        }
        drop(retained);
    }

    #[tokio::test]
    async fn actual_status_profile_rejection_and_stale_reply_have_reason_headers() {
        let profile_error =
            handle_status(&BuildStatus::default(), &MaybeTelemetry::disabled(), None)
                .await
                .unwrap_err();
        assert_wire_reason(profile_error, StatusFailureReason::ProfileRestricted).await;
        let stale =
            ensure_status_metrics_match_authoritative_height(&Status::default(), 1).unwrap_err();
        assert_wire_reason(stale, StatusFailureReason::MetricsStale).await;
    }
}
