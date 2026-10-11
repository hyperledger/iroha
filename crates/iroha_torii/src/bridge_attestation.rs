//! Exact failure classification for the challenge-bound finality endpoint.
use axum::response::IntoResponse as _;
use iroha_core::sumeragi::{
    certified_chain::ChainReadError,
    finality::{AttestationBuildError as BuildError, ProofError, status_is_consistent},
};
use iroha_data_model::{
    query::error::{CanonicalHistoryError, QueryExecutionFail},
    sumeragi::SumeragiStatus,
};
use iroha_torii_shared::bridge_attestation::{
    FinalityAttestationFailure, FinalityAttestationFailureReason as Reason,
};

/// Reject restart or contradictory status before deciding whether consensus is uninitialized.
pub(crate) fn startup_failure(
    restart_required: bool,
    status: Option<&SumeragiStatus>,
) -> Option<Reason> {
    if restart_required || status.is_some_and(|value| value.is_halted()) {
        return Some(Reason::RestartRequired);
    }
    if status.is_none() {
        return Some(Reason::ConsensusUninitialized);
    }
    if status.is_some_and(|value| !status_is_consistent(value)) {
        return Some(Reason::ConflictingState);
    }
    None
}

/// Classify the actual immutable-view build failure without treating missing proof as startup.
pub(crate) fn build_failure(error: BuildError, status_committed_height: u64) -> Reason {
    match error {
        BuildError::EmptyState if status_committed_height == 0 => Reason::GenesisUncommitted,
        BuildError::EmptyState => Reason::ConflictingState,
        BuildError::HeightIsNotDurableTip { .. } | BuildError::StatusHeightMismatch => {
            Reason::TipChanged
        }
        BuildError::RestartRequired => Reason::RestartRequired,
        BuildError::InvalidStatus | BuildError::InvalidBody(_) => Reason::ConflictingState,
        BuildError::FinalityProof(error) | BuildError::GenesisFinalityProof(error) => match error {
            ProofError::Chain(
                ChainReadError::NotCommitted { .. }
                | ChainReadError::NotInView { .. }
                | ChainReadError::MissingCertificate { .. },
            )
            | ProofError::UnverifiedCommittee(_)
            | ProofError::Chain(ChainReadError::Committee { .. }) => Reason::FinalityUnavailable,
            ProofError::NativeExecution(QueryExecutionFail::CanonicalHistory(
                CanonicalHistoryError::BodyUnavailable { .. }
                | CanonicalHistoryError::HeightOutsideSnapshot { .. },
            )) => Reason::FinalityUnavailable,
            // The original execution owner has rejected the captured history or its
            // selected certificate. No diagnostic string grants startup progress.
            ProofError::NativeExecution(_) => Reason::ConflictingState,
            _ => Reason::ConflictingState,
        },
        BuildError::HeightOverflow
        | BuildError::InvalidSigner
        | BuildError::ClockUnavailable
        | BuildError::Signing(_) => Reason::InternalFailure,
    }
}

/// Encode one closed non-success observation with the endpoint cache protections.
pub(crate) fn failure_response(
    reason: Reason,
    challenge: [u8; 32],
    height: u64,
    tip_mismatch: Option<
        iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1,
    >,
    format: crate::utils::ResponseFormat,
) -> crate::AxResponse {
    let failure = FinalityAttestationFailure {
        challenge,
        height,
        reason,
        tip_mismatch,
    };
    let mut response = match format {
        crate::utils::ResponseFormat::Norito => {
            crate::NoritoBody(failure.into_error_envelope()).into_response()
        }
        crate::utils::ResponseFormat::Json => {
            crate::JsonBody(failure.into_error_envelope()).into_response()
        }
    };
    *response.status_mut() = axum::http::StatusCode::from_u16(reason.http_status_code())
        .expect("closed failure statuses are valid HTTP");
    crate::protect_bridge_finality_attestation_response(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn finality_failure_survives_the_actual_http_error_boundary() {
        use iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1;
        let key =
            iroha_crypto::KeyPair::try_from_seed(vec![73; 32], iroha_crypto::Algorithm::BlsNormal)
                .unwrap();
        let node_id = iroha_model_base::peer::PeerId::new(key.public_key().clone());
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"HTTP boundary finality",
            )),
        );
        for reason in [
            Reason::TipChanged,
            Reason::ConsensusUninitialized,
            Reason::GenesisUncommitted,
            Reason::RestartRequired,
            Reason::FinalityUnavailable,
            Reason::ConflictingState,
            Reason::InternalFailure,
        ] {
            for format in [
                crate::utils::ResponseFormat::Json,
                crate::utils::ResponseFormat::Norito,
            ] {
                let progress = (reason == Reason::TipChanged).then(|| {
                    BridgeFinalityAttestationTipMismatchV1 {
                        requested_height: 10,
                        applied_height: 9,
                        status_height: 10,
                        challenge: [7; 32],
                        node_id: node_id.clone(),
                        network_id,
                    }
                });
                let router = axum::Router::new()
                    .route(
                        "/v1/bridge/finality/attestation/{height}",
                        axum::routing::get(move || async move {
                            failure_response(reason, [7; 32], 10, progress, format)
                        }),
                    )
                    .layer(axum::middleware::from_fn(
                        crate::enforce_typed_error_contract,
                    ));
                let media = if matches!(format, crate::utils::ResponseFormat::Norito) {
                    "application/x-norito"
                } else {
                    "application/json"
                };
                let response = router
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/v1/bridge/finality/attestation/10")
                            .header(axum::http::header::ACCEPT, media)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), reason.http_status_code());
                let expected_content_type =
                    if matches!(format, crate::utils::ResponseFormat::Norito) {
                        "application/x-norito"
                    } else {
                        "application/json; charset=utf-8"
                    };
                assert_eq!(
                    response.headers()[axum::http::header::CONTENT_TYPE],
                    expected_content_type
                );
                assert_eq!(
                    response.headers()[axum::http::header::CACHE_CONTROL],
                    "no-store"
                );
                assert_eq!(response.headers()["x-content-type-options"], "nosniff");
                assert_eq!(
                    response.headers()[axum::http::header::VARY],
                    "X-Iroha-Finality-Challenge, Accept"
                );
                assert!(
                    !response
                        .headers()
                        .contains_key(axum::http::header::RETRY_AFTER)
                );
                let bytes = axum::body::to_bytes(
                    response.into_body(),
                    iroha_torii_shared::bridge_attestation::FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
                )
                .await
                .unwrap();
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    if matches!(format, crate::utils::ResponseFormat::Norito) {
                        norito::decode_canonical_with_limits(
                            &bytes,
                            norito::canonical_decode_limits(bytes.len()),
                        )
                        .unwrap()
                    } else {
                        norito::json::from_slice(&bytes).unwrap()
                    };
                assert_eq!(
                    envelope.code(),
                    iroha_torii_shared::bridge_attestation::FINALITY_ATTESTATION_FAILURE_CODE,
                    "reason={reason:?}, media={media}"
                );
                let mut details = envelope.details.unwrap();
                let observed = details.finality_attestation_failure.take().unwrap();
                assert!(details.is_empty());
                assert_eq!(observed.reason, reason);
                assert!(observed.matches(10, [7; 32], &node_id, network_id));
            }
        }
    }

    #[tokio::test]
    async fn internal_finality_failure_keeps_only_the_closed_record_through_http_boundary() {
        use axum::http::{HeaderValue, StatusCode};
        use iroha_torii_shared::{
            ErrorDetails, ErrorEnvelope, bridge_attestation::FINALITY_ATTESTATION_FAILURE_CODE,
        };

        for format in [
            crate::utils::ResponseFormat::Json,
            crate::utils::ResponseFormat::Norito,
        ] {
            let media = if matches!(format, crate::utils::ResponseFormat::Norito) {
                "application/x-norito"
            } else {
                "application/json"
            };
            for case in 0..8 {
                let router = axum::Router::new()
                    .route(
                        "/v1/bridge/finality/attestation/{height}",
                        axum::routing::get(move || async move {
                            let mut failure = FinalityAttestationFailure {
                                height: 10,
                                challenge: [7; 32],
                                reason: Reason::InternalFailure,
                                tip_mismatch: None,
                            };
                            match case {
                                2 => failure.height = 0,
                                3 => failure.challenge = [0; 32],
                                5 => failure.reason = Reason::GenesisUncommitted,
                                _ => {}
                            }
                            let mut envelope = failure.into_error_envelope();
                            match case {
                                1 => {
                                    envelope = ErrorEnvelope::new(
                                        "signer_internal_diagnostic",
                                        "private signer implementation detail",
                                    )
                                    .with_details(
                                        ErrorDetails {
                                            hint: Some("private signer diagnostic".to_owned()),
                                            ..ErrorDetails::default()
                                        },
                                    );
                                }
                                4 => envelope.code = "query_validation_failed".to_owned(),
                                6 => {
                                    envelope.details.as_mut().unwrap().hint =
                                        Some("private signer diagnostic".to_owned());
                                }
                                7 => envelope.details = None,
                                _ => {}
                            }
                            envelope.message = "private signer implementation detail".to_owned();
                            let mut response = crate::utils::respond_with_status_and_format(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                envelope,
                                format,
                            );
                            response.headers_mut().insert(
                                "x-iroha-reject-code",
                                HeaderValue::from_static("private_signer_failure"),
                            );
                            response.headers_mut().insert(
                                "x-iroha-axt-reason",
                                HeaderValue::from_static("private signer diagnostic"),
                            );
                            if case == 0 {
                                response.headers_mut().insert(
                                    axum::http::header::RETRY_AFTER,
                                    HeaderValue::from_static("7"),
                                );
                            }
                            response
                        }),
                    )
                    .layer(axum::middleware::from_fn(
                        crate::enforce_typed_error_contract,
                    ));
                let response = router
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/v1/bridge/finality/attestation/10")
                            .header(axum::http::header::ACCEPT, media)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert!(!response.headers().contains_key("x-iroha-reject-code"));
                assert!(!response.headers().contains_key("x-iroha-axt-reason"));
                assert!(
                    !response
                        .headers()
                        .contains_key(axum::http::header::RETRY_AFTER)
                );
                let bytes = axum::body::to_bytes(
                    response.into_body(),
                    iroha_torii_shared::bridge_attestation::FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
                )
                .await
                .unwrap();
                let envelope: ErrorEnvelope =
                    if matches!(format, crate::utils::ResponseFormat::Norito) {
                        norito::decode_canonical_with_limits(
                            &bytes,
                            norito::canonical_decode_limits(bytes.len()),
                        )
                        .unwrap()
                    } else {
                        norito::json::from_slice(&bytes).unwrap()
                    };
                if case == 0 {
                    assert_eq!(
                        envelope.code(),
                        FINALITY_ATTESTATION_FAILURE_CODE,
                        "case={case}, media={media}"
                    );
                    assert_eq!(
                        envelope.message(),
                        "The requested finality attestation is unavailable."
                    );
                    let mut details = envelope.details.unwrap();
                    let failure = details.finality_attestation_failure.take().unwrap();
                    assert!(details.is_empty());
                    assert_eq!(failure.height, 10);
                    assert_eq!(failure.challenge, [7; 32]);
                    assert_eq!(failure.reason, Reason::InternalFailure);
                    assert!(failure.tip_mismatch.is_none());
                } else {
                    assert_eq!(
                        envelope.code(),
                        "internal_server_error",
                        "case={case}, media={media}"
                    );
                    assert_eq!(envelope.message(), "Torii could not complete the request.");
                    assert!(envelope.details.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn http_boundary_rejects_mismatched_finality_details_and_preserves_generic_errors() {
        for case in 0..4 {
            let router = axum::Router::new()
                .route(
                    "/test",
                    axum::routing::get(move || async move {
                        if case == 0 {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        let mut failure = FinalityAttestationFailure {
                            height: 10,
                            challenge: [7; 32],
                            reason: Reason::GenesisUncommitted,
                            tip_mismatch: None,
                        };
                        if case == 3 {
                            failure.reason = Reason::TipChanged;
                        }
                        let mut envelope = failure.into_error_envelope();
                        if case == 2 {
                            envelope.code = "query_validation_failed".into();
                        }
                        crate::utils::respond_with_status_and_format(
                            if case == 1 {
                                axum::http::StatusCode::CONFLICT
                            } else {
                                axum::http::StatusCode::SERVICE_UNAVAILABLE
                            },
                            envelope,
                            crate::utils::ResponseFormat::Norito,
                        )
                    }),
                )
                .layer(axum::middleware::from_fn(
                    crate::enforce_typed_error_contract,
                ));
            let response = router
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/test")
                        .header(axum::http::header::ACCEPT, "application/x-norito")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap();
            let details = envelope.details.unwrap_or_default();
            assert!(details.finality_attestation_failure.is_none());
            if case == 0 {
                assert!(details.retry_after_seconds.is_some());
            }
        }
    }
    #[test]
    fn restart_required_wins_even_before_first_status() {
        assert_eq!(startup_failure(true, None), Some(Reason::RestartRequired));
        assert_eq!(
            startup_failure(false, None),
            Some(Reason::ConsensusUninitialized)
        );
    }
    fn initialized_status() -> SumeragiStatus {
        use iroha_data_model::sumeragi::SumeragiFootprint;
        SumeragiStatus {
            protocol_version: 1,
            config_fingerprint: iroha_crypto::Hash::new(b"bridge attestation test config"),
            beacon_horizon: None,
            instance: [7; 32],
            height: 2,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 500,
            committed_height: 1,
            applied_height: 1,
            awaiting: false,
            signer: None,
            unanchored: false,
            abstaining: true,
            halted: None,
            footprint: SumeragiFootprint {
                votes: 0,
                timeouts: 0,
                blocks: 0,
                exec_entries: 0,
                wants: 0,
                pending_apply: 0,
                sync_entries: 0,
                sync_bytes: 0,
                peers: 4,
                recent_headers: 0,
                configs: 2,
                cert_cache: 0,
                evidence_keys: 0,
                probe: 0,
            },
        }
    }
    #[test]
    fn initialized_status_requires_structural_consistency_and_no_restart() {
        let mut status = initialized_status();
        assert_eq!(startup_failure(false, Some(&status)), None);
        status.halted = Some(iroha_data_model::sumeragi::SumeragiHaltReason::DriverAnomaly);
        assert_eq!(
            startup_failure(false, Some(&status)),
            Some(Reason::RestartRequired)
        );
        status.halted = None;
        status.applied_height = 2;
        assert_eq!(
            startup_failure(false, Some(&status)),
            Some(Reason::ConflictingState)
        );
    }
    #[test]
    fn durable_tip_and_finality_failures_never_become_startup() {
        assert_eq!(
            build_failure(BuildError::EmptyState, 0),
            Reason::GenesisUncommitted
        );
        assert_eq!(
            build_failure(BuildError::EmptyState, 1),
            Reason::ConflictingState
        );
        assert_eq!(
            build_failure(
                BuildError::HeightIsNotDurableTip {
                    requested: 1,
                    committed: 2
                },
                2
            ),
            Reason::TipChanged
        );
        assert_eq!(
            build_failure(BuildError::StatusHeightMismatch, 2),
            Reason::TipChanged
        );
        for error in [
            ProofError::Chain(ChainReadError::NotCommitted { height: 1 }),
            ProofError::Chain(ChainReadError::MissingCertificate { height: 1 }),
            ProofError::UnverifiedCommittee(1),
        ] {
            assert_eq!(
                build_failure(BuildError::FinalityProof(error.clone()), 1),
                Reason::FinalityUnavailable
            );
            assert_eq!(
                build_failure(BuildError::GenesisFinalityProof(error), 1),
                Reason::FinalityUnavailable
            );
        }
        for error in [
            ProofError::Chain(ChainReadError::HeaderMismatch { height: 1 }),
            ProofError::Portable(iroha_data_model::sumeragi_finality::FinalityError(
                "invalid signature".into(),
            )),
        ] {
            assert_eq!(
                build_failure(BuildError::FinalityProof(error), 1),
                Reason::ConflictingState
            );
        }
        assert_eq!(
            build_failure(BuildError::RestartRequired, 1),
            Reason::RestartRequired
        );
        assert_eq!(
            build_failure(BuildError::InvalidStatus, 1),
            Reason::ConflictingState
        );
        for error in [
            BuildError::InvalidSigner,
            BuildError::HeightOverflow,
            BuildError::ClockUnavailable,
            BuildError::Signing("failed".into()),
        ] {
            assert_eq!(build_failure(error, 1), Reason::InternalFailure);
        }
    }
    #[test]
    fn original_execution_failures_keep_typed_unavailability_and_never_grant_progress() {
        let expected_hash = iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"captured original block",
        ));
        for error in [
            CanonicalHistoryError::BodyUnavailable {
                height: 3,
                expected_hash,
            },
            CanonicalHistoryError::HeightOutsideSnapshot {
                height: 3,
                committed_height: 2,
            },
        ] {
            let proof = ProofError::NativeExecution(QueryExecutionFail::CanonicalHistory(error));
            assert_eq!(
                build_failure(BuildError::FinalityProof(proof), 3),
                Reason::FinalityUnavailable,
            );
        }
        for error in [
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BlockHashMismatch {
                height: 3,
                expected_hash,
                actual_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"different block",
                )),
            }),
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BlockHeightMismatch {
                height: 3,
                actual_height: 2,
            }),
            QueryExecutionFail::Conversion("native execution ancestry differs".into()),
            QueryExecutionFail::Conversion("canonical history body is unavailable".into()),
        ] {
            assert_eq!(
                build_failure(
                    BuildError::FinalityProof(ProofError::NativeExecution(error)),
                    3
                ),
                Reason::ConflictingState,
            );
        }
    }

    #[tokio::test]
    async fn failure_response_is_bounded_canonical_and_never_cached() {
        let response = failure_response(
            Reason::RestartRequired,
            [83; 32],
            1,
            None,
            crate::utils::ResponseFormat::Norito,
        );
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let bytes = axum::body::to_bytes(
            response.into_body(),
            iroha_torii_shared::bridge_attestation::FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
        )
        .await
        .expect("bounded failure");
        let decoded: iroha_torii_shared::ErrorEnvelope = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .expect("canonical body");
        assert_eq!(
            decoded
                .details
                .unwrap()
                .finality_attestation_failure
                .unwrap(),
            FinalityAttestationFailure {
                challenge: [83; 32],
                height: 1,
                reason: Reason::RestartRequired,
                tip_mismatch: None,
            }
        );
    }
}
