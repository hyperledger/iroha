// Actual signed-carrier admission retains local resource ownership until HTTP retry.
mod signed_attachment_refusal {
    use super::*;
    use iroha_core::execution_attempt::ExecutionDeferred;
    use iroha_data_model::{
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        transaction::{FeePaymentIntent, SignedAttachmentErrorV1, SignedAttachmentPlanV1},
    };
    use iroha_version::codec::EncodeVersioned as _;
    use norito::core::{DecodeBudgetContext, DecodeLocalRefusal, DecodeLocalRefusalKind};

    fn fixture() -> (SharedAppState, SignedTransaction, Vec<u8>) {
        let key = checked_torii_test_ed25519_keypair(0x72, "attachment retry authority");
        let authority = AccountId::new(key.public_key().clone());
        let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
        let attachment = ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("halo2/ipa", "local_attachment_reader"),
        );
        let tx = TransactionBuilder::new(
            *app.state.network_id_ref(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "signed carrier retry".into())])
        .with_proof_attachments([attachment])
        .expect("structurally valid proof wrapper")
        .sign(key.private_key());
        let wire = tx.encode_versioned();
        (app, tx, wire)
    }
    fn narrow() -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX)
    }
    fn original(error: &Error) -> DecodeLocalRefusal {
        let Error::TransactionAdmissionDeferred(owner) = error else {
            panic!("expected typed unfinished admission, got {error:?}");
        };
        assert!(owner.allocation_refusal().is_none());
        let original = owner
            .decode_refusal()
            .expect("original scoped reader error");
        assert_eq!(original.kind(), DecodeLocalRefusalKind::EnclosingLimit);
        assert!(
            matches!(original.resource_error(), norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 } if attempted > 0)
        );
        original.clone()
    }
    fn unchanged_receipts(app: &SharedAppState, tx: &SignedTransaction) {
        assert_eq!(app.queue.active_len(), 0);
        assert!(app.pipeline_status_cache.entries.is_empty());
        assert!(app.pipeline_status_cache.pending_blocks.is_empty());
        assert!(!app.state.has_committed_entrypoint(tx.hash_as_entrypoint()));
    }
    async fn assert_retry_response(error: Error, format: crate::utils::ResponseFormat) {
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        use tower::ServiceExt as _;
        // Move the exact error through the real outer HTTP error middleware.
        // The test-only slot supplies a one-shot response, without cloning its owner.
        let error = Arc::new(Mutex::new(Some(error)));
        let router = axum::Router::new()
            .route(
                "/",
                axum::routing::get(
                    |State(error): State<Arc<Mutex<Option<Error>>>>| async move {
                        error.lock().unwrap().take().expect("one original response")
                    },
                ),
            )
            .layer(axum::middleware::from_fn(capture_response_format))
            .layer(axum::middleware::from_fn(coalesce_accept_headers))
            .layer(axum::middleware::from_fn(enforce_typed_error_contract))
            .with_state(error);
        let accept = match format {
            crate::utils::ResponseFormat::Json => "application/json",
            crate::utils::ResponseFormat::Norito => crate::utils::NORITO_MIME_TYPE,
        };
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header(axum::http::header::ACCEPT, accept)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "1");
        for header in [
            "x-iroha-reject-code",
            "x-iroha-transactions-accepted",
            "x-iroha-entrypoint-hash",
            "preference-applied",
        ] {
            assert!(response.headers().get(header).is_none(), "{header}");
        }
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let envelope: ErrorEnvelope = match format {
            crate::utils::ResponseFormat::Json => norito::json::from_slice(&bytes).unwrap(),
            crate::utils::ResponseFormat::Norito => norito::decode_from_bytes(&bytes).unwrap(),
        };
        assert_eq!(envelope.code, "transaction_admission_deferred");
        assert_eq!(
            envelope.message,
            "Local readiness or resources prevented transaction admission. This request was not queued; retry the unchanged signed request."
        );
        let details = envelope.details.unwrap();
        assert_eq!(details.retry_after_seconds, Some(1));
        assert!(details.reject_code.is_none() && details.queue.is_none());
        assert!(details.actual.is_none() && details.expected.is_none());
    }

    #[tokio::test]
    async fn signed_attachment_actual_ingress_variants_keep_original_and_same_source_retry() {
        for mode in 0..3 {
            let (app, tx, wire) = fixture();
            let signature = tx.signature().clone();
            // The actual decode and Ed25519 batch check precede the narrow reader
            // scope. A supplied boolean never substitutes for signature checking.
            let decoded = DecodedVersionedSignedTransaction::decode_versioned(&wire).unwrap();
            let mut prechecks =
                precheck_transaction_batch_ed25519(std::slice::from_ref(&decoded), 8);
            let precheck = prechecks.remove(0);
            assert!(precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_none());
            let input = tx.clone();
            let outer_pool = iroha_allocation::AllocationBudget::new(
                DecodeBudgetContext::allocation_layout().size(),
            );
            let context = DecodeBudgetContext::try_new_owned(narrow(), &outer_pool).unwrap();
            #[cfg(feature = "telemetry")]
            let before_rejected = app
                .telemetry
                .metrics()
                .torii_route_stage_latency_seconds
                .with_label_values(&["transaction", "verify", "error"])
                .get_sample_count();
            #[cfg(feature = "telemetry")]
            let before_deferred = app
                .telemetry
                .metrics()
                .torii_route_stage_latency_seconds
                .with_label_values(&["transaction", "verify", "deferred"])
                .get_sample_count();
            let error = context
                .with(|| match mode {
                    0 => routing::accept_transaction_for_ingress(
                        app.state.clone(),
                        input,
                        &app.telemetry,
                    ),
                    1 => routing::accept_decoded_signed_transaction_for_ingress(
                        app.state.clone(),
                        decoded,
                        &app.telemetry,
                    ),
                    _ => routing::accept_decoded_signed_transaction_for_ingress_with_precheck(
                        app.state.clone(),
                        decoded,
                        &app.telemetry,
                        precheck.single_ed25519_prechecked,
                        precheck.precheck_rejection,
                    ),
                })
                .expect_err("genuine signed-carrier reader refuses the enclosing budget");
            let captured = original(&error);
            assert_eq!(context.consumed_allocated_bytes(), 0);
            drop(context);
            assert_eq!(
                original(&error),
                captured,
                "observer retirement preserves identity"
            );
            #[cfg(feature = "telemetry")]
            {
                let metrics = app.telemetry.metrics();
                assert_eq!(
                    metrics
                        .torii_route_stage_latency_seconds
                        .with_label_values(&["transaction", "verify", "error"])
                        .get_sample_count(),
                    before_rejected
                );
                assert_eq!(
                    metrics
                        .torii_route_stage_latency_seconds
                        .with_label_values(&["transaction", "verify", "deferred"])
                        .get_sample_count(),
                    before_deferred + 1
                );
            }
            unchanged_receipts(&app, &tx);
            let Error::TransactionAdmissionDeferred(owner) = error else {
                unreachable!()
            };
            let owner = ExecutionDeferred::try_from_vm_error(owner.into_vm_error()).unwrap();
            assert_eq!(owner.decode_refusal(), Some(&captured));
            assert_retry_response(
                Error::TransactionAdmissionDeferred(owner),
                crate::utils::ResponseFormat::Norito,
            )
            .await;
            drop(captured);
            assert_eq!(outer_pool.reserved_bytes(), 0);
            let decoded = DecodedVersionedSignedTransaction::decode_versioned(&wire).unwrap();
            decoded
                .signed()
                .validate_signed_attachments_v1()
                .expect("same signed source completes structural checking after release");
            decoded
                .signed()
                .verify_signature()
                .expect("same signed source retains valid authorization");
            assert_eq!(decoded.signed().encode_versioned(), wire);
            assert_eq!(decoded.signed().signature(), &signature);
            let error = routing::accept_decoded_signed_transaction_for_ingress(
                app.state.clone(),
                decoded,
                &app.telemetry,
            )
            .expect_err("retry reaches the current missing consuming-route refusal");
            assert!(matches!(
                &error,
                Error::AcceptTransaction(AcceptTransactionFail::SignedAttachments(
                    SignedAttachmentErrorV1::UnsupportedOperation { action_index: 0 }
                ))
            ));
            assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
            assert_eq!(tx.encode_versioned(), wire);
            assert_eq!(tx.signature(), &signature);
            // Retrying completes validation; an unsupported operation stays rejected.
            unchanged_receipts(&app, &tx);
        }
    }
    #[tokio::test]
    async fn signed_attachment_worker_moves_original_and_releases_compute_without_receipt() {
        let (app, tx, wire) = fixture();
        let signature = tx.signature().clone();
        let capacity = app.transaction_ingress_compute_inflight.available_permits();
        let permit =
            try_acquire_transaction_ingress_compute(&app.transaction_ingress_compute_inflight)
                .unwrap();
        let state = app.state.clone();
        let telemetry = app.telemetry.clone();
        let decoded = DecodedVersionedSignedTransaction::decode_versioned(&wire).unwrap();
        // Real physical ingress worker and decoded route; the enclosing scope
        // belongs to this worker thread, not an unrelated HTTP executor thread.
        let error =
            run_transaction_ingress_compute_job(permit, "fixture_worker_failed", move || {
                norito::with_decode_limits_scope(narrow(), || {
                    routing::accept_decoded_signed_transaction_for_ingress(
                        state, decoded, &telemetry,
                    )
                })
            })
            .await
            .expect_err("worker returns original unfinished admission");
        let captured = original(&error);
        assert_eq!(
            app.transaction_ingress_compute_inflight.available_permits(),
            capacity
        );
        unchanged_receipts(&app, &tx);
        assert_retry_response(error, crate::utils::ResponseFormat::Json).await;
        drop(captured);
        let decoded = DecodedVersionedSignedTransaction::decode_versioned(&wire).unwrap();
        decoded
            .signed()
            .validate_signed_attachments_v1()
            .expect("caller-owned signed source completes structural checking after release");
        decoded
            .signed()
            .verify_signature()
            .expect("caller-owned signed source retains valid authorization");
        assert_eq!(decoded.signed().encode_versioned(), wire);
        assert_eq!(decoded.signed().signature(), &signature);
        let error = routing::accept_decoded_signed_transaction_for_ingress(
            app.state.clone(),
            decoded,
            &app.telemetry,
        )
        .expect_err("caller-owned retry reaches the current missing consuming-route refusal");
        assert!(matches!(
            &error,
            Error::AcceptTransaction(AcceptTransactionFail::SignedAttachments(
                SignedAttachmentErrorV1::UnsupportedOperation { action_index: 0 }
            ))
        ));
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(tx.encode_versioned(), wire);
        assert_eq!(tx.signature(), &signature);
        unchanged_receipts(&app, &tx);
    }

    fn actual_accept_failure(app: &SharedAppState, tx: SignedTransaction) -> AcceptTransactionFail {
        let parameters = app.state.transaction_admission_parameters();
        let drift = parameters.sumeragi().max_clock_drift();
        let limits = parameters.transaction();
        let policy = parameters
            .require_crypto_policy()
            .expect("initialized attachment fixture policy");
        norito::with_decode_limits_scope(narrow(), || {
            AcceptedTransaction::accept_entrypoint(
                tx.into(),
                app.state.network_id_ref(),
                drift,
                limits,
                policy,
            )
        })
        .expect_err("actual carrier reader refusal")
    }

    #[tokio::test]
    async fn signed_attachment_public_error_constructors_never_render_local_rejection() {
        let (app, tx, wire) = fixture();
        for direct in [false, true] {
            let fail = actual_accept_failure(&app, tx.clone());
            let original = fail.local_refusal().unwrap().clone();
            let error = if direct {
                Error::AcceptTransaction(fail)
            } else {
                Error::from(fail)
            };
            assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
            let classified = error.classify_transaction_admission();
            let Error::TransactionAdmissionDeferred(owner) = classified else {
                panic!("original must move")
            };
            assert_eq!(owner.decode_refusal(), Some(&original));
            assert_retry_response(
                Error::TransactionAdmissionDeferred(owner),
                crate::utils::ResponseFormat::Norito,
            )
            .await;
            // Cover direct wrapper rendering independently from its classifier.
            assert_retry_response(
                Error::AcceptTransaction(actual_accept_failure(&app, tx.clone())),
                crate::utils::ResponseFormat::Json,
            )
            .await;
            let envelope =
                Error::AcceptTransaction(actual_accept_failure(&app, tx.clone())).into_envelope();
            assert_eq!(envelope.code, "transaction_admission_deferred");
            let details = envelope.details.unwrap();
            assert_eq!(details.retry_after_seconds, Some(1));
            assert!(details.reject_code.is_none());
        }
        assert_eq!(tx.encode_versioned(), wire);
        unchanged_receipts(&app, &tx);
    }

    #[tokio::test]
    async fn signed_attachment_completed_admission_keeps_bad_request_and_reject_metadata() {
        let (app, tx, _) = fixture();
        let key = checked_torii_test_ed25519_keypair(0x72, "attachment retry authority");
        // Empty signed attachment intent is an actual intrinsic schema violation.
        let malformed = TransactionBuilder::new(
            *app.state.network_id_ref(),
            tx.authority().clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "malformed intent".into())])
        .with_signed_attachments(SignedAttachmentPlanV1::new().declare())
        .sign(key.private_key());
        let error =
            routing::accept_transaction_for_ingress(app.state.clone(), malformed, &app.telemetry)
                .expect_err("completed schema violation stays rejected");
        assert!(matches!(
            &error,
            Error::AcceptTransaction(AcceptTransactionFail::SignedAttachments(
                SignedAttachmentErrorV1::NoActions
            ))
        ));
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()["x-iroha-reject-code"],
            "transaction_rejected"
        );
        assert!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_none()
        );
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let envelope: ErrorEnvelope = norito::decode_from_bytes(&bytes).unwrap();
        assert_eq!(envelope.code, "transaction_rejected");
        assert!(
            envelope
                .message
                .contains("signed attachments declare no action")
        );
        assert_eq!(
            envelope.details.unwrap().reject_code.as_deref(),
            Some("transaction_rejected")
        );
        unchanged_receipts(&app, &tx);
    }

    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn signed_attachment_outer_handler_metrics_do_not_record_local_rejection() {
        let (app, tx, wire) = fixture();
        let metrics = app.telemetry.metrics();
        let error_count = metrics
            .torii_route_stage_latency_seconds
            .with_label_values(&["transaction", "handle", "error"])
            .get_sample_count();
        let deferred_count = metrics
            .torii_route_stage_latency_seconds
            .with_label_values(&["transaction", "handle", "deferred"])
            .get_sample_count();
        let input = tx.clone();
        let error = norito::with_decode_limits_scope(narrow(), || {
            futures::executor::block_on(routing::handle_transaction_with_metrics(
                app.queue.clone(),
                app.state.clone(),
                input,
                app.telemetry.clone(),
                "attachment-refusal-control",
            ))
        })
        .expect_err("actual outer handler preserves local admission refusal");
        let captured = original(&error);
        let metrics = app.telemetry.metrics();
        assert_eq!(
            metrics
                .torii_route_stage_latency_seconds
                .with_label_values(&["transaction", "handle", "error"])
                .get_sample_count(),
            error_count
        );
        assert_eq!(
            metrics
                .torii_route_stage_latency_seconds
                .with_label_values(&["transaction", "handle", "deferred"])
                .get_sample_count(),
            deferred_count + 1
        );
        assert_retry_response(error, crate::utils::ResponseFormat::Norito).await;
        drop(captured);
        assert_eq!(tx.encode_versioned(), wire);
        unchanged_receipts(&app, &tx);
    }
}
