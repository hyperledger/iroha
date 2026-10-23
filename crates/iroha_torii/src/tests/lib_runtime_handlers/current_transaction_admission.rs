#[cfg(feature = "connect")]
async fn current_admission_http(
    app: SharedAppState,
    transaction: &SignedTransaction,
    endpoint: &str,
) -> Response {
    use iroha_version::codec::EncodeVersioned as _;
    use tower::ServiceExt as _;
    let body = if endpoint == route_catalog::pipeline::TRANSACTIONS_BATCH.path() {
        norito::to_bytes(&vec![transaction.encode_versioned()]).unwrap()
    } else if endpoint == route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path() {
        TransactionEntrypoint::External(transaction.clone()).encode_versioned()
    } else {
        transaction.encode_versioned()
    };
    let router = axum::Router::new()
        .route(
            route_catalog::pipeline::TRANSACTION.path(),
            axum::routing::post(super::handler_post_transaction),
        )
        .route(
            route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path(),
            axum::routing::post(super::handler_post_transaction_entrypoint),
        )
        .route(
            route_catalog::pipeline::TRANSACTIONS_BATCH.path(),
            axum::routing::post(super::handler_post_transactions_batch),
        )
        .with_state(app);
    router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(endpoint)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    crate::utils::NORITO_MIME_TYPE,
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[cfg(feature = "connect")]
async fn assert_unsupported_current_admission(response: Response) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        torii_response_header(&response, "x-iroha-reject-code"),
        Some("unsupported_transaction_admission")
    );
    for header in [
        "x-iroha-transactions-accepted",
        "x-iroha-route",
        "preference-applied",
    ] {
        assert!(
            response.headers().get(header).is_none(),
            "rejection cannot contain {header}"
        );
    }
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let envelope: iroha_torii_shared::ErrorEnvelope = if is_json {
        norito::json::from_slice(&bytes).unwrap()
    } else {
        norito::decode_from_bytes(&bytes).unwrap()
    };
    assert_eq!(envelope.code, "unsupported_transaction_admission");
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn current_http_admission_retains_exact_canonical_input_in_local_custody() {
    use iroha_version::codec::EncodeVersioned as _;
    for endpoint in [
        route_catalog::pipeline::TRANSACTION.path(),
        route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path(),
        route_catalog::pipeline::TRANSACTIONS_BATCH.path(),
    ] {
        let (app, key, _, _) = lifecycle_ordinary_fixture(true);
        let transaction = lifecycle_ordinary_transaction(
            &app,
            &key,
            vec![Log::new(Level::INFO, "current admission control".to_owned()).into()],
        );
        assert!(lifecycle_pending_wire(&app).is_empty());
        let response = current_admission_http(app.clone(), &transaction, endpoint).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(app.queue.active_len(), 1);
        assert_eq!(
            lifecycle_pending_wire(&app),
            vec![TransactionEntrypoint::External(transaction.clone()).encode_versioned()]
        );
        assert!(
            !app.state
                .has_committed_entrypoint(transaction.hash_as_entrypoint())
        );
    }
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn current_http_admission_rejects_actual_multiroute_before_local_custody() {
    let domains = [
        DomainId::try_new("first", "universal").unwrap(),
        DomainId::try_new("second", "secondary").unwrap(),
    ];
    let world = World::with(
        domains
            .iter()
            .cloned()
            .map(|id| Domain::new(id).build(&ALICE_ID)),
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let app =
        mk_app_state_for_tests_with_world_and_nexus(world, multiple_dataspace_nexus_for_test());
    for domain in &domains {
        bind_domain_name_for_test(&app, &domain.to_string());
    }
    let transaction = TransactionBuilder::new(
        *app.state.network_id_ref(),
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(domains.into_iter().map(|domain| {
        iroha_data_model::isi::SetKeyValue::domain(
            domain,
            "current_admission".parse().unwrap(),
            iroha_primitives::json::Json::new(true),
        )
    }))
    .sign(ALICE_KEYPAIR.private_key());
    let plan = app
        .queue
        .route_payload_plan_with_state(transaction.payload(), &app.state)
        .unwrap();
    assert!(
        !matches!(plan, RoutingPlan::Single(_)),
        "exercise actual two-dataspace routing"
    );
    let before = lifecycle_pending_wire(&app);
    for endpoint in [
        route_catalog::pipeline::TRANSACTION.path(),
        route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path(),
        route_catalog::pipeline::TRANSACTIONS_BATCH.path(),
    ] {
        assert_unsupported_current_admission(
            current_admission_http(app.clone(), &transaction, endpoint).await,
        )
        .await;
        assert_eq!(app.queue.active_len(), 0);
        assert_eq!(lifecycle_pending_wire(&app), before);
    }
}

#[cfg(feature = "connect")]
#[tokio::test]
async fn anonymous_entrypoint_unavailable_returns_503_before_queue_mutation() {
    use iroha_version::codec::EncodeVersioned as _;
    use tower::ServiceExt as _;
    let (app, _, _, _) = lifecycle_ordinary_fixture(true);
    let entry = crate::anonymous_ballot_test_support::entrypoint(*app.state.network_id_ref());
    let endpoint = route_catalog::pipeline::TRANSACTION_ENTRYPOINT.path();
    let router = axum::Router::new()
        .route(
            endpoint,
            axum::routing::post(super::handler_post_transaction_entrypoint),
        )
        .with_state(app.clone());
    for (mime, body) in [
        (crate::utils::NORITO_MIME_TYPE, entry.encode_versioned()),
        (
            "application/json",
            format!(
                "{{\"version\":1,\"content\":{}}}",
                norito::json::to_json(&entry).unwrap()
            )
            .into_bytes(),
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header(axum::http::header::CONTENT_TYPE, mime)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get("x-iroha-reject-code").is_none());
        assert!(
            response
                .headers()
                .get("x-iroha-transactions-accepted")
                .is_none()
        );
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let envelope: iroha_torii_shared::ErrorEnvelope =
            norito::decode_from_bytes(&bytes).unwrap();
        assert_eq!(envelope.code(), "anonymous_ballot_unavailable");
        assert!(lifecycle_pending_wire(&app).is_empty());
    }
}

/// These controls deliberately use pristine State instead of the ready app policy fixture.
mod committed_crypto_policy_admission {
    use super::*;
    use iroha_core::tx::{DecodedVersionedSignedTransaction, SignatureRejectionCode};
    use iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1;
    use iroha_version::codec::EncodeVersioned as _;

    fn fixture(policy: Option<CryptoAdmissionPolicyV1>) -> (Arc<IrohaState>, SignedTransaction) {
        let key = checked_torii_test_ed25519_keypair(0xD3, "committed policy admission signer");
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        if let Some(policy) = policy {
            let mut block = world.block();
            block
                .parameters
                .set_parameter(policy.into_parameter().unwrap())
                .unwrap();
            block.commit();
        }
        let state = Arc::new(IrohaState::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let transaction = TransactionBuilder::new(
            *state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "original committed policy".to_owned(),
        )])
        .sign(key.private_key());
        (state, transaction)
    }

    fn ingress(
        state: Arc<IrohaState>,
        transaction: &SignedTransaction,
        mode: usize,
    ) -> Result<AcceptedTransaction<'static>, Error> {
        let telemetry = MaybeTelemetry::disabled();
        if mode == 0 {
            return routing::accept_transaction_for_ingress(state, transaction.clone(), &telemetry);
        }
        let decoded =
            DecodedVersionedSignedTransaction::decode_versioned(&transaction.encode_versioned())
                .unwrap();
        if mode == 1 {
            return routing::accept_decoded_signed_transaction_for_ingress(
                state, decoded, &telemetry,
            );
        }
        let mut prechecks = precheck_transaction_batch_ed25519(std::slice::from_ref(&decoded), 8);
        let precheck = prechecks.remove(0);
        assert!(precheck.single_ed25519_prechecked && precheck.precheck_rejection.is_none());
        routing::accept_decoded_signed_transaction_for_ingress_with_precheck(
            state,
            decoded,
            &telemetry,
            precheck.single_ed25519_prechecked,
            precheck.precheck_rejection,
        )
    }

    #[tokio::test]
    async fn pristine_state_crypto_policy_defers_all_ingress_variants_without_rejection() {
        let (state, transaction) = fixture(None);
        let original = transaction.encode_versioned();
        assert!(
            state
                .transaction_admission_parameters()
                .require_crypto_policy()
                .is_err()
        );
        for mode in 0..3 {
            let error =
                ingress(state.clone(), &transaction, mode).expect_err("no genesis policy owner");
            assert!(
                matches!(&error, Error::TransactionAdmissionDeferred(original)
                if original.reason() == ivm::error::ExecutionDeferral::CryptoAdmissionPolicyUnavailable)
            );
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "1");
            assert!(response.headers().get("x-iroha-reject-code").is_none());
            assert!(
                response
                    .headers()
                    .get("x-iroha-transactions-accepted")
                    .is_none()
            );
            assert_eq!(transaction.encode_versioned(), original);
            assert!(!state.has_committed_entrypoint(transaction.hash_as_entrypoint()));
        }
    }

    #[test]
    fn explicit_committed_policy_controls_every_ingress_signature_path() {
        let (allowed, transaction) = fixture(Some(
            CryptoAdmissionPolicyV1::new(vec![iroha_crypto::Algorithm::Ed25519]).unwrap(),
        ));
        let original = transaction.encode_versioned();
        for mode in 0..3 {
            let accepted =
                ingress(allowed.clone(), &transaction, mode).expect("explicit member admitted");
            assert_eq!(accepted.external(), Some(&transaction));
            assert_eq!(transaction.encode_versioned(), original);
        }
        let (denied, transaction) = fixture(Some(
            CryptoAdmissionPolicyV1::new(vec![iroha_crypto::Algorithm::Secp256k1]).unwrap(),
        ));
        for mode in 0..3 {
            match ingress(denied.clone(), &transaction, mode)
                .expect_err("no implicit Ed25519 membership")
            {
                Error::AcceptTransaction(AcceptTransactionFail::SignatureVerification(failure)) => {
                    assert_eq!(
                        failure.code(),
                        SignatureRejectionCode::AlgorithmNotPermitted
                    )
                }
                other => panic!("expected explicit policy denial, got {other:?}"),
            }
        }
    }

    #[test]
    fn ready_fixture_preserves_an_explicit_restrictive_policy() {
        let mut world = World::default();
        let policy =
            CryptoAdmissionPolicyV1::new(vec![iroha_crypto::Algorithm::Secp256k1]).unwrap();
        let mut block = world.block();
        block
            .parameters
            .set_parameter(policy.clone().into_parameter().unwrap())
            .unwrap();
        block.commit();
        crate::test_utils::author_ready_fixture_crypto_policy(&mut world);
        let state = IrohaState::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert_eq!(
            state
                .transaction_admission_parameters()
                .require_crypto_policy()
                .unwrap(),
            &policy
        );
    }

    #[test]
    fn unavailable_crypto_implementation_remains_typed_through_public_error_adapters() {
        // This is an adapter control. Actual backend-absence verification requires
        // the Crypto/model minimal-feature controls; this fixed cause is not a signature verdict.
        let expected = iroha_crypto::UnsupportedImplementation {
            algorithm: iroha_crypto::Algorithm::MlDsa,
            operation: iroha_crypto::CryptoOperation::VerifySignature,
        };
        for direct in [false, true] {
            let failure = AcceptTransactionFail::CryptoImplementationUnavailable(expected);
            let error = if direct {
                Error::AcceptTransaction(failure)
            } else {
                Error::from(failure)
            };
            assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
            let error = error.classify_transaction_admission();
            let Error::TransactionAdmissionDeferred(original) = error else {
                panic!("unavailable implementation is unfinished local admission");
            };
            assert_eq!(
                original.reason(),
                ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(expected)
            );
            assert!(original.decode_refusal().is_none());
            assert!(original.allocation_refusal().is_none());
            let response = Error::TransactionAdmissionDeferred(original).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "1");
            assert!(response.headers().get("x-iroha-reject-code").is_none());
            assert!(
                response
                    .headers()
                    .get("x-iroha-transactions-accepted")
                    .is_none()
            );
        }
    }
}
