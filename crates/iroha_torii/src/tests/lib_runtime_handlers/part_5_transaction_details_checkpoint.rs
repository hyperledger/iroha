// Native checkpoint receipt controls for the signed transaction-details route.

#[tokio::test]
async fn transaction_details_http_reads_past_fetch_budget_and_retains_response_owner() {
    use http_body_util::BodyExt as _;
    use iroha_core::execution_attempt::ExecutionAttemptError;
    use iroha_data_model::query::error::QueryExecutionFail;
    use tower::ServiceExt as _;

    let sender_key = checked_torii_test_ed25519_keypair(0x24, "checkpoint receipt sender");
    let authority = AccountId::new(sender_key.public_key().clone());
    let (app, _, mut chain) = canonical_outcome_test_fixture(false);
    let work = routing::app_query_limits().max_fetch_size;
    assert_eq!(
        work, 500,
        "exercise the shipped default without changing global limits"
    );
    while chain.height() < work {
        chain.commit(Vec::new());
    }
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(1_001));
    let transaction = builder
        .with_instructions([Log::new(
            Level::INFO,
            "receipt beyond full-prefix budget".into(),
        )])
        .sign(sender_key.private_key());
    let signed_hash = transaction.hash();
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(signed_hash);
    assert_eq!(chain.commit(vec![transaction]), vec![true]);
    let height = NonZeroUsize::new(usize::try_from(chain.height()).unwrap()).unwrap();
    assert_eq!(height.get(), 501);
    let original = chain.committed(501);
    let original_result = original
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .clone();
    // The HTTP read authenticates 501 backwards from the executed tip (502) or a node-local
    // checkpoint, never from genesis.
    chain.commit(Vec::new());
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    assert!(
        matches!(
            app.state
                .read_finalized_execution_carrier(height, work, bytes),
            Err(ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ),
        "the consensus reader must retain deterministic full-prefix work accounting"
    );
    let router = axum::Router::new()
        .route(
            route_catalog::pipeline::TRANSACTION_DETAILS.path(),
            axum::routing::post(super::handler_pipeline_transaction_details),
        )
        .with_state(app.clone());
    let mut original_response = None;
    for (attempt, content_type) in [
        crate::utils::NORITO_MIME_TYPE,
        crate::utils::NORITO_MIME_TYPE,
        crate::utils::JSON_MIME_TYPE,
    ]
    .into_iter()
    .enumerate()
    {
        if attempt == 1 {
            app.kura.forget_cached_block_for_testing(height).unwrap();
        }
        let available = app.query_fanout_inflight.available_bytes();
        let signed = signed_transaction_details_query(&app, &sender_key, entrypoint_hash);
        let request = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(route_catalog::pipeline::TRANSACTION_DETAILS.path())
            .header(
                axum::http::header::CONTENT_TYPE,
                crate::utils::NORITO_MIME_TYPE,
            )
            .header(axum::http::header::ACCEPT, content_type)
            .extension(crate::loopback_connect_info())
            .body(Body::from(
                iroha_version::codec::EncodeVersioned::encode_versioned(&signed),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            content_type
        );
        let (parts, mut body) = response.into_parts();
        drop(parts);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(body.frame().await.is_none());
        let retained = bytes.clone();
        let slice = bytes.slice(..);
        drop(body);
        let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
            if content_type == crate::utils::NORITO_MIME_TYPE {
                norito::decode_canonical_with_limits(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
                .unwrap()
            } else {
                norito::json::from_slice(&bytes).unwrap()
            };
        assert_eq!(details.transaction.entrypoint_hash(), &entrypoint_hash);
        assert_eq!(details.transaction.result(), &original_result);
        let wire = norito::to_bytes(&details).unwrap();
        if let Some(expected) = &original_response {
            assert_eq!(
                &wire, expected,
                "cold and JSON reads preserve the exact native receipt"
            );
        } else {
            original_response = Some(wire);
        }
        drop(bytes);
        assert!(app.query_fanout_inflight.available_bytes() < available);
        drop(retained);
        assert!(app.query_fanout_inflight.available_bytes() < available);
        drop(slice);
        assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    }
}

#[tokio::test]
async fn transaction_details_checkpoint_reader_refuses_a_foreign_query_owner() {
    let (app, hash, _chain) = canonical_outcome_test_fixture(false);
    let entrypoint = iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash);
    let foreign = crate::history_producer::HistoryProducerOwner::for_test();
    let observed = foreign.scope(|| {
        canonical_transaction_details_for_indexed_identity(
            &app,
            NonZeroUsize::new(2).unwrap(),
            &entrypoint,
        )
    });
    assert!(matches!(
        observed,
        Err(Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
}
