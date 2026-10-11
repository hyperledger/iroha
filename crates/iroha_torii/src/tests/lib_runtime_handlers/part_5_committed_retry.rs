// Exact committed-carrier acknowledgment through native signed history and fresh ingress.

fn committed_retry_fixture(
    live: bool,
    applied: bool,
) -> (
    SharedAppState,
    SignedTransaction,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    KeyPair,
) {
    use iroha_core::sumeragi::test_chain::TestChainConfig;
    let key = checked_torii_test_ed25519_keypair(0x29, "committed retry authority");
    let authority = AccountId::new(key.public_key().clone());
    let genesis_ms = if live {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
        .checked_sub(1)
        .unwrap()
    } else {
        1_000
    };
    let instruction = if applied {
        Log::new(Level::INFO, "committed retry".into()).into()
    } else {
        iroha_data_model::isi::Unregister::domain(
            DomainId::try_new("missing_retry_domain", "universal").unwrap(),
        )
        .into()
    };
    let (mut app, hash, chain) = executed_history_test_fixture(
        TestChainConfig::new(world_with_account(&authority), genesis_ms),
        &key,
        vec![instruction],
        applied,
    );
    Arc::get_mut(&mut app)
        .expect("unique committed retry fixture")
        .local_peer_id = Some(chain.validators()[0].0.clone());
    let original = chain.committed(2);
    let transaction = original
        .block()
        .network_entrypoints()
        .find_map(|entrypoint| match entrypoint {
            TransactionEntrypoint::External(transaction) if transaction.hash() == hash => {
                Some(transaction.clone())
            }
            _ => None,
        })
        .expect("original signed carrier");
    (app, transaction, chain, key)
}

#[tokio::test]
async fn committed_retry_acknowledges_exact_carrier_without_requeueing() {
    for applied in [true, false] {
        let (app, transaction, chain, _) = committed_retry_fixture(true, applied);
        let original = chain.committed(2).block().encode_wire().unwrap();
        let response =
            post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
                .await
                .expect("an exact committed retry acknowledges its original admission");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            torii_response_header(&response, "x-iroha-entrypoint-hash"),
            Some(transaction.hash().to_string().as_str())
        );
        let response = post_external_transaction_entrypoint_for_test(
            app.clone(),
            HeaderMap::new(),
            transaction.clone(),
        )
        .await
        .expect("entrypoint ingress shares exact committed retry authentication");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let wire = iroha_version::codec::EncodeVersioned::encode_versioned(&transaction);
        let response = super::handler_post_transactions_batch(
            State(app.clone()),
            HeaderMap::new(),
            transaction_batch_body_for_test(vec![wire.clone(), wire]),
        )
        .await
        .expect("batch ingress acknowledges both copies of the exact committed carrier");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            torii_response_header(&response, "x-iroha-transactions-accepted"),
            Some("2")
        );
        #[cfg(feature = "connect")]
        {
            let sender = chain.validators()[1].0.clone();
            let response = super::execute_incoming_torii_proxy_request(
                &app,
                ToriiProxyRequestV1 {
                    schema_version: TORII_PROXY_REQUEST_VERSION_V1,
                    request_id: Hash::new(b"exact committed retry at proxy receiver"),
                    deadline_unix_ms: super::torii_proxy_test_deadline_unix_ms(),
                    hop_count: 1,
                    max_hops: 3,
                    visited_peer_ids: vec![sender.clone()],
                    request: ToriiProxyRequestKindV1::SubmitTransaction {
                        transaction: TransactionEntrypoint::External(transaction.clone()),
                        expected_plan: ToriiRoutingPlanHintV1::from(RoutingPlan::single(
                            RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                        )),
                    },
                },
                Some(sender),
            )
            .await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }
        assert_eq!(app.queue.active_len(), 0);
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.committed(2).block().encode_wire().unwrap(), original);
    }
}

#[tokio::test]
async fn committed_retry_requires_full_carrier_including_authorization() {
    let (app, transaction, _chain, key) = committed_retry_fixture(true, true);
    let forged = transaction_with_invalid_signature_for_test(transaction.clone());
    assert_eq!(forged.hash(), transaction.hash());
    assert!(
        !super::ordinary_transaction_ingress::contains_exact_committed_input(
            &app.state,
            &TransactionEntrypoint::External(forged.clone()),
        )
        .unwrap(),
        "payload membership alone must never authenticate a substituted signature"
    );
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &forged)
        .await
        .expect_err("fresh authentication precedes committed retry lookup");
    assert!(matches!(
        error,
        Error::AcceptTransaction(AcceptTransactionFail::SignatureVerification(_))
    ));
    let fresh = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        "uncommitted distinct input",
        &key,
    );
    assert!(
        !super::ordinary_transaction_ingress::contains_exact_committed_input(
            &app.state,
            &TransactionEntrypoint::External(fresh),
        )
        .unwrap()
    );
    assert_eq!(app.queue.active_len(), 0);
}

#[tokio::test]
async fn committed_retry_fails_closed_when_original_history_is_unavailable() {
    let (app, transaction, _chain, _) = committed_retry_fixture(true, true);
    app.kura
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(2).unwrap())
        .unwrap();
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect_err("membership is insufficient without authentic original history");
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "transaction_replay_history_unavailable",
            ..
        }
    ));
    assert_eq!(app.queue.active_len(), 0);
}

#[tokio::test]
async fn committed_retry_preserves_original_history_capacity_refusal_and_retry() {
    let (app, transaction, _chain, _) = committed_retry_fixture(true, true);
    let budget = app.state.ivm_execution_budget();
    let limit = budget.limit_bytes();
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(baseline);
    let result = super::ordinary_transaction_ingress::contains_exact_committed_input(
        &app.state,
        &TransactionEntrypoint::External(transaction.clone()),
    );
    budget.set_limit_bytes(limit);
    assert!(
        matches!(
            result,
            Err(Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
            )))
        ),
        "local history pressure must remain retryable capacity: {result:?}"
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    assert!(
        super::ordinary_transaction_ingress::contains_exact_committed_input(
            &app.state,
            &TransactionEntrypoint::External(transaction)
        )
        .unwrap()
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(app.queue.active_len(), 0);
}

#[tokio::test]
async fn committed_retry_rejects_membership_rebound_to_another_genuine_block() {
    let (app, transaction, mut chain, _) = committed_retry_fixture(true, true);
    let anchor = canonical_transaction_anchor(&app.state, &transaction.hash())
        .unwrap()
        .unwrap();
    append_canonical_outcome_test_block(&mut chain, anchor, true);
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect_err("an independently valid block cannot replace the original carrier");
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "transaction_replay_history_unavailable",
            ..
        }
    ));
    assert_eq!(app.queue.active_len(), 0);
}

#[tokio::test]
async fn committed_retry_revalidates_expiry_and_current_signature_policy() {
    let (app, expired, _chain, _) = committed_retry_fixture(false, true);
    let response = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &expired)
        .await
        .map_or_else(IntoResponse::into_response, |response| response);
    assert_ne!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 0);

    let (app, transaction, _chain, _) = committed_retry_fixture(true, true);
    let mut crypto = app.state.crypto().as_ref().clone();
    crypto
        .allowed_signing
        .retain(|algorithm| *algorithm != Algorithm::Ed25519);
    app.state.set_crypto(crypto);
    let error = post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
        .await
        .expect_err("committed identity cannot bypass the current signing policy");
    let Error::AcceptTransaction(AcceptTransactionFail::SignatureVerification(error)) = error
    else {
        panic!("expected current signing-policy rejection");
    };
    assert_eq!(error.code(), SignatureRejectionCode::AlgorithmNotPermitted);
    assert_eq!(app.queue.active_len(), 0);
}

#[tokio::test]
async fn committed_retry_preserves_full_queue_and_authority_rate_reservation() {
    let (mut app, transaction, _chain, key) = committed_retry_fixture(true, true);
    install_single_slot_transaction_queue(&mut app);
    Arc::get_mut(&mut app).unwrap().tx_rate_limiter =
        limits::RateLimiter::new_without_refill_for_tests(std::num::NonZeroU32::new(1).unwrap());
    let authority = transaction.authority().clone();
    let pending = signed_log_transaction_for_test(
        *app.state.network_id_ref(),
        authority.clone(),
        "unrelated pending input retains its slot",
        &key,
    );
    let accepted = routing::accept_transaction_for_ingress(
        app.state.clone(),
        TransactionEntrypoint::External(pending.clone()),
        &app.telemetry,
    )
    .unwrap();
    routing::push_accepted_transaction_for_ingress_with_routing_plan(
        app.queue.clone(),
        app.state.clone(),
        accepted,
        None,
    )
    .unwrap();
    let original_pending = lifecycle_pending_wire(&app);
    for _ in 0..2 {
        let response =
            post_signed_transaction_for_test(app.clone(), HeaderMap::new(), &transaction)
                .await
                .expect("committed retry needs no fresh queue slot or authority quota");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(app.queue.active_len(), 1);
        assert_eq!(lifecycle_pending_wire(&app), original_pending);
        assert_native_pending_for_test(&app, &pending);
    }
    assert!(
        app.tx_rate_limiter
            .allow(&transaction_verified_authority_key(&authority))
            .await
    );
    assert!(
        !app.tx_rate_limiter
            .allow(&transaction_verified_authority_key(&authority))
            .await
    );
}

#[tokio::test]
async fn committed_retry_rechecks_route_after_history_authentication() {
    let (mut app, transaction, _chain, _) = committed_retry_fixture(true, true);
    let calls = install_counting_route_queue(
        &mut app,
        Some(RoutingDecision::new(LaneId::new(9), DataSpaceId::new(9))),
    );
    let accepted = routing::accept_transaction_for_ingress(
        app.state.clone(),
        TransactionEntrypoint::External(transaction),
        &app.telemetry,
    )
    .unwrap();
    let prepared = super::prepare_fresh_transaction_ingress(&app, accepted).unwrap();
    assert!(prepared.committed_replay);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let error =
        super::submit_prepared_transaction_ingress(&app, prepared, false, ResponseFormat::Json)
            .await
            .expect_err("a changed route cannot reuse the previous acknowledgment route");
    assert_ne!(error.into_response().status(), StatusCode::ACCEPTED);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(app.queue.active_len(), 0);
}
