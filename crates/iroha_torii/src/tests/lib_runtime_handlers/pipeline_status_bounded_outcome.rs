// G24: the public status route reads a committed outcome through bounded windows of its
// carrier, so neither the block's size nor the transaction's size can turn a committed
// transaction into permanent retryable backpressure.

fn bounded_status_chain() -> (
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
    KeyPair,
) {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let key = checked_torii_test_ed25519_keypair(0x47, "bounded status authority");
    let authority = AccountId::new(key.public_key().clone());
    let chain =
        CertifiedTestChain::start(TestChainConfig::new(world_with_account(&authority), 1_000))
            .unwrap();
    (chain, key)
}

/// A signed `Log` transaction whose canonical frame (the admission measure) is exactly
/// `frame_bytes`; `salt` keeps otherwise equal transactions distinct.
fn sized_log_transaction(
    chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
    key: &KeyPair,
    frame_bytes: usize,
    salt: u64,
) -> SignedTransaction {
    let sign = |length: usize| {
        let mut builder = TransactionBuilder::new(
            chain.network_id(),
            AccountId::new(key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1_001 + salt));
        builder
            .with_instructions([Log::new(Level::INFO, "x".repeat(length))])
            .sign(key.private_key())
    };
    let frame = |transaction: &SignedTransaction| {
        norito::encode_canonical(transaction)
            .expect("canonical transaction frame")
            .len()
    };
    // Both probes stay in one compact length band, so the frame is linear in the text.
    let initial = frame_bytes - (64 << 10);
    let measured = frame(&sign(initial));
    let transaction = sign(initial + (frame_bytes - measured));
    assert_eq!(frame(&transaction), frame_bytes, "byte-linear Log fixture");
    transaction
}

fn bounded_status_app(
    chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
    working_set: Option<usize>,
) -> SharedAppState {
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    if let Some(bytes) = working_set {
        unique.query_fanout_working_set_bytes = bytes;
    }
    app
}

/// The request working set whose cold-frame corridor is exactly `frames` bytes.
fn status_working_set_for_frames(frames: usize) -> usize {
    crate::query_fanout_fixed_overhead_bytes().unwrap() + crate::QUERY_FANOUT_PREBODY_UNITS * frames
}

async fn committed_status(
    app: &SharedAppState,
    transaction: &SignedTransaction,
    height: u64,
    kind: &str,
) {
    let response = pipeline_status_response(
        app.clone(),
        transaction.hash().to_string(),
        None,
        "bounded committed status",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload = torii_json_body(response).await;
    assert_eq!(payload["status"]["kind"].as_str(), Some(kind));
    assert_eq!(payload["status"]["block_height"].as_u64(), Some(height));
    assert_eq!(payload["resolved_from"].as_str(), Some("state"));
}

async fn applied_status(app: &SharedAppState, transaction: &SignedTransaction, height: u64) {
    committed_status(app, transaction, height, "Applied").await;
}

#[tokio::test]
async fn pipeline_status_reports_applied_for_blocks_above_the_retired_frame_threshold() {
    // X.2 measured the first refused Kura frame at 1,514,153 bytes (one 1,500,000-byte
    // transaction); five 400,000-byte transactions in one block were refused as well. The cap
    // is the default 10,485,760-byte transaction.
    let (mut chain, key) = bounded_status_chain();
    let single = sized_log_transaction(&chain, &key, 1_500_000, 0);
    assert_eq!(chain.commit_at(10_000, vec![single.clone()]), vec![true]);
    let batch: Vec<_> = (1..=5)
        .map(|salt| sized_log_transaction(&chain, &key, 400_000, salt))
        .collect();
    assert_eq!(chain.commit_at(20_000, batch.clone()), vec![true; 5]);
    let cap = sized_log_transaction(&chain, &key, 10_485_760, 6);
    // The capped transaction is admitted and committed; the status route reports exactly the
    // result its block carries, whether execution applied or rejected it.
    let cap_applied = chain.commit_at(30_000, vec![cap.clone()]);
    let cap_kind = {
        let committed = chain.committed(4);
        let (_, output) = committed
            .block()
            .network_output_at(0)
            .expect("the capped transaction's committed output");
        match output.result.as_ref() {
            Ok(_) => "Applied",
            Err(reason) => {
                println!("G24 capped 10,485,760-byte transaction committed as rejected: {reason}");
                "Rejected"
            }
        }
    };
    assert_eq!(cap_applied, vec![cap_kind == "Applied"]);
    let frames: Vec<usize> = (2..=4)
        .map(|height| chain.committed(height).block().encode_wire().unwrap().len())
        .collect();
    // Every frame is larger than the largest one X.2 saw answered (1,364,153 bytes).
    assert!(frames.iter().all(|frame| *frame > 1_364_153), "{frames:?}");
    let app = bounded_status_app(&chain, None);
    for (transactions, height) in [(vec![single.clone()], 2), (batch, 3)] {
        for transaction in &transactions {
            applied_status(&app, transaction, height).await;
        }
    }
    committed_status(&app, &cap, 4, cap_kind).await;
    // The complete carrier, which genesis alone still uses, is refused for these blocks in the
    // same request geometry (the retired status path); the bounded read above answered them.
    for transaction in [&single, &cap] {
        let anchor = canonical_transaction_anchor(&app.state, &transaction.hash())
            .unwrap()
            .unwrap();
        let owner =
            crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
        let refused = owner.scope(|| read_pipeline_transaction_carrier(&app, anchor));
        println!(
            "G24 whole-carrier status read at height {}: {:?}",
            anchor.height,
            refused.as_ref().map(|_| "answered")
        );
        assert!(
            refused.is_err(),
            "the retired whole-carrier read must not fit"
        );
    }
    // The capped frame alone is larger than the request's frame pool: a permanent refusal.
    let anchor = canonical_transaction_anchor(&app.state, &cap.hash())
        .unwrap()
        .unwrap();
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames().limit_bytes();
    let wire = chain.committed(4).block().encode_wire().unwrap().len();
    match owner.scope(|| read_pipeline_transaction_carrier(&app, anchor)) {
        Err(Error::HistoryReadExceedsBudget {
            resource,
            required,
            limit,
        }) => assert_eq!(
            (resource, required, limit),
            (
                "bytes",
                u64::try_from(wire).unwrap(),
                u64::try_from(frames).unwrap()
            )
        ),
        Err(other) => panic!("the capped frame can never fit the request's frame pool: {other:?}"),
        Ok(_) => panic!("the capped frame cannot be held whole by the request's frame pool"),
    }
}

#[tokio::test]
async fn pipeline_status_old_whole_carrier_threshold_binding_term() {
    // Root-cause evidence for G24: run the retired whole-carrier status read in the default
    // request geometry and report which finite term refuses it. Printed with --nocapture.
    let (mut chain, key) = bounded_status_chain();
    let sizes = [1_000_000_usize, 1_350_000, 1_500_000, 2_000_000];
    let transactions: Vec<_> = sizes
        .iter()
        .enumerate()
        .map(|(salt, size)| {
            sized_log_transaction(&chain, &key, *size, u64::try_from(salt).unwrap())
        })
        .collect();
    for (index, transaction) in transactions.iter().enumerate() {
        let at = 10_000 * (u64::try_from(index).unwrap() + 1);
        assert_eq!(chain.commit_at(at, vec![transaction.clone()]), vec![true]);
    }
    let app = bounded_status_app(&chain, None);
    let work = routing::app_query_limits().max_fetch_size;
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    let mut refused = Vec::new();
    for (size, transaction) in sizes.iter().zip(&transactions) {
        let anchor = canonical_transaction_anchor(&app.state, &transaction.hash())
            .unwrap()
            .unwrap();
        let wire = chain
            .committed(u64::try_from(anchor.height.get()).unwrap())
            .block()
            .encode_wire()
            .unwrap()
            .len();
        let owner =
            crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
        let budget = owner.canonical_history_budget();
        let result = owner.scope(|| {
            app.state
                .read_executed_carrier_from_checkpoints(anchor.height, work, bytes, &budget)
        });
        let consumed = owner.allocation_context().consumed_allocated_bytes();
        match result {
            Ok(_) => println!(
                "G24 old status read: tx {size} frame {wire}: ok, cumulative decoder bytes {consumed}, frame pool {}",
                owner.cold_frames().limit_bytes()
            ),
            Err(iroha_core::execution_attempt::ExecutionAttemptError::Deferred(deferred)) => {
                println!(
                    "G24 old status read: tx {size} frame {wire}: refused, allocation {:?}, decoder {:?}, cumulative decoder bytes {consumed}, frame pool {}, permanent {:?}",
                    deferred.allocation_refusal(),
                    deferred
                        .decode_refusal()
                        .map(norito::core::DecodeLocalRefusal::resource_error),
                    owner.cold_frames().limit_bytes(),
                    crate::canonical_history::permanent_refusal(&deferred),
                );
                assert!(
                    crate::canonical_history::permanent_refusal(&deferred).is_some(),
                    "the old refusal depends only on this request's own budget"
                );
                refused.push(*size);
            }
            Err(other) => panic!("unexpected completed rejection: {other:?}"),
        }
        // The bounded read answers every size in the same geometry.
        applied_status(
            &app,
            transaction,
            u64::try_from(anchor.height.get()).unwrap(),
        )
        .await;
    }
    assert!(!refused.contains(&1_000_000), "{refused:?}");
    assert!(refused.contains(&1_500_000), "{refused:?}");
}

#[tokio::test]
async fn pipeline_status_item_above_the_request_frame_pool_is_a_typed_permanent_refusal() {
    let (mut chain, key) = bounded_status_chain();
    let transaction = sized_log_transaction(&chain, &key, 1_500_000, 0);
    assert_eq!(
        chain.commit_at(10_000, vec![transaction.clone()]),
        vec![true]
    );
    // The certificate is the largest window of this bounded read; one byte less of frame pool
    // than its canonical payload can never hold it, whatever other requests are doing.
    let certificate = chain
        .committed(2)
        .block()
        .commit_certificate()
        .cloned()
        .expect("committed certificate");
    let certificate_bytes = norito::codec::encode_adaptive(&certificate).len();
    let app = bounded_status_app(
        &chain,
        Some(status_working_set_for_frames(certificate_bytes - 1)),
    );
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    assert_eq!(owner.cold_frames().limit_bytes(), certificate_bytes - 1);
    drop(owner);
    let result = super::handler_pipeline_transaction_status(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(transaction.hash().to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await;
    let Err(error) = result else {
        panic!("a window above the request's own frame pool must be refused");
    };
    let Error::HistoryReadExceedsBudget {
        resource,
        required,
        limit,
    } = &error
    else {
        panic!("permanent refusal must be typed, not retryable capacity: {error:?}");
    };
    assert_eq!(
        (*resource, *required, *limit),
        (
            "bytes",
            u64::try_from(certificate_bytes).unwrap(),
            u64::try_from(certificate_bytes - 1).unwrap()
        )
    );
    // The JSON client's response: 413, no Retry-After, both byte counts in the typed details.
    let response = crate::utils::with_current_response_format(
        crate::utils::ResponseFormat::Json,
        async move { error.into_response() },
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none()
    );
    let payload = torii_json_body(response).await;
    assert_eq!(
        payload["code"].as_str(),
        Some("history_read_exceeds_request_budget")
    );
    assert_eq!(payload["details"]["field"].as_str(), Some("bytes"));
    assert_eq!(
        payload["details"]["actual"].as_str(),
        Some(certificate_bytes.to_string().as_str())
    );
    assert_eq!(
        payload["details"]["expected"].as_str(),
        Some(format!("at most {} bytes", certificate_bytes - 1).as_str())
    );
    assert!(payload["details"]["retry_after_seconds"].is_null());
    // Exactly at the certificate's size the frame pool holds that window: the read answers, or
    // stops only at a different term of the same request budget (never at its frame bytes).
    let exact = bounded_status_app(
        &chain,
        Some(status_working_set_for_frames(certificate_bytes)),
    );
    match super::handler_pipeline_transaction_status(
        State(exact.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        Some(crate::utils::extractors::ExtractAccept(
            HeaderValue::from_static("application/json"),
        )),
        crate::NoritoStringQuery(PipelineStatusQuery {
            hash: Some(transaction.hash().to_string()),
            scope: Some("local".to_owned()),
        }),
    )
    .await
    {
        Ok(response) => {
            println!("G24 frame pool exactly {certificate_bytes} bytes: answered");
            assert_eq!(response.status(), StatusCode::OK);
            let payload = torii_json_body(response).await;
            assert_eq!(payload["status"]["kind"].as_str(), Some("Applied"));
        }
        Err(Error::HistoryReadExceedsBudget {
            resource,
            required,
            limit,
        }) => {
            println!(
                "G24 frame pool exactly {certificate_bytes} bytes: stops at {required} {resource} > {limit}"
            );
            assert_ne!(resource, "bytes", "the exact frame pool holds every window");
        }
        Err(other) => panic!("unexpected refusal at the exact frame pool: {other:?}"),
    }
    // The same deterministic read in the default request geometry answers the outcome.
    applied_status(&bounded_status_app(&chain, None), &transaction, 2).await;
}

#[test]
fn history_read_refusals_separate_permanent_items_from_transient_capacity() {
    use iroha_core::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
    let pool = iroha_core::state::AllocationBudget::new(8);
    // A demand above the whole pool can never fit: permanent, typed, with both byte counts.
    let exceeds = pool.try_reserve_bytes(9).unwrap_err();
    let deferred: ExecutionDeferred = exceeds.into();
    assert_eq!(
        crate::canonical_history::permanent_refusal(&deferred),
        Some(("bytes", 9, 8))
    );
    let error =
        crate::canonical_history::query_attempt_error(ExecutionAttemptError::Deferred(deferred));
    assert!(matches!(
        error,
        Error::HistoryReadExceedsBudget {
            resource: "bytes",
            required: 9,
            limit: 8
        }
    ));
    assert_eq!(
        error.into_response().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // A pool that other owners occupy is transient: retryable capacity, as before.
    let held = pool.try_reserve_bytes(8).unwrap();
    let busy: ExecutionDeferred = pool.try_reserve_bytes(1).unwrap_err().into();
    assert_eq!(crate::canonical_history::permanent_refusal(&busy), None);
    assert!(matches!(
        crate::canonical_history::query_attempt_error(ExecutionAttemptError::Deferred(busy)),
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ));
    drop(held);
    // A decoder limit of the request's own budget that this read exceeds is permanent too.
    let (mut chain, key) = bounded_status_chain();
    let transaction = sized_log_transaction(&chain, &key, 100_000, 0);
    assert_eq!(
        chain.commit_at(10_000, vec![transaction.clone()]),
        vec![true]
    );
    let tight = iroha_core::state::CanonicalHistoryReadBudget::new(
        iroha_core::state::AllocationBudget::new(1 << 20),
        norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            1 << 20,
            1 << 20,
            1 << 20,
            64,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        )),
    );
    let refused = chain.state().read_committed_network_outcome(
        std::num::NonZeroUsize::new(2).unwrap(),
        &transaction.hash_as_entrypoint(),
        routing::app_query_limits().max_fetch_size,
        1 << 30,
        &tight,
    );
    let deferred = match refused {
        Err(ExecutionAttemptError::Deferred(deferred)) => deferred,
        other => panic!("a cumulative decoder limit is a local refusal: {other:?}"),
    };
    let Some(("decoded bytes", attempted, 64)) =
        crate::canonical_history::permanent_refusal(&deferred)
    else {
        panic!("{deferred:?}");
    };
    assert!(attempted > 64);
}
