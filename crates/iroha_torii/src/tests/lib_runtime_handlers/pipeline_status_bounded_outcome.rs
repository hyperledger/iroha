// G24: the public status route reads a committed outcome through bounded windows of its
// carrier without decoding transaction bodies. These controls cover the recorded frame
// shapes; the request's separate work, byte and decoder allowances still apply.

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

/// Apply the canonical HTTP error boundary, including its matching retry header and hint.
fn history_read_error_response(error: Error) -> axum::response::Response {
    let (parts, _) = error.status_code().into_response().into_parts();
    crate::canonical_error_response(
        parts,
        error.into_envelope(),
        crate::utils::ResponseFormat::Json,
        false,
    )
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
    let iroha_data_model::transaction::Executable::Instructions(instructions) = cap.instructions()
    else {
        panic!("the byte-boundary fixture must contain native instructions");
    };
    let log = instructions[0].as_any().downcast_ref::<Log>().unwrap();
    let expected_reason =
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(format!(
                "block gas limit exceeded: {} > 4000000",
                8 + u64::try_from(log.msg.len()).unwrap()
            )),
        );
    // Log costs eight gas plus its message length. The default four-million-gas
    // block policy rejects this admitted byte-boundary transaction; any other
    // rejection is a regression, not interchangeable evidence of status recovery.
    let cap_applied = chain.commit_at(30_000, vec![cap.clone()]);
    assert_eq!(cap_applied, vec![false]);
    {
        let committed = chain.committed(4);
        let (_, output) = committed
            .block()
            .network_output_at(0)
            .expect("the capped transaction's committed output");
        match output.result.as_ref() {
            Ok(_) => panic!("the capped Log must exceed the default block gas allowance"),
            Err(reason) => {
                assert_eq!(reason, &expected_reason);
                println!("G24 capped transaction's exact rejection: {reason:?}");
            }
        }
    }
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
    committed_status(&app, &cap, 4, "Rejected").await;
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
    // Preserve the retired whole-carrier read's exact refusal evidence. Its generic reader
    // does not classify target versus ancestry, so that error alone cannot prove permanence.
    let anchor = canonical_transaction_anchor(&app.state, &cap.hash())
        .unwrap()
        .unwrap();
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames().limit_bytes();
    let wire = chain.committed(4).block().encode_wire().unwrap().len();
    let work = routing::app_query_limits().max_fetch_size;
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    let budget = owner.canonical_history_budget();
    match owner.scope(|| {
        app.state
            .read_executed_carrier_from_checkpoints(anchor.height, work, bytes, &budget)
    }) {
        Err(iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original)) => {
            assert!(matches!(
                original.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::ExceedsLimit {
                    requested_bytes,
                    limit_bytes,
                }) if *requested_bytes == wire && *limit_bytes == frames
            ));
            assert_eq!(original.phase(), None);
            assert_eq!(crate::canonical_history::permanent_refusal(&original), None);
            let response =
                history_read_error_response(crate::canonical_history::query_attempt_error(
                    iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original),
                ));
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
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
                assert_eq!(deferred.phase(), None);
                assert_eq!(
                    crate::canonical_history::permanent_refusal(&deferred),
                    None,
                    "an unclassified whole-carrier refusal does not prove a required target item"
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
    let response = history_read_error_response(error);
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
    // The original item cannot fit, but without its source provenance it could be ancestry
    // that a closer authenticated checkpoint omits. Preserve the cause and allow retry.
    let exceeds = pool.try_reserve_bytes(9).unwrap_err();
    let deferred: ExecutionDeferred = exceeds.into();
    assert_eq!(crate::canonical_history::permanent_refusal(&deferred), None);
    assert!(matches!(
        deferred.allocation_refusal(),
        Some(iroha_allocation::AllocationRefusal::ExceedsLimit {
            requested_bytes: 9,
            limit_bytes: 8,
        })
    ));
    let error =
        crate::canonical_history::query_attempt_error(ExecutionAttemptError::Deferred(deferred));
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ));
    let response = history_read_error_response(error);
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .contains_key(axum::http::header::RETRY_AFTER)
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
    // Cumulative decoder exhaustion does not prove the same query can never fit:
    // authenticated checkpoints can shorten the next attempt's ancestry.
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
        Err(iroha_core::state::CommittedOutcomeReadError::Execution(
            ExecutionAttemptError::Deferred(deferred),
        )) => deferred,
        other => panic!("a cumulative decoder limit is a local refusal: {other:?}"),
    };
    assert!(matches!(
        deferred
            .decode_refusal()
            .map(norito::core::DecodeLocalRefusal::resource_error),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: 64,
        }) if attempted > 64
    ));
    assert_eq!(crate::canonical_history::permanent_refusal(&deferred), None);
    let response = history_read_error_response(crate::canonical_history::query_attempt_error(
        ExecutionAttemptError::Deferred(deferred),
    ));
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .contains_key(axum::http::header::RETRY_AFTER)
    );
}

#[tokio::test]
async fn pipeline_status_same_certificate_refusal_is_retryable_only_as_ancestry() {
    let (mut chain, key) = bounded_status_chain();
    let ancestor_target = sized_log_transaction(&chain, &key, 100_000, 0);
    assert_eq!(
        chain.commit_at(10_000, vec![ancestor_target.clone()]),
        vec![true]
    );
    let tip_target = sized_log_transaction(&chain, &key, 100_000, 1);
    assert_eq!(
        chain.commit_at(20_000, vec![tip_target.clone()]),
        vec![true]
    );
    let certificate_bytes =
        norito::codec::encode_adaptive(chain.committed(3).block().commit_certificate().unwrap())
            .len();
    let app = bounded_status_app(
        &chain,
        Some(status_working_set_for_frames(certificate_bytes - 1)),
    );
    // H3 proposal assembly authenticates its parent and can warm H2's checkpoint.
    // Clear only this optional cache before each request so both encounter the same
    // original H3 certificate and frame allowance; only its role in the request differs.
    for (transaction, target_height) in [(&ancestor_target, 2), (&tip_target, 3)] {
        chain.kura().clear_history_checkpoints_for_testing();
        let anchor = canonical_transaction_anchor(&app.state, &transaction.hash())
            .unwrap()
            .unwrap();
        assert_eq!(anchor.height.get(), target_height);
        let error = match read_pipeline_transaction_outcome(&app, &transaction.hash(), anchor) {
            Err(error) => error,
            Ok(_) => panic!("the original H3 certificate must exceed its window allowance"),
        };
        if target_height == 3 {
            assert!(
                matches!(
                    &error,
                    Error::HistoryReadExceedsBudget {
                        resource: "bytes",
                        required,
                        limit,
                    } if *required == u64::try_from(certificate_bytes).unwrap()
                        && *limit == u64::try_from(certificate_bytes - 1).unwrap()
                ),
                "target refusal: {error:?}; certificate_bytes={certificate_bytes}"
            );
        } else {
            assert!(
                matches!(
                    &error,
                    Error::Query(ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
                    ))
                ),
                "ancestry refusal: {error:?}; certificate_bytes={certificate_bytes}"
            );
        }
        let response = history_read_error_response(error);
        if target_height == 2 {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let retry = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .expect("the canonical HTTP boundary must retain the retry contract")
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let payload = torii_json_body(response).await;
            assert_eq!(
                payload["details"]["retry_after_seconds"].as_u64(),
                Some(retry)
            );
        } else {
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert!(
                !response
                    .headers()
                    .contains_key(axum::http::header::RETRY_AFTER)
            );
            let payload = torii_json_body(response).await;
            assert_eq!(
                payload["code"].as_str(),
                Some("history_read_exceeds_request_budget")
            );
            assert!(payload["details"]["retry_after_seconds"].is_null());
        }
    }
}
#[tokio::test]
async fn transaction_details_full_carrier_respects_explicit_query_memory() {
    // Details returns the full transaction, unlike bounded status projection. A larger
    // caller-owned source corridor is legitimate, but a retry cannot widen the default.
    let (mut chain, key) = bounded_status_chain();
    let transaction = sized_log_transaction(&chain, &key, 3 * 1024 * 1024, 0);
    assert_eq!(
        chain.commit_at(10_000, vec![transaction.clone()]),
        vec![true]
    );
    let height = NonZeroUsize::new(2).unwrap();
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let authority = AccountId::new(key.public_key().clone());
    let original = chain.committed(2);
    let original_wire = original.block().encode_wire().unwrap();
    let original_output = &original.block().network_output_at(0).unwrap().1.result;
    let app = bounded_status_app(&chain, None);
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let frames = owner.cold_frames().limit_bytes();
    assert!(original_wire.len() > frames);
    let work = routing::app_query_limits().max_fetch_size;
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    let budget = owner.canonical_history_budget();
    match owner.scope(|| {
        app.state
            .read_executed_carrier_from_checkpoints(height, work, bytes, &budget)
    }) {
        Err(iroha_core::execution_attempt::ExecutionAttemptError::Deferred(refusal)) => {
            assert!(matches!(
                refusal.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::ExceedsLimit {
                    requested_bytes,
                    limit_bytes,
                }) if *requested_bytes == original_wire.len() && *limit_bytes == frames
            ));
            assert_eq!(refusal.phase(), None);
            assert_eq!(crate::canonical_history::permanent_refusal(&refusal), None);
        }
        Err(other) => panic!("expected the exact full-frame allocation refusal: {other:?}"),
        Ok(_) => panic!("a full carrier cannot fit the default cold-frame corridor"),
    }
    drop(owner);
    let refused = pipeline_transaction_details_response(&app, &authority, entrypoint_hash)
        .expect_err("full details cannot fit the unchanged default owner");
    assert!(matches!(
        &refused,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        ))
    ));
    let refusal = history_read_error_response(refused);
    assert_eq!(refusal.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = refusal
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let refusal_bytes = torii_body_bytes(refusal, "full-details capacity refusal").await;
    let envelope: iroha_torii_shared::ErrorEnvelope =
        norito::json::from_slice(&refusal_bytes).unwrap();
    assert_eq!(envelope.code(), "query_validation_failed");
    assert_eq!(
        envelope.details.as_ref().unwrap().retry_after_seconds,
        Some(retry_after)
    );
    assert_eq!(original.block().encode_wire().unwrap(), original_wire);
    assert_eq!(
        app.state.committed_entrypoint_height(&entrypoint_hash),
        Some(height),
        "read capacity must not become transaction absence"
    );

    // This finite source phase fits the 3 MiB control inside the default aggregate
    // pool. The exact-cap control below separately accounts for response encoding.
    let funded = bounded_status_app(
        &chain,
        Some(status_working_set_for_frames(16 * 1024 * 1024)),
    );
    let owner =
        crate::history_producer::HistoryProducerOwner::authentication_read(&funded).unwrap();
    assert_eq!(owner.cold_frames().limit_bytes(), 16 * 1024 * 1024);
    let response = pipeline_transaction_details_http_response(
        &funded,
        &authority,
        entrypoint_hash,
        crate::utils::ResponseFormat::Norito,
        &owner,
    )
    .expect("the explicitly funded details read");
    assert_eq!(response.status(), StatusCode::OK);
    let response_bytes = torii_body_bytes(response, "funded full transaction details").await;
    let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
        norito::decode_canonical(&response_bytes).unwrap();
    assert_eq!(details.transaction.entrypoint_hash(), &entrypoint_hash);
    assert_eq!(details.transaction.entrypoint().hash(), entrypoint_hash);
    assert_eq!(details.transaction.block_hash(), &original.block().hash());
    assert_eq!(details.transaction.result(), original_output);
    assert_eq!(
        details.transaction.output_hash(),
        &HashOf::new(details.transaction.output())
    );
    assert_eq!(original.block().encode_wire().unwrap(), original_wire);
}

#[tokio::test]
async fn transaction_details_exact_cap_funds_the_complete_response() {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::parameter::{CustomParameter, Parameter};

    const TRANSACTION_BYTES: usize = 10_485_760;
    let key = checked_torii_test_ed25519_keypair(0x47, "exact-cap details authority");
    let authority = AccountId::new(key.public_key().clone());
    let mut config = TestChainConfig::new(world_with_account(&authority), 1_000);
    // The original signed genesis admits this synthetic Log's actual gas cost.
    config
        .genesis_parameters
        .push(Parameter::Custom(CustomParameter::new(
            "ivm_gas_limit_per_block".parse().unwrap(),
            iroha_primitives::json::Json::new(TRANSACTION_BYTES as u64 + 1_024),
        )));
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let transaction = sized_log_transaction(&chain, &key, TRANSACTION_BYTES, 0);
    assert_eq!(
        chain.commit_at(10_000, vec![transaction.clone()]),
        vec![true]
    );
    let height = NonZeroUsize::new(2).unwrap();
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let original = chain.committed(2);
    let original_wire = original.block().encode_wire().unwrap();
    let original_output = &original.block().network_output_at(0).unwrap().1.result;
    let work = routing::app_query_limits().max_fetch_size;
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);

    // Both phases fund the exact cold carrier and projection. The 20 MiB phase
    // still cannot fund response encoding; 24 MiB completes the original owner.
    for (phase_mib, complete) in [(20_usize, false), (24, true)] {
        let phase_bytes = phase_mib * 1024 * 1024;
        let working_set = status_working_set_for_frames(phase_bytes);
        let mut app = bounded_status_app(&chain, Some(working_set));
        Arc::get_mut(&mut app).unwrap().query_fanout_inflight =
            ByteWeightedMemoryPool::new(working_set).unwrap();
        {
            chain.kura().clear_history_checkpoints_for_testing();
            let owner =
                crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
            assert_eq!(owner.cold_frames().limit_bytes(), phase_bytes);
            assert!(original_wire.len() < phase_bytes);
            let budget = owner.canonical_history_budget();
            let carrier = owner
                .scope(|| {
                    app.state
                        .read_executed_carrier_from_checkpoints(height, work, bytes, &budget)
                })
                .expect("the original owner funds the complete cold carrier");
            let projected = owner
                .scope(|| carrier.transaction_at(0, bytes))
                .expect("the same original owner funds the selected transaction");
            assert_eq!(projected.entrypoint_hash(), &entrypoint_hash);
            assert_eq!(projected.block_hash(), &original.block().hash());
            assert_eq!(projected.result(), original_output);
        }

        // A fresh original HTTP owner must pay acquisition, authorization,
        // projection and encoding together; the diagnostic read above grants no credit.
        chain.kura().clear_history_checkpoints_for_testing();
        let owner =
            crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
        let response = pipeline_transaction_details_http_response(
            &app,
            &authority,
            entrypoint_hash,
            crate::utils::ResponseFormat::Norito,
            &owner,
        );
        if complete {
            let response =
                response.expect("24 MiB funds the complete transaction-details response");
            assert_eq!(response.status(), StatusCode::OK);
            let response_bytes =
                torii_body_bytes(response, "exact-cap complete transaction details").await;
            let details: iroha_torii_shared::PipelineTransactionDetailsResponse =
                norito::decode_canonical(&response_bytes).unwrap();
            assert_eq!(details.transaction.entrypoint_hash(), &entrypoint_hash);
            assert_eq!(details.transaction.entrypoint().hash(), entrypoint_hash);
            assert_eq!(details.transaction.block_hash(), &original.block().hash());
            assert_eq!(details.transaction.result(), original_output);
            assert_eq!(
                details.transaction.output_hash(),
                &HashOf::new(details.transaction.output())
            );
        } else {
            let error = response.expect_err("20 MiB cannot fund the complete encoded response");
            assert!(matches!(
                &error,
                Error::Query(ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
                ))
            ));
            let response = history_read_error_response(error);
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let retry_after: u64 = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let response_bytes =
                torii_body_bytes(response, "exact-cap response-encoding refusal").await;
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&response_bytes).unwrap();
            assert_eq!(envelope.code(), "query_validation_failed");
            assert_eq!(
                envelope.details.as_ref().unwrap().retry_after_seconds,
                Some(retry_after)
            );
        }
        assert_eq!(original.block().encode_wire().unwrap(), original_wire);
        assert_eq!(
            app.state.committed_entrypoint_height(&entrypoint_hash),
            Some(height),
            "response capacity must not become committed transaction absence"
        );
    }
}

#[tokio::test]
async fn pipeline_status_target_output_work_excess_is_permanent_under_default_policy() {
    use iroha_core::{
        state::{World, WorldReadOnly},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        block::execution_output::ExecutionOutputV1,
        events::time::{ExecutionTime, Schedule, TimeEventFilter},
        isi::{InstructionBox, Register},
        parameter::{
            execution_output::ExecutionOutputPolicyV1, fastpq_source::FastpqSourcePolicyV1,
        },
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };

    let mut config = TestChainConfig::new(World::new(), 1_000);
    let key = config.genesis_key.clone();
    let authority = AccountId::new(key.public_key().clone());
    for index in 0..500 {
        let trigger = Trigger::new(
            format!("g24_work_{index:04}").parse().unwrap(),
            Action::new(
                vec![InstructionBox::from(Log::new(
                    Level::DEBUG,
                    "time work".into(),
                ))],
                Repeats::Exactly(1),
                authority.clone(),
                TimeEventFilter::new(ExecutionTime::Schedule(Schedule::starting_at(
                    Duration::from_millis(10_000),
                ))),
            )
            .unwrap(),
        );
        config
            .genesis_instructions
            .push(Register::trigger(trigger).into());
    }
    assert!(
        config.genesis_parameters.is_empty(),
        "no policy enlargement"
    );
    let mut chain = CertifiedTestChain::start(config)
        .expect("500 genuine scheduled registrations must fit unchanged genesis admission");
    let assert_default_policy = || {
        let view = chain.state().view();
        let parameters = view.world().parameters();
        let block = parameters.block();
        assert_eq!(
            block.execution_output(),
            ExecutionOutputPolicyV1::bootstrap()
        );
        assert_eq!(block.fastpq_source(), FastpqSourcePolicyV1::bootstrap());
        assert_eq!(block.max_time_trigger_invocations().get(), 512);
        assert_eq!(
            block
                .fastpq_source()
                .maximum_network_inputs(block.execution_output())
                .unwrap(),
            11,
        );
    };
    assert_default_policy();
    let transaction = chain.sign(
        &key,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "real Network work".into(),
        ))],
        19_999,
    );
    assert_eq!(
        chain.commit_at(20_000, vec![transaction.clone()]),
        vec![true]
    );
    let height = NonZeroUsize::new(2).unwrap();
    let original = chain.committed(2);
    let rows = original.block().execution_outputs();
    let time_rows = rows
        .iter()
        .filter(|row| matches!(row, ExecutionOutputV1::Time(_)))
        .count();
    assert_eq!(
        time_rows, 500,
        "the real schedule must execute, not fabricated rows"
    );
    let inputs = original.block().network_entrypoint_count();
    assert!((1..=11).contains(&inputs));
    assert_eq!(rows.len(), inputs + time_rows);
    assert!(rows.len() > 500);
    let required_work = u64::try_from(rows.len()).unwrap() + 1;
    let original_wire = original.block().encode_wire().unwrap();
    let original_hash = original.block().hash();
    let original_height = chain.state().view().height();
    let identity = transaction.hash_as_entrypoint();
    let app = bounded_status_app(&chain, None);
    let work = routing::app_query_limits().max_fetch_size;
    assert_eq!(
        work, 500,
        "exercise the unmodified default route work allowance"
    );
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    eprintln!(
        "G24 work fixture: Network={inputs}, Time={time_rows}, outputs={}, required_work={required_work}, route_work={work}, wire_bytes={}",
        rows.len(),
        original_wire.len()
    );

    // The same real target and default request-memory owner succeed with only the
    // explicit Core work argument large enough for one frame plus all output rows.
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
    let positive = owner
        .scope(|| {
            let budget = owner.canonical_history_budget();
            app.state.read_committed_network_outcome(
                height,
                &identity,
                required_work,
                bytes,
                &budget,
            )
        })
        .expect("the complete actual output set fits O+1 work and unchanged memory/byte budgets");
    assert!(matches!(positive.matched_results(), [Ok(())]));
    drop(owner);

    for _ in 0..2 {
        let anchor = canonical_transaction_anchor(&app.state, &transaction.hash())
            .unwrap()
            .unwrap();
        let error = match read_pipeline_transaction_outcome(&app, &transaction.hash(), anchor) {
            Err(error) => error,
            Ok(_) => panic!("the default route must retain the target-work refusal"),
        };
        let response = history_read_error_response(error);
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "intrinsic certified target work must be permanent, not endlessly retryable"
        );
        assert!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_none()
        );
        let body = torii_body_bytes(response, "target output work refusal").await;
        let envelope: iroha_torii_shared::ErrorEnvelope = norito::json::from_slice(&body).unwrap();
        assert_eq!(envelope.code(), "history_read_exceeds_request_budget");
        let details = envelope.details.as_ref().unwrap();
        assert_eq!(details.field.as_deref(), Some("work units"));
        assert_eq!(
            details.actual.as_deref(),
            Some(required_work.to_string().as_str())
        );
        assert_eq!(details.expected.as_deref(), Some("at most 500 work units"));
        assert_eq!(details.retry_after_seconds, None);
        assert_eq!(
            app.state.committed_entrypoint_height(&identity),
            Some(height)
        );
        assert_eq!(chain.state().view().height(), original_height);
        assert_eq!(chain.committed(2).block().hash(), original_hash);
        assert_eq!(
            chain.committed(2).block().encode_wire().unwrap(),
            original_wire
        );
    }
    let view = chain.state().view();
    assert_eq!(
        view.world().parameters().block().execution_output(),
        ExecutionOutputPolicyV1::bootstrap()
    );
    assert_eq!(
        view.world().parameters().block().fastpq_source(),
        FastpqSourcePolicyV1::bootstrap()
    );
    assert_eq!(
        view.world()
            .parameters()
            .block()
            .max_time_trigger_invocations()
            .get(),
        512
    );
}
