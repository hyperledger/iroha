// Native height-501 controls for HTTP observations that read State/checkpoint ancestry.

/// Certify `receipts` at 501, past the shipped full-prefix fetch budget, then an empty
/// executed tip at 502. The deterministic full-prefix reader must still refuse 501.
pub fn past_fetch_budget_history_fixture(
    config: iroha_core::sumeragi::test_chain::TestChainConfig,
    receipts: impl FnOnce(iroha_data_model::NetworkId) -> Vec<SignedTransaction>,
    expected_applied: &[bool],
) -> (
    SharedAppState,
    Vec<SignedTransaction>,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    use iroha_core::execution_attempt::ExecutionAttemptError;
    use iroha_data_model::query::error::QueryExecutionFail;

    let work = routing::app_query_limits().max_fetch_size;
    assert_eq!(
        work, 500,
        "exercise the shipped default without changing global limits"
    );
    let mut chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    while chain.height() < work {
        chain.commit(Vec::new());
    }
    let transactions = receipts(chain.network_id());
    let observed = chain.commit(transactions.clone());
    assert_eq!(chain.height(), 501);
    let receipt = chain.committed(501);
    assert_eq!(
        observed,
        expected_applied,
        "original native results: {:?}",
        (0..u32::try_from(observed.len()).unwrap())
            .map(|index| &receipt.block().network_output_at(index).unwrap().1.result)
            .collect::<Vec<_>>()
    );
    drop(receipt);
    // HTTP readers authenticate 501 backwards from the executed tip (502) or a node-local
    // checkpoint, never from genesis.
    chain.commit(Vec::new());
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    assert!(
        matches!(
            chain.state().read_finalized_execution_carrier(
                NonZeroUsize::new(501).unwrap(),
                work,
                bytes
            ),
            Err(ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ),
        "the consensus reader must retain deterministic full-prefix work accounting"
    );
    let mut app = mk_app_state_for_tests();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.state = chain.state().clone();
    unique.kura = chain.kura().clone();
    (app, transactions, chain)
}

/// One ordinary authority transaction for [`past_fetch_budget_history_fixture`].
pub fn past_fetch_budget_transaction(
    network: iroha_data_model::NetworkId,
    key: &KeyPair,
    instructions: Vec<iroha_data_model::isi::InstructionBox>,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(1_001));
    builder
        .with_instructions(instructions)
        .sign(key.private_key())
}

#[tokio::test]
async fn prepared_submit_outcome_reads_past_fetch_budget_through_checkpoint_ancestry() {
    let key = checked_torii_test_ed25519_keypair(0x24, "prepared replay authority");
    let authority = AccountId::new(key.public_key().clone());
    let (app, transactions, _chain) = past_fetch_budget_history_fixture(
        iroha_core::sumeragi::test_chain::TestChainConfig::new(
            world_with_account(&authority),
            1_000,
        ),
        |network| {
            vec![
                past_fetch_budget_transaction(
                    network,
                    &key,
                    vec![
                        Log::new(Level::INFO, "prepared replay past the fetch budget".into())
                            .into(),
                    ],
                ),
                past_fetch_budget_transaction(
                    network,
                    &key,
                    vec![
                        iroha_data_model::isi::Unregister::domain(
                            DomainId::try_new("missing_replay_domain", "universal").unwrap(),
                        )
                        .into(),
                    ],
                ),
            ]
        },
        &[true, false],
    );
    let available = app.query_fanout_inflight.available_bytes();
    for (transaction, expected) in transactions.iter().zip(["Applied", "Rejected"]) {
        let hash = transaction.hash();
        let anchor = canonical_transaction_anchor(&app.state, &hash)
            .unwrap()
            .expect("the receipt has committed membership");
        assert_eq!(anchor.height.get(), 501);
        assert_eq!(
            routing::prepared_submit_outcome(&app, transaction).unwrap(),
            Some(expected)
        );
        assert!(
            app.pipeline_status_cache.lookup(&hash).is_none(),
            "a prepared replay records no pipeline cache entry"
        );
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            available,
            "the request owner is released after the membership recheck"
        );
    }
    assert_eq!(
        app.queue.active_len(),
        0,
        "a replay of committed receipts must not resubmit them"
    );
}

#[tokio::test]
async fn prepared_submit_outcome_refuses_a_foreign_query_owner() {
    let (app, hash, chain) = canonical_outcome_test_fixture(false);
    let original = chain.committed(2);
    let transaction = original.block().external_transactions().next().unwrap();
    assert_eq!(transaction.hash(), hash);
    let foreign = crate::history_producer::HistoryProducerOwner::for_test();
    let observed = foreign.scope(|| routing::prepared_submit_outcome(&app, transaction));
    assert!(matches!(
        observed,
        Err(Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
    assert!(app.pipeline_status_cache.lookup(&hash).is_none());
    assert_eq!(
        routing::prepared_submit_outcome(&app, transaction).unwrap(),
        Some("Applied")
    );
}

#[test]
fn trigger_completion_query_reads_past_fetch_budget_and_keeps_cumulative_work_limit() {
    use iroha_data_model::{
        events::data::prelude::{AccountEventFilter, AccountEventSet, DataEventFilter},
        isi::{Register, SetKeyValue},
        query::error::QueryExecutionFail,
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };

    let key = checked_torii_test_ed25519_keypair(0x24, "past-budget data-trigger authority");
    let authority = AccountId::new(key.public_key().clone());
    let trigger_id: TriggerId = "past_budget_data_trigger".parse().unwrap();
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![iroha_data_model::isi::InstructionBox::from(Log::new(
                Level::INFO,
                "past-budget data callback".into(),
            ))],
            Repeats::Exactly(1),
            authority.clone(),
            DataEventFilter::Account(
                AccountEventFilter::new()
                    .for_account(authority.clone())
                    .for_events(AccountEventSet::MetadataInserted),
            ),
        )
        .unwrap(),
    );
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        world_with_account(&authority),
        1_000,
    );
    config
        .genesis_instructions
        .push(Register::trigger(trigger).into());
    let (app, transactions, chain) = past_fetch_budget_history_fixture(
        config,
        |network| {
            vec![past_fetch_budget_transaction(
                network,
                &key,
                vec![
                    SetKeyValue::account(
                        authority.clone(),
                        "past_budget_callback".parse().unwrap(),
                        "actual source event",
                    )
                    .into(),
                ],
            )]
        },
        &[true],
    );
    let entrypoint_hash =
        iroha_core::tx::external_entrypoint_hash_from_signed_hash(transactions[0].hash());
    let receipt = chain.committed(501);
    let (_, output) = receipt.block().network_output_at(0).unwrap();
    assert_eq!(
        output.completions.len(),
        1,
        "one actual data invocation at 501"
    );
    assert_eq!(output.completions[0].trigger_id, trigger_id);
    let available = app.query_fanout_inflight.available_bytes();
    let response = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: Some(trigger_id.to_string()),
            entrypoint_hash: None,
            outcome: None,
            from_height: Some(501),
            to_height: Some(501),
            limit: Some(10),
            scan_limit_blocks: Some(1),
        },
    )
    .expect("the HTTP observation serves a completion past the full-prefix budget");
    assert_eq!(response.scanned_blocks, 1);
    assert_eq!(response.completions.len(), 1);
    let record = &response.completions[0];
    assert_eq!(record.block_height, 501);
    assert_eq!(record.entrypoint_index, Some(0));
    assert_eq!(record.source, "execution_output");
    assert_eq!(record.completion.trigger_id, trigger_id.to_string());
    assert_eq!(
        record.completion.trigger_execution_hash,
        entrypoint_hash.to_string()
    );
    assert_eq!(record.completion.outcome, "Success");
    assert_eq!(app.query_fanout_inflight.available_bytes(), available);
    // Checkpoint ancestry does not widen a scan: its unchanged cumulative work still refuses.
    let refused = super::trigger_completion_query_response(
        &app,
        &TriggerCompletionQuery {
            id: Some("absent_past_budget_trigger".to_owned()),
            entrypoint_hash: None,
            outcome: None,
            from_height: None,
            to_height: None,
            limit: Some(10),
            scan_limit_blocks: Some(TRIGGER_COMPLETION_MAX_SCAN_BLOCKS),
        },
    )
    .expect_err("the cumulative work budget still bounds a wide scan");
    assert!(matches!(
        refused,
        Error::Query(ValidationFail::QueryFailed(
            QueryExecutionFail::GasBudgetExceeded
        ))
    ));
    assert_eq!(app.query_fanout_inflight.available_bytes(), available);
}
