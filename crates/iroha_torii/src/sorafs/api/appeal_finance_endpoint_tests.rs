// Appeal-finance, privacy-aggregate, and publication endpoint regressions.

fn appeal_finance_settlement_receipt_fixture() -> SoraFsAppealFinanceSettlementReceiptV1 {
    SoraFsAppealFinanceSettlementReceiptV1 {
        version: SORAFS_APPEAL_FINANCE_SETTLEMENT_RECEIPT_VERSION_V1,
        receipt_id: [0x52; 16],
        case_id: "case-42".to_string(),
        round_id: Some("round-1".to_string()),
        generated_at_unix_ms: 1_800_000_032_000,
        finalized_block_height: 42,
        finalized_block_hash: [0x43; 32],
        appeal_finance_config_version: "baseline-v1".to_string(),
        appeal_finance_policy_digest: [0x44; 32],
        outcome: SoraFsAppealFinanceOutcomeV1::Frivolous,
        escrow_id_hex: "11".repeat(32),
        payer_account: "payer-account".to_string(),
        destination_account: "escrow-account".to_string(),
        release_authority_account: Some("release-authority".to_string()),
        submitted_step: "drawdown_non_refund".to_string(),
        required_authority: "release-authority".to_string(),
        amount_xor: "420".parse().expect("canonical XOR amount"),
        tx_hash_hex: "22".repeat(32),
        reconciliation_digest_hex: "33".repeat(32),
        reconciliation_status: "settled".to_string(),
        observed_lifecycle_status: "drawn_down".to_string(),
        observed_remaining_xor: "0".parse().expect("canonical XOR amount"),
        deposit_xor: "420".parse().expect("canonical XOR amount"),
        refund_xor: "0".parse().expect("canonical XOR amount"),
        treasury_xor: "210".parse().expect("canonical XOR amount"),
        held_xor: "210".parse().expect("canonical XOR amount"),
        panel_size: 7,
        configured_signer_count: 1,
    }
}

#[test]
fn appeal_pricing_quote_uses_baseline_config() {
    let policy = baseline_appeal_finance_runtime_policy();
    let config = policy.pricing();
    let request = AppealPricingQuoteRequestDto {
        class: "content".to_owned(),
        backlog: 28,
        evidence_size_mb: 45,
        urgency: Some("normal".to_owned()),
        panel_size: Some(7),
    };
    let input = appeal_quote_input(request, config).expect("valid quote input");
    let quote = config.quote(input).expect("baseline quote");
    let value = appeal_pricing_quote_json(&policy, input, &quote);
    let deposit = quote.deposit_xor.to_string();

    assert_eq!(value.json_str(&["class"]), Some("content"));
    assert_eq!(value.json_str(&["urgency"]), Some("normal"));
    assert_eq!(value.json_u64(&["panel_size"]), Some(7));
    assert_eq!(
        value.json_str(&["pricing_config_version"]),
        Some(config.version())
    );
    assert_eq!(value.json_str(&["deposit_xor"]), Some(deposit.as_str()));
    assert!(value.json_str(&["breakdown", "raw_deposit_xor"]).is_some());
}
#[test]
fn appeal_pricing_quote_rejects_unknown_class() {
    let config = baseline_appeal_pricing_config();
    let request = AppealPricingQuoteRequestDto {
        class: "unknown".to_owned(),
        backlog: 0,
        evidence_size_mb: 0,
        urgency: None,
        panel_size: None,
    };
    let err = appeal_quote_input(request, &config).expect_err("unknown class rejected");
    assert!(err.contains("unknown appeal class"));
}
#[test]
fn appeal_pricing_status_marks_deposit_builder_and_publish_flows_enabled() {
    let policy = baseline_appeal_finance_runtime_policy();
    let value = appeal_pricing_status_json(
        &policy,
        AppealFinanceAssetReadiness {
            ready: true,
            status: "ready",
            observed_scale: Some(9),
        },
    );

    assert_eq!(value.json_str(&["pricing_api"]), Some("enabled"));
    assert_eq!(value.json_str(&["quote_api"]), Some("enabled"));
    assert_eq!(
        value.json_str(&["deposit_api"]),
        Some("enabled_canonical_auth_durable_finalized_asset_lock_forwarder_status_confirmation")
    );
    assert_eq!(value.json_str(&["settlement_plan_api"]), Some("enabled"));
    assert_eq!(
        value.json_str(&["settlement_execution_api"]),
        Some("enabled_canonical_auth_plan_only_durable_forwarder_handoff")
    );
    assert_eq!(
        value.json_str(&["settlement_reconciliation_api"]),
        Some("enabled_canonical_auth_runtime_asset_lock_reconciliation_digest")
    );
    assert_eq!(
        value.json_str(&["settlement_submission_api"]),
        Some("enabled_canonical_auth_runtime_signer_durable_finalized_next_step_forwarder")
    );
    assert_eq!(
        value.json_str(&["settlement_receipt_publication"]),
        Some("enabled_governance_dag_after_finalized_commit")
    );
    assert_eq!(
        value.json_str(&["settlement_receipt_dashboard_api"]),
        Some("enabled_local_publish_index")
    );
    assert_eq!(value.json_str(&["disbursement_plan_api"]), Some("enabled"));
    assert_eq!(
        value.json_str(&["report_publication"]),
        Some("enabled_local_governance_dag")
    );
    assert_eq!(
        value.json_str(&["weekly_rollup_publication"]),
        Some("enabled_local_governance_dag")
    );
    assert_eq!(
        value.json_str(&["weekly_rollup_dashboard_api"]),
        Some("enabled_local_publish_index")
    );
    assert_eq!(
        value.json_str(&["report_api"]),
        Some("enabled_canonical_auth_local_governance_dag")
    );
    assert_eq!(
        value.json_str(&["weekly_rollup_api"]),
        Some("enabled_canonical_auth_local_governance_dag")
    );
    assert_eq!(
        value.json_str(&["settlement_processor"]),
        Some("enabled_durable_finalized_ledger_reconciliation")
    );
}
#[tokio::test]
async fn appeal_pricing_handlers_return_baseline_quote_and_status() {
    let app = mk_app_state_for_tests();
    let config_response = handle_get_sorafs_appeal_pricing_config(State(app.clone())).await;
    assert_eq!(config_response.status(), StatusCode::OK);
    let config_value = api_test_response_json(config_response).await;
    assert_eq!(
        config_value.json_str(&["appeal_finance_policy_source"]),
        Some(APPEAL_FINANCE_CONFIG_SOURCE_V1)
    );
    assert!(
        config_value
            .get("classes")
            .and_then(|classes| classes.get("content"))
            .is_some()
    );
    let quote_request = AppealPricingQuoteRequestDto {
        class: "fraud".to_owned(),
        backlog: 9,
        evidence_size_mb: 12,
        urgency: Some("high".to_owned()),
        panel_size: None,
    };
    let quote_response =
        handle_post_sorafs_appeal_pricing_quote(State(app.clone()), JsonOnly(quote_request)).await;
    assert_eq!(quote_response.status(), StatusCode::OK);
    let quote_value = api_test_response_json(quote_response).await;
    assert_eq!(quote_value.json_str(&["class"]), Some("fraud"));
    assert_eq!(quote_value.json_str(&["urgency"]), Some("high"));
    assert_eq!(quote_value.json_u64(&["panel_size"]), Some(7));
    assert!(quote_value.json_str(&["deposit_xor"]).is_some());

    let status_response = handle_get_sorafs_appeal_pricing_status(State(app)).await;
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_value = api_test_response_json(status_response).await;
    assert_eq!(
        status_value.json_str(&["deposit_api"]),
        Some("enabled_canonical_auth_durable_finalized_asset_lock_forwarder_status_confirmation")
    );
    assert_eq!(
        status_value.json_str(&["settlement_plan_api"]),
        Some("enabled")
    );
    assert_eq!(
        status_value.json_str(&["settlement_execution_api"]),
        Some("enabled_canonical_auth_plan_only_durable_forwarder_handoff")
    );
    assert_eq!(
        status_value.json_str(&["settlement_reconciliation_api"]),
        Some("enabled_canonical_auth_runtime_asset_lock_reconciliation_digest")
    );
    assert_eq!(
        status_value.json_str(&["settlement_submission_api"]),
        Some("enabled_canonical_auth_runtime_signer_durable_finalized_next_step_forwarder")
    );
    assert_eq!(
        status_value.json_str(&["settlement_receipt_publication"]),
        Some("enabled_governance_dag_after_finalized_commit")
    );
    assert_eq!(
        status_value.json_str(&["settlement_receipt_dashboard_api"]),
        Some("enabled_local_publish_index")
    );
    assert_eq!(
        status_value.json_str(&["weekly_rollup_publication"]),
        Some("enabled_local_governance_dag")
    );
    assert_eq!(
        status_value.json_str(&["report_api"]),
        Some("enabled_canonical_auth_local_governance_dag")
    );
}
#[tokio::test]
async fn appeal_pricing_quote_handler_rejects_invalid_panel_size() {
    let request = AppealPricingQuoteRequestDto {
        class: "content".to_owned(),
        backlog: 0,
        evidence_size_mb: 0,
        urgency: None,
        panel_size: Some(0),
    };
    let response =
        handle_post_sorafs_appeal_pricing_quote(State(mk_app_state_for_tests()), JsonOnly(request))
            .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value = api_test_response_json(response).await;
    assert!(
        value
            .json_str(&["error"])
            .is_some_and(|error| error.contains("panel"))
    );
}
#[tokio::test]
async fn appeal_finance_settle_handler_returns_baseline_plan() {
    let response = handle_post_sorafs_appeal_finance_settle(
        State(mk_app_state_for_tests()),
        JsonOnly(AppealFinanceSettleRequestDto {
            deposit_xor: "400".parse().expect("canonical XOR amount"),
            outcome: "overturn".to_owned(),
            panel_size: Some(7),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.settlement.v1")
    );
    assert_eq!(value.json_str(&["outcome"]), Some("overturn"));
    assert_eq!(value.json_str(&["refund_xor"]), Some("400"));
    assert_eq!(value.json_str(&["treasury_xor"]), Some("0"));
}
#[tokio::test]
async fn appeal_finance_disburse_handler_returns_juror_plan() {
    fn account(seed: u8) -> String {
        AccountId::new(checked_test_keypair(seed).public_key().clone()).to_string()
    }
    let juror_ids = (0x10..0x17).map(account).collect::<Vec<_>>();
    let no_show = juror_ids[0].clone();
    let response = handle_post_sorafs_appeal_finance_disburse(
        State(mk_app_state_for_tests()),
        JsonOnly(AppealFinanceDisburseRequestDto {
            deposit_xor: "420".parse().expect("canonical XOR amount"),
            outcome: "overturn".to_owned(),
            refund_account: account(0x40),
            treasury_account: account(0x41),
            escrow_account: account(0x42),
            juror_ids,
            no_show_account_ids: Some(vec![no_show.clone()]),
            panel_size: Some(7),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.disbursement.v1")
    );
    assert_eq!(value.json_u64(&["rewards", "attending"]), Some(6));
    assert_eq!(
        value
            .json_first(&["rewards", "no_shows"])
            .and_then(Value::as_str),
        Some(no_show.as_str())
    );
}
#[tokio::test]
async fn appeal_finance_deposit_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let body = appeal_finance_deposit_body(appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    ));
    let response = handle_post_sorafs_appeal_finance_deposit(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSITS),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn appeal_finance_deposit_endpoint_rejects_payer_mismatch() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let body = appeal_finance_deposit_body(appeal_finance_deposit_request(
        &auth.buyer.account,
        &auth.provider.account,
        Some(&auth.provider.account),
    ));
    let response = post_appeal_finance_deposit(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[test]
fn appeal_finance_deposit_amount_preserves_wide_values_and_enforces_xor_scale() {
    let wide: XorQuantity = "340282366920938463463374607431768211456.000000001"
        .parse()
        .expect("wide XOR quantity");
    assert_eq!(
        appeal_finance_deposit_amount(wide.clone()).expect("positive scale-nine amount"),
        wide.into_quantity()
    );
}
#[test]
fn appeal_finance_runtime_policy_digest_is_deterministic_and_config_bound() {
    let first = baseline_appeal_finance_runtime_policy();
    let second = baseline_appeal_finance_runtime_policy();
    assert_ne!(first.policy_digest, [0; 32]);
    assert_eq!(first.policy_digest, second.policy_digest);
    assert_eq!(first.pricing_policy_digest, second.pricing_policy_digest);
    assert_eq!(
        first.settlement_policy_digest,
        second.settlement_policy_digest
    );
    let mut changed = iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default();
    changed.pricing.version = "baseline-revision-v2".to_owned();
    let changed = AppealFinanceRuntimePolicy::from_config(&changed).expect("valid changed policy");
    assert_ne!(first.policy_digest, changed.policy_digest);
    assert_ne!(first.pricing_policy_digest, changed.pricing_policy_digest);
    assert_eq!(
        first.settlement_policy_digest,
        changed.settlement_policy_digest
    );
    let wrong_asset = iroha_config::parameters::actual::SorafsAppealFinanceSettlement {
        asset_definition_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("xor", "universal").expect("domain id"),
            "other".parse().expect("asset definition name"),
        ),
        ..Default::default()
    };
    assert!(AppealFinanceRuntimePolicy::from_config(&wrong_asset).is_err());
    let wrong_scale = iroha_config::parameters::actual::SorafsAppealFinanceSettlement {
        asset_scale: 8,
        ..Default::default()
    };
    assert!(AppealFinanceRuntimePolicy::from_config(&wrong_scale).is_err());
    let mut mismatched_panel =
        iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default();
    mismatched_panel.settlement.default_panel_size =
        mismatched_panel.pricing.default_panel_size + 1;
    assert!(AppealFinanceRuntimePolicy::from_config(&mismatched_panel).is_err());
    for version in [
        "Baseline-v1",
        "baseline_v1",
        "baseline-v0",
        "baseline-v01",
        "baseline-v1-revision-2",
    ] {
        let mut invalid =
            iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default();
        invalid.pricing.version = version.to_owned();
        assert!(
            AppealFinanceRuntimePolicy::from_config(&invalid).is_err(),
            "noncanonical runtime policy version `{version}` must fail closed"
        );
    }
}
#[test]
fn appeal_finance_settlement_context_is_canonical_and_rotation_safe() {
    use sorafs_node::appeal_finance_transaction_forwarder::{
        AppealFinanceFinalizedCursorV1, AppealFinanceOperationV1,
        AppealFinanceTransactionSigningRequestV1,
    };
    let auth = orderbook_auth_fixture();
    let expected = appeal_finance_deposit_expectation(appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    ))
    .expect("valid appeal deposit expectation");
    let policy = baseline_appeal_finance_runtime_policy();
    let verdict = AppealVerdict::Frivolous;
    let panel_size = policy.settlement().default_panel_size();
    let breakdown = policy
        .settlement()
        .settle(expected.deposit_xor.clone(), panel_size, verdict)
        .expect("valid baseline settlement");
    let context = AppealFinanceSettlementOutboxContextV1 {
        version: APPEAL_FINANCE_SETTLEMENT_OUTBOX_CONTEXT_VERSION_V1,
        policy_digest: policy.policy_digest,
        settlement: AppealFinanceSettlementSnapshotV1::from_policy_and_breakdown(
            &policy, &breakdown,
        ),
        expected: expected.clone(),
        outcome: verdict.to_string(),
        panel_size,
    };
    crate::frame_test_support::assert_current_frame(
        &context,
        "iroha_torii::sorafs::api::AppealFinanceSettlementOutboxContextV1",
    );
    let deposit_context = AppealFinanceDepositOutboxContextV1 {
        version: APPEAL_FINANCE_DEPOSIT_OUTBOX_CONTEXT_VERSION_V1,
        policy_digest: policy.policy_digest,
        expected: expected.clone(),
    };
    crate::frame_test_support::assert_current_frame(
        &deposit_context,
        "iroha_torii::sorafs::api::AppealFinanceDepositOutboxContextV1",
    );
    let encoded = norito::to_bytes(&context).expect("encode settlement context");
    assert_eq!(
        decode_appeal_finance_outbox_context(&encoded),
        Some(context.clone())
    );
    let drawdown_xor = breakdown
        .treasury_xor
        .checked_add(&breakdown.held_xor)
        .expect("bounded drawdown amount");
    let operation = AppealFinanceOperationV1::Drawdown(DrawdownAssetLock::new(
        expected.escrow_id,
        drawdown_xor,
        expected.deposit_xor.clone(),
    ));
    let mut expected_record = appeal_finance_deposit_status_record(
        expected.payer_account.clone(),
        Some(expected.destination_account.clone()),
        expected.release_authority_account.clone(),
    );
    expected_record.id = expected.escrow_id;
    expected_record.asset_definition = expected.asset_definition_id.clone();
    expected_record.amount = expected.deposit_xor.clone();
    expected_record.remaining_amount = expected.deposit_xor.clone();
    expected_record.expires_at_ms = expected.expires_at_ms;
    expected_record.evidence_hashes = expected.evidence_hashes.clone();
    let mut request = AppealFinanceTransactionSigningRequestV1 {
        operation_id: [0xA1; 32],
        network_id: crate::signed_query_test_network_id(),
        chain_id: ChainId::from("appeal-finance-policy-rotation-test"),
        authority: auth.provider.account.clone(),
        operation,
        expected_record: Some(expected_record.clone()),
        reconciliation_context: encoded,
        baseline_finalized_cursor: AppealFinanceFinalizedCursorV1 {
            height: 1,
            block_hash: [0xA2; 32],
        },
    };
    assert_eq!(
        appeal_finance_outbox_policy_status(&request, &policy),
        AppealFinanceOutboxPolicyStatusV1::Active
    );
    let drawdown_post = appeal_finance_exact_applied_post_record(&request, 41)
        .expect("derive exact committed drawdown post-state");
    assert_eq!(drawdown_post.remaining_amount, breakdown.refund_xor);
    assert_eq!(drawdown_post.status, AssetEscrowStatus::Locked);
    assert_eq!(drawdown_post.closed_at_ms, None);
    let mut rotated = iroha_config::parameters::actual::SorafsAppealFinanceSettlement::default();
    rotated.pricing.version = "baseline-rotated-v2".to_owned();
    let rotated = AppealFinanceRuntimePolicy::from_config(&rotated).expect("valid rotated policy");
    assert_eq!(
        appeal_finance_outbox_policy_status(&request, &rotated),
        AppealFinanceOutboxPolicyStatusV1::Superseded
    );
    expected_record.remaining_amount = breakdown.refund_xor.clone();
    request.operation = AppealFinanceOperationV1::Cancel(CancelAssetLock::new(
        expected.escrow_id,
        expected_record.remaining_amount.clone(),
    ));
    request.authority = expected.payer_account.clone();
    request.expected_record = Some(expected_record);
    assert_eq!(
        appeal_finance_outbox_policy_status(&request, &rotated),
        AppealFinanceOutboxPolicyStatusV1::Grandfathered
    );
    let cancel_post = appeal_finance_exact_applied_post_record(&request, 42)
        .expect("derive exact committed cancellation post-state");
    assert!(cancel_post.remaining_amount.is_zero());
    assert_eq!(cancel_post.status, AssetEscrowStatus::Cancelled);
    assert_eq!(cancel_post.closed_at_ms, Some(42));
    let refund_only_verdict = AppealVerdict::Decision(AppealDecision::Overturn);
    let refund_only = policy
        .settlement()
        .settle(
            expected.deposit_xor.clone(),
            panel_size,
            refund_only_verdict,
        )
        .expect("valid refund-only settlement");
    assert_eq!(refund_only.refund_xor, expected.deposit_xor);
    assert!(refund_only.treasury_xor.is_zero());
    assert!(refund_only.held_xor.is_zero());
    let refund_only_context = AppealFinanceSettlementOutboxContextV1 {
        version: APPEAL_FINANCE_SETTLEMENT_OUTBOX_CONTEXT_VERSION_V1,
        policy_digest: policy.policy_digest,
        settlement: AppealFinanceSettlementSnapshotV1::from_policy_and_breakdown(
            &policy,
            &refund_only,
        ),
        expected: expected.clone(),
        outcome: refund_only_verdict.to_string(),
        panel_size,
    };
    request.reconciliation_context =
        norito::to_bytes(&refund_only_context).expect("encode refund-only settlement context");
    let mut refund_only_record = request
        .expected_record
        .clone()
        .expect("cancel pre-operation record");
    refund_only_record.remaining_amount = expected.deposit_xor.clone();
    request.operation = AppealFinanceOperationV1::Cancel(CancelAssetLock::new(
        expected.escrow_id,
        refund_only_record.remaining_amount.clone(),
    ));
    request.expected_record = Some(refund_only_record);
    assert_eq!(
        appeal_finance_outbox_policy_status(&request, &rotated),
        AppealFinanceOutboxPolicyStatusV1::Grandfathered,
        "a validated refund-only cancellation must not strand custody on policy rotation"
    );
    let mut tampered = context;
    tampered.settlement.refund_xor = tampered
        .settlement
        .refund_xor
        .checked_add(&Quantity::from(1_u32))
        .expect("bounded tampered refund");
    request.reconciliation_context =
        norito::to_bytes(&tampered).expect("encode tampered settlement context");
    assert_eq!(
        appeal_finance_outbox_policy_status(&request, &policy),
        AppealFinanceOutboxPolicyStatusV1::InvalidContext
    );
}
#[test]
fn appeal_finance_deposit_rejects_non_governed_asset_definition() {
    let auth = orderbook_auth_fixture();
    let mut request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    request.asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("xor", "universal").expect("domain id"),
        "other".parse().expect("asset definition name"),
    )
    .to_string();
    let error = appeal_finance_deposit_expectation(request)
        .expect_err("caller-selected appeal asset must be rejected");
    assert!(error.contains("must equal governed asset"));
}
#[test]
fn appeal_finance_asset_readiness_requires_exact_ledger_scale() {
    let missing = mk_app_state_for_tests();
    let missing_readiness =
        appeal_finance_asset_readiness(&missing, &missing.sorafs_appeal_finance_policy);
    assert!(!missing_readiness.ready);
    assert_eq!(missing_readiness.status, "asset_definition_missing");
    let auth = orderbook_auth_fixture();
    let policy = baseline_appeal_finance_runtime_policy();
    let scale_mismatch =
        mk_app_state_for_tests_with_world(appeal_finance_asset_lock_world_with_scale(
            &auth,
            &policy.asset_definition_id,
            policy.asset_scale.saturating_sub(1),
        ));
    let mismatch_readiness = appeal_finance_asset_readiness(
        &scale_mismatch,
        &scale_mismatch.sorafs_appeal_finance_policy,
    );
    assert!(!mismatch_readiness.ready);
    assert_eq!(mismatch_readiness.status, "asset_scale_mismatch");
    assert_eq!(mismatch_readiness.observed_scale, Some(8));
    let (ready, _temp_dir, _native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &policy.asset_definition_id);
    let ready_readiness =
        appeal_finance_asset_readiness(&ready, &ready.sorafs_appeal_finance_policy);
    assert!(ready_readiness.ready);
    assert_eq!(ready_readiness.observed_scale, Some(9));
}
#[test]
fn appeal_finance_request_dtos_enforce_xor_scale_at_json_boundary() {
    macro_rules! assert_nominal_xor_wire {
        ($ty:ty, $valid:expr, $invalid:expr) => {{
            let decoded: $ty =
                json::from_slice($valid.as_bytes()).expect("decode canonical XOR request");
            assert_eq!(decoded.deposit_xor.to_string(), "0.000000001");
            let encoded = json::to_vec(&decoded).expect("re-encode canonical XOR request");
            let value: Value = json::from_slice(&encoded).expect("decode re-encoded XOR request");
            assert_eq!(value.json_str(&["deposit_xor"]), Some("0.000000001"));
            assert!(
                json::from_slice::<$ty>($invalid.as_bytes()).is_err(),
                "scale-ten XOR request must fail during JSON decoding"
            );
        }};
    }
    assert_nominal_xor_wire!(
        AppealFinanceSettleRequestDto,
        r#"{"deposit_xor":"0.000000001","outcome":"overturn","panel_size":7}"#,
        r#"{"deposit_xor":"0.0000000001","outcome":"overturn","panel_size":7}"#
    );
    assert_nominal_xor_wire!(
        AppealFinanceDisburseRequestDto,
        r#"{"deposit_xor":"0.000000001","outcome":"overturn","refund_account":"refund","treasury_account":"treasury","escrow_account":"escrow","juror_ids":[],"no_show_account_ids":[],"panel_size":7}"#,
        r#"{"deposit_xor":"0.0000000001","outcome":"overturn","refund_account":"refund","treasury_account":"treasury","escrow_account":"escrow","juror_ids":[],"no_show_account_ids":[],"panel_size":7}"#
    );
    assert_nominal_xor_wire!(
        AppealFinanceDepositRequestDto,
        r#"{"case_id":"case","round_id":"round","payer_account":"payer","destination_account":"destination","release_authority_account":null,"asset_definition_id":"xor","deposit_xor":"0.000000001","expires_at_ms":null,"idempotency_key":"attempt","evidence_hashes_hex":[]}"#,
        r#"{"case_id":"case","round_id":"round","payer_account":"payer","destination_account":"destination","release_authority_account":null,"asset_definition_id":"xor","deposit_xor":"0.0000000001","expires_at_ms":null,"idempotency_key":"attempt","evidence_hashes_hex":[]}"#
    );
    assert_nominal_xor_wire!(
        AppealFinanceDepositConfirmRequestDto,
        r#"{"escrow_id_hex":"escrow","case_id":"case","round_id":"round","payer_account":"payer","destination_account":"destination","release_authority_account":null,"asset_definition_id":"xor","deposit_xor":"0.000000001","expires_at_ms":null,"idempotency_key":"attempt","evidence_hashes_hex":[]}"#,
        r#"{"escrow_id_hex":"escrow","case_id":"case","round_id":"round","payer_account":"payer","destination_account":"destination","release_authority_account":null,"asset_definition_id":"xor","deposit_xor":"0.0000000001","expires_at_ms":null,"idempotency_key":"attempt","evidence_hashes_hex":[]}"#
    );
}
#[tokio::test]
async fn appeal_finance_deposit_endpoint_durably_enqueues_open_asset_lock() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (mut app, _temp_dir, native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    configure_appeal_finance_settlement_submitter(&mut app, &auth.provider, _temp_dir.path());
    seed_appeal_finance_finalized_anchor(&native_chain);
    let asset_definition_id = request.asset_definition_id.clone();
    let destination_account = request.destination_account.clone();
    let release_authority_account = request
        .release_authority_account
        .clone()
        .expect("release authority fixture");
    let expires_at_ms = request.expires_at_ms;
    let body = appeal_finance_deposit_body(request);
    let replay_body = body.clone();
    let response = post_appeal_finance_deposit(app.clone(), &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.deposit_submission.v1")
    );
    assert_eq!(value.json_str(&["status"]), Some("durably_enqueued"));
    assert_eq!(
        value.json_str(&["ledger_mutation"]),
        Some("durable_finalized_ledger_forwarder")
    );
    assert_hex_32(
        value
            .json_str(&["operation_id_hex"])
            .expect("durable operation id"),
    );
    assert!(value.get("tx_instructions").is_none());
    let payer_account = auth.provider.account.to_string();
    assert_eq!(
        value.json_str(&["payer_account"]),
        Some(payer_account.as_str())
    );
    assert_eq!(
        value.json_str(&["asset_definition_id"]),
        Some(asset_definition_id.as_str())
    );
    assert_eq!(
        value.json_str(&["destination_account"]),
        Some(destination_account.as_str())
    );
    assert_eq!(
        value.json_str(&["release_authority_account"]),
        Some(release_authority_account.as_str())
    );
    assert_eq!(value.json_u64(&["expires_at_ms"]), expires_at_ms);
    assert_eq!(value.json_str(&["deposit_xor"]), Some("420"));
    let submitter = app
        .sorafs_appeal_settlement_submitter
        .as_ref()
        .expect("test submitter");
    let pending = submitter
        .forwarder
        .pending_after(None, 8)
        .expect("durable pending deposit");
    assert_eq!(pending.len(), 1);
    let retained = submitter
        .forwarder
        .operation_for_reconciliation(pending[0].operation_id)
        .expect("retained open operation");
    let sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceOperationV1::Open(open) =
        retained.operation
    else {
        panic!("retained operation must be OpenAssetLock");
    };
    assert_eq!(open.amount.to_string(), "420");
    assert_eq!(open.asset_definition.to_string(), asset_definition_id);
    assert_eq!(open.destination.to_string(), destination_account);
    assert_eq!(
        open.release_authority
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(release_authority_account.as_str())
    );
    assert_eq!(open.expires_at_ms, expires_at_ms);
    assert_eq!(open.evidence_hashes.len(), 1);
    let escrow_id_hex = expected.escrow_id.as_hash().to_string();
    assert_eq!(
        value.json_str(&["escrow_id_hex"]),
        Some(escrow_id_hex.as_str())
    );
    let replay = post_appeal_finance_deposit(app.clone(), &auth.provider, replay_body).await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    let replay_value = api_test_response_json(replay).await;
    assert_eq!(
        replay_value.json_str(&["status"]),
        Some("already_durably_enqueued")
    );
    assert_eq!(
        replay_value.json_str(&["operation_id_hex"]),
        value.json_str(&["operation_id_hex"])
    );
}
#[test]
fn appeal_finance_deposit_visibility_is_limited_to_participants() {
    let auth = orderbook_auth_fixture();
    let release_authority = AccountId::new(checked_test_keypair(0x7A).public_key().clone());
    let record = appeal_finance_deposit_status_record(
        auth.provider.account.clone(),
        Some(auth.buyer.account.clone()),
        Some(release_authority.clone()),
    );
    assert!(appeal_finance_deposit_record_visible_to(
        &record,
        &auth.provider.account
    ));
    assert!(appeal_finance_deposit_record_visible_to(
        &record,
        &auth.buyer.account
    ));
    assert!(appeal_finance_deposit_record_visible_to(
        &record,
        &release_authority
    ));
    let outsider = AccountId::new(checked_test_keypair(0x7B).public_key().clone());
    assert!(!appeal_finance_deposit_record_visible_to(
        &record, &outsider
    ));
}
#[test]
fn appeal_finance_deposit_confirmation_detects_runtime_mismatches() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected = appeal_finance_deposit_expectation(request).expect("valid deposit expectation");
    let mut record = appeal_finance_deposit_status_record(
        auth.provider.account.clone(),
        Some(auth.buyer.account.clone()),
        Some(auth.provider.account.clone()),
    );
    record.id = expected.escrow_id;
    record.asset_definition = expected.asset_definition_id.clone();
    record.evidence_hashes = expected.evidence_hashes.clone();
    record.status = AssetEscrowStatus::DrawnDown;
    record.remaining_amount = iroha_primitives::numeric::Quantity::zero();
    let mismatches = appeal_finance_deposit_confirmation_mismatches(&expected, &record);
    assert!(mismatches.iter().any(|item| item.contains("locked")));
    assert!(
        mismatches
            .iter()
            .any(|item| item.contains("remaining_amount"))
    );
}
#[test]
fn asset_escrow_kind_labels_cover_the_closed_enum() {
    assert_eq!(
        asset_escrow_kind_label(AssetEscrowKind::Marketplace),
        "marketplace"
    );
    assert_eq!(asset_escrow_kind_label(AssetEscrowKind::Lock), "lock");
    assert_eq!(
        asset_escrow_kind_label(AssetEscrowKind::Conditional),
        "conditional"
    );
}
#[test]
fn appeal_finance_deposit_status_json_renders_native_asset_lock_record() {
    let auth = orderbook_auth_fixture();
    let release_authority = AccountId::new(checked_test_keypair(0x7A).public_key().clone());
    let record = appeal_finance_deposit_status_record(
        auth.provider.account.clone(),
        Some(auth.buyer.account.clone()),
        Some(release_authority.clone()),
    );
    let value = appeal_finance_deposit_status_json(&record);
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.deposit_status.v1")
    );
    let escrow_id_hex = record.id.as_hash().to_string();
    assert_eq!(
        value.json_str(&["escrow_id_hex"]),
        Some(escrow_id_hex.as_str())
    );
    let seller_account = auth.provider.account.to_string();
    assert_eq!(
        value.json_str(&["seller_account"]),
        Some(seller_account.as_str())
    );
    let buyer_account = auth.buyer.account.to_string();
    assert_eq!(
        value.json_str(&["buyer_account"]),
        Some(buyer_account.as_str())
    );
    assert_eq!(value.json_str(&["lifecycle_status"]), Some("locked"));
    assert_eq!(value.json_str(&["kind"]), Some("lock"));
    let release_authority_account = release_authority.to_string();
    assert_eq!(
        value.json_str(&["release_authority"]),
        Some(release_authority_account.as_str())
    );
    assert_eq!(value.json_u64(&["expires_at_ms"]), Some(1_800_086_400_000));
    assert_eq!(value.json_str(&["amount"]), Some("420"));
    assert_eq!(value.json_len(&["evidence_hashes_hex"]), Some(1));
}
#[tokio::test]
async fn appeal_finance_deposit_status_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, _auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let escrow_id_hex = Hash::new("missing deposit status").to_string();
    let response = handle_get_sorafs_appeal_finance_deposit(
        State(app),
        HeaderMap::new(),
        Method::GET,
        format!("{APPEAL_FINANCE_ROUTE_DEPOSITS}/{escrow_id_hex}")
            .parse()
            .expect("deposit status uri"),
        Path(escrow_id_hex),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn appeal_finance_deposit_status_endpoint_returns_not_found_for_absent_escrow() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let escrow_id_hex = Hash::new("missing deposit status").to_string();
    let response = get_appeal_finance_deposit(app, &auth.provider, &escrow_id_hex).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn appeal_finance_deposit_confirm_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let body = appeal_finance_deposit_confirm_body(appeal_finance_deposit_confirm_request(
        &request,
        expected.escrow_id.as_hash().to_string(),
    ));
    let response = handle_post_sorafs_appeal_finance_deposit_confirm(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSIT_CONFIRM),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn appeal_finance_deposit_confirm_endpoint_confirms_runtime_asset_lock() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let body = appeal_finance_deposit_confirm_body(appeal_finance_deposit_confirm_request(
        &request,
        expected.escrow_id.as_hash().to_string(),
    ));
    let response = post_appeal_finance_deposit_confirm(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.deposit_confirmation.v1")
    );
    assert_eq!(value.json_bool(&["confirmed"]), Some(true));
    assert_eq!(value.json_str(&["status"]), Some("confirmed"));
    assert_eq!(
        value.json_str(&["ledger_record", "lifecycle_status"]),
        Some("locked")
    );
}
#[tokio::test]
async fn appeal_finance_deposit_settle_endpoint_returns_plan_without_signing_payloads() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let response = post_appeal_finance_deposit_settle(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.deposit_settlement_execution.v1")
    );
    assert_eq!(value.json_str(&["status"]), Some("plan_only"));
    assert_eq!(value.json_str(&["ledger_mutation"]), Some("none"));
    assert_eq!(value.json_str(&["drawdown_xor"]), Some("210"));
    assert_eq!(value.json_str(&["cancel_refund_xor"]), Some("210"));
    assert_eq!(
        value.json_bool(&["requires_multiple_authorities"]),
        Some(false)
    );
    let steps = value
        .json_array(&["tx_steps"])
        .expect("settlement tx steps");
    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps[0].get("action").and_then(Value::as_str),
        Some("drawdown_non_refund")
    );
    assert_eq!(
        steps[1].get("action").and_then(Value::as_str),
        Some("cancel_refund")
    );
    assert!(
        steps
            .iter()
            .all(|step| { step.get("wire_id").is_none() && step.get("payload_hex").is_none() })
    );
}
#[tokio::test]
async fn appeal_finance_deposit_settle_endpoint_builds_refund_only_cancel() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "overturn");
    let response = post_appeal_finance_deposit_settle(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["drawdown_xor"]), Some("0"));
    assert_eq!(value.json_str(&["cancel_refund_xor"]), Some("420"));
    let steps = value
        .json_array(&["tx_steps"])
        .expect("refund-only settlement tx steps");
    assert_eq!(steps.len(), 1);
    assert_eq!(
        steps[0].get("action").and_then(Value::as_str),
        Some("cancel_refund")
    );
}
#[tokio::test]
async fn appeal_finance_deposit_submit_settlement_endpoint_queues_next_step() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (mut app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    configure_appeal_finance_settlement_submitter(&mut app, &auth.provider, _temp_dir.path());
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let response = post_appeal_finance_deposit_submit_settlement(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["status"]), Some("durably_enqueued"));
    assert_eq!(value.json_u64(&["configured_signer_count"]), Some(1));
    let operation_id = value
        .json_str(&["operation_id_hex"])
        .expect("durable operation id");
    assert_hex_32(operation_id);
    assert_eq!(value.json_str(&["tx_hash_hex"]), None);
    let step = value
        .json_object(&["submitted_step"])
        .expect("submitted step");
    assert_eq!(step.json_str(&["action"]), Some("drawdown_non_refund"));
    let provider_account = auth.provider.account.to_string();
    assert_eq!(
        step.json_str(&["required_authority"]),
        Some(provider_account.as_str())
    );
    let reconciliation = value
        .get("reconciliation")
        .expect("submission reconciliation");
    assert_eq!(
        reconciliation.json_str(&["status"]),
        Some("pending_forwarder_submission")
    );
    assert_appeal_finance_reconciliation_digest_hex(reconciliation);
    let receipt = value
        .json_object(&["settlement_receipt"])
        .expect("settlement receipt state");
    assert_eq!(
        receipt.json_str(&["publication_status"]),
        Some("awaiting_finalized_commit")
    );
}
#[test]
fn appeal_finance_settlement_submission_advances_after_partial_drawdown() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected = appeal_finance_deposit_expectation(request).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let record = || {
        app.state
            .world_view()
            .asset_escrows()
            .get(&expected.escrow_id)
            .cloned()
            .expect("appeal deposit record")
    };
    let next_step = || -> Result<Option<(String, String)>, String> {
        let current = record();
        let policy = baseline_appeal_finance_runtime_policy();
        let config = policy.settlement();
        let deposit_xor =
            parse_appeal_quantity_literal("deposit_xor", &expected.deposit_xor.to_string())
                .map_err(|error| error.to_string())?;
        let verdict = appeal_verdict_from_request("frivolous")?;
        let breakdown = config
            .settle(deposit_xor, 7, verdict)
            .map_err(|error| error.to_string())?;
        let reconciliation = appeal_finance_deposit_settlement_reconciliation(
            &expected, &current, &policy, verdict, 7, &breakdown,
        )?;
        let execution =
            appeal_finance_deposit_settlement_execution(&expected, &current, &breakdown)?;
        let action =
            appeal_finance_deposit_next_settlement_submission_step(&reconciliation, &execution)
                .map(|step| step.action.to_owned());
        Ok(action.map(|action| (action, reconciliation.reconciliation_digest_hex)))
    };
    let (first_action, first_reconciliation_digest) = next_step()
        .expect("initial settlement step")
        .expect("initial settlement step is pending");
    assert_eq!(first_action, "drawdown_non_refund");
    drawdown_appeal_finance_asset_lock(
        &mut native_chain,
        &expected,
        &auth.provider.account,
        iroha_primitives::numeric::Quantity::from_str("210.0").expect("drawdown amount quantity"),
        2,
    );
    let (follow_up_action, follow_up_reconciliation_digest) = next_step()
        .expect("follow-up settlement step")
        .expect("refund settlement step is pending");
    assert_eq!(follow_up_action, "cancel_refund");
    assert_ne!(first_reconciliation_digest, follow_up_reconciliation_digest);
    cancel_appeal_finance_asset_lock(&mut native_chain, &expected, &auth.provider.account, 3);
    assert!(next_step().expect("settled submission state").is_none());
}
#[tokio::test]
async fn appeal_finance_deposit_submit_settlement_never_publishes_before_finalization() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (mut app, temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world_and_governance(
            &auth,
            &expected.asset_definition_id,
        );
    configure_appeal_finance_settlement_submitter(&mut app, &auth.provider, temp_dir.path());
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let authority_reader = Arc::clone(&app);
    let response = post_appeal_finance_deposit_submit_settlement(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    let receipt_status = value
        .json_object(&["settlement_receipt"])
        .expect("settlement receipt response");
    assert_eq!(
        receipt_status.json_str(&["publication_status"]),
        Some("awaiting_finalized_commit")
    );
    assert_eq!(receipt_status.json_str(&["tx_hash_hex"]), None);

    let governance_dir = temp_dir.path().join("governance");
    let snapshot = authority_reader
        .sorafs_node
        .governance_dag_publication_snapshot()
        .expect("read typed publication authority")
        .expect("configured publisher has an initialized authority");
    let authority: Value = norito::json::from_slice(snapshot.canonical_bytes())
        .expect("decode typed publication authority");
    assert!(
        authority
            .json_array(&[
                "publish_index",
                "by_payload_kind",
                "appeal_finance_settlement_receipt"
            ])
            .is_none_or(Vec::is_empty)
    );
    assert!(
        !governance_dir
            .join(GOVERNANCE_DAG_PUBLICATION_SOURCES_DIR)
            .exists(),
        "unfinalized settlement must not persist publication sources"
    );
}
#[tokio::test]
async fn appeal_finance_deposit_submit_settlement_endpoint_reports_missing_submitter() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let response = post_appeal_finance_deposit_submit_settlement(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["status"]),
        Some("submitter_not_configured")
    );
    assert_eq!(value.json_str(&["tx_hash_hex"]), None);
    let step = value
        .json_object(&["submitted_step"])
        .expect("pending submitter step");
    let provider_account = auth.provider.account.to_string();
    assert_eq!(
        step.json_str(&["required_authority"]),
        Some(provider_account.as_str())
    );
}
#[tokio::test]
async fn appeal_finance_deposit_submit_settlement_fails_closed_without_runtime_provider() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (mut app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    configure_appeal_finance_settlement_submitter(&mut app, &auth.provider, _temp_dir.path());
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .sorafs_appeal_settlement_submitter
        .as_mut()
        .expect("configured submitter")
        .runtime_signers = None;
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let response = post_appeal_finance_deposit_submit_settlement(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["status"]), Some("missing_required_signer"));
    assert_eq!(value.json_str(&["operation_id_hex"]), None);
}
#[tokio::test]
async fn appeal_finance_deposit_reconcile_endpoint_reports_pending_forwarder_submission() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let body = appeal_finance_deposit_settle_body(confirmation, "frivolous");
    let response = post_appeal_finance_deposit_reconcile(app, &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.deposit_settlement_reconciliation.v1")
    );
    assert_eq!(
        value.json_str(&["status"]),
        Some("pending_forwarder_submission")
    );
    assert_eq!(value.json_bool(&["reconciled"]), Some(false));
    assert_eq!(
        value.json_str(&["expected_final_lifecycle_status"]),
        Some("cancelled")
    );
    assert_eq!(
        value.json_str(&["observed_lifecycle_status"]),
        Some("locked")
    );
    assert_eq!(value.json_len(&["mismatches"]), Some(0));
    assert_appeal_finance_reconciliation_digest_hex(&value);
}
#[tokio::test]
async fn appeal_finance_deposit_reconcile_endpoint_reports_in_progress_and_settled() {
    let auth = orderbook_auth_fixture();
    let request = appeal_finance_deposit_request(
        &auth.provider.account,
        &auth.buyer.account,
        Some(&auth.provider.account),
    );
    let expected =
        appeal_finance_deposit_expectation(request.clone()).expect("valid deposit expectation");
    let (app, _temp_dir, mut native_chain) =
        sorafs_app_state_with_appeal_finance_asset_lock_world(&auth, &expected.asset_definition_id);
    seed_appeal_finance_asset_lock(&mut native_chain, &expected);
    drawdown_appeal_finance_asset_lock(
        &mut native_chain,
        &expected,
        &auth.provider.account,
        iroha_primitives::numeric::Quantity::from_str("210.0").expect("drawdown amount quantity"),
        2,
    );
    let confirmation =
        appeal_finance_deposit_confirm_request(&request, expected.escrow_id.as_hash().to_string());
    let response = post_appeal_finance_deposit_reconcile(
        app.clone(),
        &auth.provider,
        appeal_finance_deposit_settle_body(confirmation.clone(), "frivolous"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["status"]), Some("awaiting_refund_cancel"));
    assert_eq!(value.json_bool(&["reconciled"]), Some(false));
    assert_eq!(value.json_str(&["observed_remaining_amount"]), Some("210"));
    let in_progress_digest = assert_appeal_finance_reconciliation_digest_hex(&value).to_owned();
    cancel_appeal_finance_asset_lock(&mut native_chain, &expected, &auth.provider.account, 3);
    let response = post_appeal_finance_deposit_reconcile(
        app,
        &auth.provider,
        appeal_finance_deposit_settle_body(confirmation, "frivolous"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["status"]), Some("settled"));
    assert_eq!(value.json_bool(&["reconciled"]), Some(true));
    assert_eq!(
        value.json_str(&["observed_lifecycle_status"]),
        Some("cancelled")
    );
    assert_eq!(value.json_str(&["observed_remaining_amount"]), Some("0"));
    let settled_digest = assert_appeal_finance_reconciliation_digest_hex(&value);
    assert_ne!(settled_digest, in_progress_digest);
}
#[tokio::test]
async fn appeal_finance_report_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, _auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let body = appeal_finance_report_body(appeal_finance_report_fixture());
    let response = handle_post_sorafs_appeal_finance_report(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(APPEAL_FINANCE_ROUTE_REPORTS),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn appeal_finance_writes_require_finance_publisher_role() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let report_response = post_appeal_finance_report(
        app.clone(),
        &auth.buyer,
        appeal_finance_report_body(appeal_finance_report_fixture()),
    )
    .await;
    assert_forbidden_role(report_response, SORAFS_APPEAL_FINANCE_PUBLISHER_ROLE).await;
    let rollup_response = post_appeal_finance_weekly_rollup(
        app.clone(),
        &auth.buyer,
        appeal_finance_weekly_rollup_body(appeal_finance_weekly_rollup_fixture()),
    )
    .await;
    assert_forbidden_role(rollup_response, SORAFS_APPEAL_FINANCE_PUBLISHER_ROLE).await;
    assert_eq!(app.sorafs_node.pending_governance_publication_count(), 0);
}
#[tokio::test]
async fn appeal_finance_report_endpoint_publishes_to_governance_dag() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let report = appeal_finance_report_fixture();
    let body = appeal_finance_report_body(report.clone());
    let response = post_appeal_finance_report(app.clone(), &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.report.publish.v1")
    );
    assert_eq!(value.json_str(&["status"]), Some("accepted"));
    let report_id_hex = hex::encode(report.report_id);
    assert_eq!(
        value.json_str(&["report_id_hex"]),
        Some(report_id_hex.as_str())
    );
    let sources = publication_source_paths_fixture(&app, APPEAL_FINANCE_REPORT_KIND);
    assert_eq!(sources.len(), 1);
    assert!(sources[0].0.exists());
    assert!(sources[0].1.exists());
    let index = read_publication_section_fixture(&app, "publish_index");
    assert_eq!(
        index
            .get("by_payload_kind")
            .and_then(|value| value.get(APPEAL_FINANCE_REPORT_KIND))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert_governance_publish_provenance(
        &app,
        APPEAL_FINANCE_REPORT_KIND,
        &auth.provider.account,
        "appeal_finance_report",
    );
}
#[tokio::test]
async fn privacy_aggregate_source_event_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, _auth) = sorafs_app_state_with_orderbook_auth();
    let body = privacy_aggregate_source_event_body(privacy_aggregate_source_event_request(
        "privacy-event-a",
    ));
    let response = handle_post_sorafs_transparency_privacy_aggregate_source_event(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(TRANSPARENCY_PRIVACY_AGGREGATE_SOURCE_EVENTS_ROUTE),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn privacy_aggregate_source_event_endpoint_requires_source_publisher_role() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_orderbook_auth();
    let body = privacy_aggregate_source_event_body(privacy_aggregate_source_event_request(
        "privacy-event-role-denied",
    ));
    let response = post_privacy_aggregate_source_event(app.clone(), &auth.buyer, body).await;
    assert_forbidden_role(response, SORAFS_TRANSPARENCY_SOURCE_PUBLISHER_ROLE).await;
    assert_eq!(app.sorafs_node.privacy_aggregate_source_event_count(), 0);
}
#[tokio::test]
async fn privacy_aggregate_source_event_endpoint_records_event_for_cycle_publication() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_orderbook_auth();
    let body = privacy_aggregate_source_event_body(privacy_aggregate_source_event_request(
        "privacy-event-a",
    ));
    let response = post_privacy_aggregate_source_event(app.clone(), &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.privacy_aggregate_source_event.ingest.v1")
    );
    assert_eq!(value.json_str(&["status"]), Some("recorded"));
    assert_eq!(value.json_str(&["event_id"]), Some("privacy-event-a"));
    assert!(value.get("retained_source_event_count").is_none());
    assert_eq!(app.sorafs_node.privacy_aggregate_source_event_count(), 1);
}
#[tokio::test]
async fn privacy_aggregate_source_event_endpoint_replays_exact_duplicate_event() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_orderbook_auth();
    let request = privacy_aggregate_source_event_request("privacy-event-a");
    let body = privacy_aggregate_source_event_body(request);
    let first =
        post_privacy_aggregate_source_event(app.clone(), &auth.provider, body.clone()).await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let duplicate = post_privacy_aggregate_source_event(app.clone(), &auth.provider, body).await;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let value = api_test_response_json(duplicate).await;
    assert_eq!(value.json_str(&["status"]), Some("already_recorded"));
    assert_eq!(app.sorafs_node.privacy_aggregate_source_event_count(), 1);
}
#[test]
fn privacy_aggregate_source_event_requires_subject_digest() {
    let body = norito::json::to_vec(&norito::json!({
        "event_id": "privacy-event-a",
        "occurred_at_unix": 1_800_000_010_u64,
        "population_label": "jurisdiction-a",
        "metrics": [
            {"key": "appeals_upheld", "value": 1_u64, "unit": "count"}
        ],
    }))
    .expect("encode source event without subject digest");
    let response = privacy_aggregate_source_event_from_body(&body)
        .expect_err("missing subject digest must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[test]
fn privacy_aggregate_publish_due_rejects_caller_supplied_policy() {
    let body = norito::json::to_vec(&norito::json!({
        "now_unix": 211_u64,
        "aggregate_id_prefix": "legacy-caller-policy",
        "privacy_mode": "suppression",
        "suppression_threshold": 1_u64,
    }))
    .expect("encode retired publish-due policy fields");
    let response = privacy_aggregate_publish_due_request_from_body(&body)
        .expect_err("caller-supplied privacy policy must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[test]
fn privacy_aggregate_publish_due_rejects_caller_supplied_prf_output() {
    let body = norito::json::to_vec(&norito::json!({
        "now_unix": 211_u64,
        "cycle_prf_output_hex": ("5a".repeat(32)),
    }))
    .expect("encode retired caller PRF field");
    let response = privacy_aggregate_publish_due_request_from_body(&body)
        .expect_err("caller-supplied PRF output must be rejected as an unknown field");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn privacy_aggregate_publish_due_endpoint_requires_canonical_request_auth() {
    let (app, _temp_dir, _auth) = sorafs_app_state_with_privacy_aggregate_schedule();
    let body = privacy_aggregate_publish_due_body(privacy_aggregate_publish_due_request(211));
    let response = handle_post_sorafs_transparency_privacy_aggregate_publish_due(
        State(app),
        HeaderMap::new(),
        Method::POST,
        Uri::from_static(TRANSPARENCY_PRIVACY_AGGREGATE_PUBLISH_DUE_ROUTE),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn privacy_aggregate_publish_due_endpoint_requires_cycle_publisher_role() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_privacy_aggregate_schedule();
    let body = privacy_aggregate_publish_due_body(privacy_aggregate_publish_due_request(211));
    let response = post_privacy_aggregate_publish_due(app.clone(), &auth.buyer, body).await;
    assert_forbidden_role(response, SORAFS_TRANSPARENCY_CYCLE_PUBLISHER_ROLE).await;
    assert_eq!(app.sorafs_node.pending_governance_publication_count(), 0);
}
#[tokio::test]
async fn privacy_aggregate_publish_due_endpoint_publishes_configured_cycle() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_privacy_aggregate_schedule();
    let source_body = privacy_aggregate_source_event_body(
        privacy_aggregate_source_event_request_at("privacy-event-a", 110),
    );
    let source_response =
        post_privacy_aggregate_source_event(app.clone(), &auth.provider, source_body).await;
    assert_eq!(source_response.status(), StatusCode::ACCEPTED);
    let response = post_privacy_aggregate_publish_due(
        app.clone(),
        &auth.provider,
        privacy_aggregate_publish_due_body(privacy_aggregate_publish_due_request(211)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.transparency.privacy_aggregate.publish_due.v1")
    );
    assert_eq!(value.json_str(&["status"]), Some("published"));
    assert_eq!(value.json_bool(&["published"]), Some(true));
    assert!(value.get("retained_source_event_count").is_none());
    let window = value.json_object(&["window"]).expect("window object");
    assert_eq!(window.json_u64(&["cycle_start_unix"]), Some(100));
    assert_eq!(window.json_u64(&["cycle_end_unix"]), Some(200));
    let publication = value
        .json_object(&["publication"])
        .expect("publication summary");
    assert_eq!(publication.json_u64(&["entry_count"]), Some(1));
    assert_eq!(publication.json_u64(&["proof_count"]), Some(1));
    assert!(
        publication
            .json_str(&["block_hash_hex"])
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_governance_publish_provenance(
        &app,
        TRANSPARENCY_LEDGER_PUBLICATION_KIND,
        &auth.provider.account,
        "privacy_aggregate_publish_due",
    );
    let repeat = post_privacy_aggregate_publish_due(
        app,
        &auth.provider,
        privacy_aggregate_publish_due_body(privacy_aggregate_publish_due_request(211)),
    )
    .await;
    assert_eq!(repeat.status(), StatusCode::OK);
    let value = api_test_response_json(repeat).await;
    assert_eq!(value.json_str(&["status"]), Some("published"));
    assert_eq!(value.json_bool(&["published"]), Some(true));
}
#[tokio::test]
async fn privacy_aggregate_publish_due_endpoint_commits_empty_suppression_window() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_privacy_aggregate_schedule();
    let response = post_privacy_aggregate_publish_due(
        app,
        &auth.provider,
        privacy_aggregate_publish_due_body(privacy_aggregate_publish_due_request(211)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = api_test_response_json(response).await;
    assert_eq!(value.json_str(&["status"]), Some("all_buckets_suppressed"));
    assert_eq!(value.json_bool(&["published"]), Some(false));
}
#[tokio::test]
async fn appeal_finance_weekly_rollup_endpoint_publishes_to_governance_dag() {
    let (app, _temp_dir, auth) = sorafs_app_state_with_appeal_finance_governance_publisher();
    let rollup = appeal_finance_weekly_rollup_fixture();
    let body = appeal_finance_weekly_rollup_body(rollup.clone());
    let response = post_appeal_finance_weekly_rollup(app.clone(), &auth.provider, body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = api_test_response_json(response).await;
    assert_eq!(
        value.json_str(&["schema"]),
        Some("sorafs.appeal_finance.weekly_rollup.publish.v1")
    );
    assert_eq!(value.json_str(&["cycle"]), Some("2026-W26"));
    assert_eq!(value.json_len(&["source_report_ids_hex"]), Some(1));

    let sources = publication_source_paths_fixture(&app, APPEAL_FINANCE_WEEKLY_ROLLUP_KIND);
    assert_eq!(sources.len(), 1);
    assert!(sources[0].0.exists());
    assert!(sources[0].1.exists());
    let index = read_publication_section_fixture(&app, "publish_index");
    assert_eq!(
        index
            .get("by_payload_kind")
            .and_then(|value| value.get(APPEAL_FINANCE_WEEKLY_ROLLUP_KIND))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert_governance_publish_provenance(
        &app,
        APPEAL_FINANCE_WEEKLY_ROLLUP_KIND,
        &auth.provider.account,
        "appeal_finance_weekly_rollup",
    );
}
async fn post_appeal_finance_report(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_REPORTS);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_report(State(app), headers, method, uri, body).await
}
async fn post_privacy_aggregate_source_event(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(TRANSPARENCY_PRIVACY_AGGREGATE_SOURCE_EVENTS_ROUTE);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_transparency_privacy_aggregate_source_event(
        State(app),
        headers,
        method,
        uri,
        body,
    )
    .await
}
async fn post_privacy_aggregate_publish_due(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(TRANSPARENCY_PRIVACY_AGGREGATE_PUBLISH_DUE_ROUTE);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_transparency_privacy_aggregate_publish_due(
        State(app),
        headers,
        method,
        uri,
        body,
    )
    .await
}
async fn post_transparency_proof_token_issuance(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(TRANSPARENCY_PROOF_TOKEN_ISSUANCES_ROUTE);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_transparency_token_issuance(State(app), headers, method, uri, body).await
}
async fn post_appeal_finance_deposit(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSITS);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_deposit(State(app), headers, method, uri, body).await
}
async fn post_appeal_finance_deposit_confirm(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSIT_CONFIRM);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_deposit_confirm(State(app), headers, method, uri, body).await
}
async fn post_appeal_finance_deposit_settle(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSIT_SETTLE);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_deposit_settle(State(app), headers, method, uri, body).await
}
async fn post_appeal_finance_deposit_submit_settlement(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSIT_SUBMIT_SETTLEMENT);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_deposit_submit_settlement(
        State(app),
        headers,
        method,
        uri,
        body,
    )
    .await
}
async fn post_appeal_finance_deposit_reconcile(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_DEPOSIT_RECONCILE);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_deposit_reconcile(State(app), headers, method, uri, body)
        .await
}
async fn get_appeal_finance_deposit(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    escrow_id_hex: &str,
) -> Response {
    let method = Method::GET;
    let uri = format!("{APPEAL_FINANCE_ROUTE_DEPOSITS}/{escrow_id_hex}")
        .parse()
        .expect("deposit status uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &[],
    );
    handle_get_sorafs_appeal_finance_deposit(
        State(app),
        headers,
        method,
        uri,
        Path(escrow_id_hex.to_owned()),
    )
    .await
}
async fn post_appeal_finance_weekly_rollup(
    app: SharedAppState,
    signer: &OrderbookAccountFixture,
    body: Bytes,
) -> Response {
    let method = Method::POST;
    let uri = Uri::from_static(APPEAL_FINANCE_ROUTE_WEEKLY_ROLLUPS);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &signer.account,
        &signer.keypair,
        &method,
        &uri,
        &body,
    );
    handle_post_sorafs_appeal_finance_weekly_rollup(State(app), headers, method, uri, body).await
}
