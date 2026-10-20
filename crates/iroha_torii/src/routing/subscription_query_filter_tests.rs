use iroha_torii_shared::list_query::ListQuery;
// Subscription route and query-filter adapter regressions.
fn sample_subscription_state(
    plan_id: AssetDefinitionId,
    provider: AccountId,
    subscriber: AccountId,
    status: SubscriptionStatus,
    billing_trigger_id: TriggerId,
) -> SubscriptionState {
    SubscriptionState {
        plan_id,
        provider,
        subscriber,
        status,
        current_period_start_ms: 0,
        current_period_end_ms: 1_000,
        next_charge_ms: 1_000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 0,
        usage_accumulated: std::collections::BTreeMap::new(),
        billing_trigger_id,
    }
}
async fn response_json(resp: Response) -> Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    norito::json::from_slice(&body).unwrap()
}
async fn assert_action_draft(
    resp: Response,
    expected_id: &NftId,
    expected_authority: &AccountId,
    expected_action: &str,
    expected_trigger_operation: &str,
) -> Value {
    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    assert_eq!(
        json["version"].as_u64(),
        Some(u64::from(SUBSCRIPTION_MUTATION_DRAFT_VERSION_V1))
    );
    let id_str = expected_id.to_string();
    assert_eq!(json["subscription_id"].as_str(), Some(id_str.as_str()));
    let authority = expected_authority.to_string();
    assert_eq!(json["authority"].as_str(), Some(authority.as_str()));
    assert_eq!(json["action"].as_str(), Some(expected_action));
    assert_eq!(
        json["details"]["billing_trigger_operation"].as_str(),
        Some(expected_trigger_operation)
    );
    assert!(
        json["tx_instructions"]
            .as_array()
            .is_some_and(|instructions| !instructions.is_empty())
    );
    assert!(json.get("ok").is_none());
    assert!(json.get("tx_hash_hex").is_none());
    json
}
fn state_with_plans_and_subscriptions(
    provider: AccountId,
    subscriber: AccountId,
    plans: Vec<(AssetDefinitionId, SubscriptionPlan)>,
    subscriptions: Vec<(NftId, SubscriptionState, Option<SubscriptionInvoice>)>,
) -> Arc<CoreState> {
    let asset_definitions: Vec<AssetDefinition> = plans
        .into_iter()
        .map(|(plan_id, plan)| {
            let mut def = AssetDefinition::new(
                plan_id,
                "subscription_plan".to_owned(),
                NumericSpec::integer(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&provider);
            def.metadata
                .insert((*SUBSCRIPTION_PLAN_KEY).clone(), IrohaJson::new(plan));
            def
        })
        .collect();
    let nfts: Vec<Nft> = subscriptions
        .into_iter()
        .map(|(nft_id, state, invoice)| {
            let mut metadata = Metadata::default();
            metadata.insert((*SUBSCRIPTION_KEY).clone(), IrohaJson::new(state));
            if let Some(invoice) = invoice {
                metadata.insert((*SUBSCRIPTION_INVOICE_KEY).clone(), IrohaJson::new(invoice));
            }
            Nft::new(nft_id, metadata).build(&subscriber)
        })
        .collect();
    state_with_asset_definitions_and_nfts(provider, subscriber, asset_definitions, nfts)
}
fn state_with_asset_definitions_and_nfts(
    provider: AccountId,
    subscriber: AccountId,
    asset_definitions: Vec<AssetDefinition>,
    nfts: Vec<Nft>,
) -> Arc<CoreState> {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id).build(&provider);
    let provider_account = provider.clone();
    let subscriber_account = subscriber.clone();
    let accounts = vec![
        Account::new(provider_account.account().clone()).build(&provider),
        Account::new(subscriber_account.account().clone()).build(&subscriber),
    ];
    let mut world = World::with_assets([domain], accounts, asset_definitions, [], nfts);
    crate::test_utils::bind_fixture_root(
        &mut world,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
    );
    Arc::new(CoreState::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ))
}
#[tokio::test]
async fn handle_v1_subscription_plans_filters_provider() {
    let provider = ALICE_ID.clone();
    let other = BOB_ID.clone();
    let plan_primary_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f4");
    let plan_secondary_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f5");
    let plan_a = SubscriptionPlan {
        provider: provider.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 0,
            max_failures: 0,
            grace_ms: 0,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(10_u32),
            asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f1"),
        }),
    };
    let plan_b = SubscriptionPlan {
        provider: other.clone(),
        ..plan_a.clone()
    };
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        other.clone(),
        vec![
            (plan_primary_id.clone(), plan_a),
            (plan_secondary_id, plan_b),
        ],
        Vec::new(),
    );
    let params = ListQuery {
        filter: Some(FilterExpr::Eq(
            FieldPath("provider".to_owned()),
            Value::from(provider.to_string()),
        )),
        include_total: true,
        ..ListQuery::default()
    };
    let resp = handle_v1_subscription_plans(state, crate::NoritoQuery(params))
        .await
        .expect("handler ok")
        .into_response();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = norito::json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(json["total"].as_u64(), Some(1));
    let plan_id = plan_primary_id.to_string();
    assert_eq!(items[0]["id"].as_str(), Some(plan_id.as_str()));
}
#[tokio::test]
async fn handle_v1_subscription_plans_filters_provider_alias() {
    let provider = ALICE_ID.clone();
    let other = BOB_ID.clone();
    let plan_primary_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554401f4");
    let plan_secondary_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554401f5");
    let plan_a = SubscriptionPlan {
        provider: provider.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 0,
            max_failures: 0,
            grace_ms: 0,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(10_u32),
            asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554401f1"),
        }),
    };
    let plan_b = SubscriptionPlan {
        provider: other.clone(),
        ..plan_a.clone()
    };
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        other.clone(),
        vec![
            (plan_primary_id.clone(), plan_a),
            (plan_secondary_id, plan_b),
        ],
        Vec::new(),
    );
    bind_account_alias_for_test(&state, &provider, "billing@universal");
    let params = ListQuery {
        filter: Some(FilterExpr::Eq(
            FieldPath("provider".to_owned()),
            Value::from("billing@universal".to_string()),
        )),
        include_total: true,
        ..ListQuery::default()
    };
    let rejected = match handle_v1_subscription_plans(state.clone(), crate::NoritoQuery(params))
        .await
    {
        Ok(_) => panic!("public provider filter must not perform unauthenticated alias resolution"),
        Err(error) => error,
    };
    assert!(matches!(
        rejected,
        Error::CollectionQuery(ref error) if error.code == "invalid_filter" && error.message.contains("canonical I105")
    ));
    let resolved =
        resolve_account_alias_with_exact_permission_for_test(&state, &other, "billing@universal");
    assert_eq!(resolved, provider);
    let params = ListQuery {
        filter: Some(FilterExpr::Eq(
            FieldPath("provider".to_owned()),
            Value::from(resolved.to_string()),
        )),
        include_total: true,
        ..ListQuery::default()
    };
    let resp = handle_v1_subscription_plans(state, crate::NoritoQuery(params))
        .await
        .expect("handler ok")
        .into_response();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = norito::json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(json["total"].as_u64(), Some(1));
    let plan_id = plan_primary_id.to_string();
    assert_eq!(items[0]["id"].as_str(), Some(plan_id.as_str()));
}
#[tokio::test]
async fn handle_v1_subscriptions_filters_status() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f6");
    let plan = SubscriptionPlan {
        provider: provider.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 0,
            max_failures: 0,
            grace_ms: 0,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(1_u32),
            asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f1"),
        }),
    };
    let active_id: NftId = "sub-active$wonderland.universal".parse().unwrap();
    let paused_id: NftId = "sub-paused$wonderland.universal".parse().unwrap();
    let active_state = SubscriptionState {
        plan_id: plan_id.clone(),
        provider: provider.clone(),
        subscriber: subscriber.clone(),
        status: SubscriptionStatus::Active,
        current_period_start_ms: 0,
        current_period_end_ms: 1_000,
        next_charge_ms: 1_000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 0,
        usage_accumulated: std::collections::BTreeMap::new(),
        billing_trigger_id: "bill_active".parse().unwrap(),
    };
    let paused_state = SubscriptionState {
        status: SubscriptionStatus::Paused,
        billing_trigger_id: "bill_paused".parse().unwrap(),
        ..active_state.clone()
    };
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        subscriber.clone(),
        vec![(plan_id, plan)],
        vec![
            (active_id.clone(), active_state, None),
            (paused_id.clone(), paused_state, None),
        ],
    );
    let params = ListQuery {
        filter: Some(FilterExpr::And(vec![
            FilterExpr::Eq(
                FieldPath("owned_by".to_owned()),
                Value::from(subscriber.to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("status".to_owned()),
                Value::from("paused".to_string()),
            ),
        ])),
        include_total: false,
        ..ListQuery::default()
    };
    let resp = handle_v1_subscriptions(state, crate::NoritoQuery(params))
        .await
        .expect("handler ok")
        .into_response();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = norito::json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let paused_id_str = paused_id.to_string();
    assert_eq!(items[0]["id"].as_str(), Some(paused_id_str.as_str()));
    assert_eq!(items[0]["status"].as_str(), Some("paused"));
}
#[tokio::test]
async fn handle_v1_subscriptions_filters_account_aliases() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554401f6");
    let plan = SubscriptionPlan {
        provider: provider.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 0,
            max_failures: 0,
            grace_ms: 0,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(1_u32),
            asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554401f1"),
        }),
    };
    let active_id: NftId = "sub-alias-active$wonderland.universal".parse().unwrap();
    let paused_id: NftId = "sub-alias-paused$wonderland.universal".parse().unwrap();
    let active_state = SubscriptionState {
        plan_id: plan_id.clone(),
        provider: provider.clone(),
        subscriber: subscriber.clone(),
        status: SubscriptionStatus::Active,
        current_period_start_ms: 0,
        current_period_end_ms: 1_000,
        next_charge_ms: 1_000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 0,
        usage_accumulated: std::collections::BTreeMap::new(),
        billing_trigger_id: "bill_alias_active".parse().unwrap(),
    };
    let paused_state = SubscriptionState {
        status: SubscriptionStatus::Paused,
        billing_trigger_id: "bill_alias_paused".parse().unwrap(),
        ..active_state.clone()
    };
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        subscriber.clone(),
        vec![(plan_id, plan)],
        vec![
            (active_id, active_state, None),
            (paused_id.clone(), paused_state, None),
        ],
    );
    bind_account_alias_for_test(&state, &provider, "billing@universal");
    bind_account_alias_for_test(&state, &subscriber, "member@universal");
    let params = ListQuery {
        filter: Some(FilterExpr::And(vec![
            FilterExpr::Eq(
                FieldPath("owned_by".to_owned()),
                Value::from("member@universal".to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("provider".to_owned()),
                Value::from("billing@universal".to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("status".to_owned()),
                Value::from("paused".to_string()),
            ),
        ])),
        include_total: false,
        ..ListQuery::default()
    };
    let rejected = match handle_v1_subscriptions(state.clone(), crate::NoritoQuery(params)).await {
        Ok(_) => {
            panic!("public subscriber filter must not perform unauthenticated alias resolution")
        }
        Err(error) => error,
    };
    assert!(matches!(
        rejected,
        Error::CollectionQuery(ref error) if error.code == "invalid_filter" && error.message.contains("canonical I105")
    ));
    let resolved_provider = resolve_account_alias_with_exact_permission_for_test(
        &state,
        &subscriber,
        "billing@universal",
    );
    let resolved_subscriber =
        resolve_account_alias_with_exact_permission_for_test(&state, &provider, "member@universal");
    assert_eq!(resolved_provider, provider);
    assert_eq!(resolved_subscriber, subscriber);
    let provider_alias_only = ListQuery {
        filter: Some(FilterExpr::And(vec![
            FilterExpr::Eq(
                FieldPath("owned_by".to_owned()),
                Value::from(resolved_subscriber.to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("provider".to_owned()),
                Value::from("billing@universal".to_owned()),
            ),
            FilterExpr::Eq(
                FieldPath("status".to_owned()),
                Value::from("paused".to_owned()),
            ),
        ])),
        include_total: false,
        ..ListQuery::default()
    };
    let rejected =
        match handle_v1_subscriptions(state.clone(), crate::NoritoQuery(provider_alias_only)).await
        {
            Ok(_) => {
                panic!("public provider filter must not perform unauthenticated alias resolution")
            }
            Err(error) => error,
        };
    assert!(matches!(
        rejected,
        Error::CollectionQuery(ref error) if error.code == "invalid_filter" && error.message.contains("canonical I105")
    ));
    let params = ListQuery {
        filter: Some(FilterExpr::And(vec![
            FilterExpr::Eq(
                FieldPath("owned_by".to_owned()),
                Value::from(resolved_subscriber.to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("provider".to_owned()),
                Value::from(resolved_provider.to_string()),
            ),
            FilterExpr::Eq(
                FieldPath("status".to_owned()),
                Value::from("paused".to_owned()),
            ),
        ])),
        include_total: false,
        ..ListQuery::default()
    };
    let resp = handle_v1_subscriptions(state, crate::NoritoQuery(params))
        .await
        .expect("handler ok")
        .into_response();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = norito::json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let paused_id_str = paused_id.to_string();
    assert_eq!(items[0]["id"].as_str(), Some(paused_id_str.as_str()));
    assert_eq!(items[0]["status"].as_str(), Some("paused"));
}
#[tokio::test]
async fn handle_v1_subscription_get_includes_invoice() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f7");
    let plan = SubscriptionPlan {
        provider: provider.clone(),
        billing: SubscriptionBilling {
            cadence: SubscriptionCadence::FixedPeriod(SubscriptionFixedPeriodCadence {
                period_ms: 1_000,
            }),
            bill_for: SubscriptionBillFor::NextPeriod,
            retry_backoff_ms: 0,
            max_failures: 0,
            grace_ms: 0,
        },
        pricing: SubscriptionPricing::Fixed(SubscriptionFixedPricing {
            amount: Quantity::from(1_u32),
            asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f1"),
        }),
    };
    let subscription_id: NftId = "sub-invoice$wonderland.universal".parse().unwrap();
    let subscription_state = SubscriptionState {
        plan_id: plan_id.clone(),
        provider: provider.clone(),
        subscriber: subscriber.clone(),
        status: SubscriptionStatus::Active,
        current_period_start_ms: 0,
        current_period_end_ms: 1_000,
        next_charge_ms: 1_000,
        cancel_at_period_end: false,
        cancel_at_ms: None,
        failure_count: 0,
        usage_accumulated: std::collections::BTreeMap::new(),
        billing_trigger_id: "bill_invoice".parse().unwrap(),
    };
    let invoice = SubscriptionInvoice {
        subscription_nft_id: subscription_id.clone(),
        period_start_ms: 0,
        period_end_ms: 1_000,
        attempted_at_ms: 1_000,
        amount: Quantity::from(1_u32),
        asset_definition: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f1"),
        status: SubscriptionInvoiceStatus::Paid,
        tx_hash: None,
    };
    let state = state_with_plans_and_subscriptions(
        provider,
        subscriber,
        vec![(plan_id, plan)],
        vec![(
            subscription_id.clone(),
            subscription_state,
            Some(invoice.clone()),
        )],
    );
    let resp = handle_v1_subscription_get(state, subscription_id.clone())
        .await
        .expect("handler ok")
        .into_response();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = norito::json::from_slice(&body).unwrap();
    let sub_id = subscription_id.to_string();
    assert_eq!(json["subscription_id"].as_str(), Some(sub_id.as_str()));
    let parsed_invoice: SubscriptionInvoice =
        norito::json::from_value(json["invoice"].clone()).unwrap();
    assert_eq!(parsed_invoice, invoice);
}
#[tokio::test]
async fn handle_post_v1_subscription_plan_returns_unsigned_transaction_draft() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let state =
        state_with_plans_and_subscriptions(provider.clone(), subscriber, Vec::new(), Vec::new());
    let queue = test_queue();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f8");
    let plan = sample_plan(provider.clone());
    let req = SubscriptionPlanCreateRequest {
        authority: provider,
        plan_id: plan_id.clone(),
        plan,
    };
    let resp = handle_post_v1_subscription_plan(queue.clone(), state, NoritoJson(req))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(queue.queued_len(), 0);
    let json = response_json(resp).await;
    assert_eq!(json["submitted"].as_bool(), Some(false));
    let plan_id_str = plan_id.to_string();
    assert_eq!(json["plan_id"].as_str(), Some(plan_id_str.as_str()));
    assert!(json["transaction_payload_b64"].as_str().is_some());
    assert!(json["signing_message_b64"].as_str().is_some());
    assert!(json.get("private_key").is_none());
    assert!(json.get("tx_hash_hex").is_none());
}
#[tokio::test]
async fn handle_post_v1_subscription_create_returns_exact_unsigned_draft() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400f9");
    let plan = sample_plan(provider.clone());
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        subscriber.clone(),
        vec![(plan_id.clone(), plan)],
        Vec::new(),
    );
    let subscription_id: NftId = "sub-create$wonderland.universal".parse().unwrap();
    let req = SubscriptionCreateRequest {
        authority: subscriber.clone(),
        subscription_id: subscription_id.clone(),
        plan_id: plan_id.clone(),
        billing_trigger_id: None,
        usage_trigger_id: None,
        first_charge_ms: Some(1_000),
        grant_usage_to_provider: None,
    };
    let resp = handle_post_v1_subscription_create(state, NoritoJson(req))
        .await
        .expect("handler ok")
        .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_json(resp).await;
    assert_eq!(json["version"].as_u64(), Some(1));
    assert_eq!(json["action"].as_str(), Some("create"));
    assert_eq!(
        json["authority"].as_str(),
        Some(subscriber.to_string().as_str())
    );
    let sub_id_str = subscription_id.to_string();
    assert_eq!(json["subscription_id"].as_str(), Some(sub_id_str.as_str()));
    assert_eq!(json["plan_id"].as_str(), Some(plan_id.to_string().as_str()));
    assert_eq!(json["first_charge_ms"].as_u64(), Some(1_000));
    assert_eq!(json["provider_usage_grant_included"].as_bool(), Some(false));
    assert_eq!(
        json["resulting_subscription"]["subscriber"].as_str(),
        Some(subscriber.to_string().as_str())
    );
    assert!(
        json["tx_instructions"]
            .as_array()
            .is_some_and(|instructions| instructions.len() == 2)
    );
    assert!(json.get("ok").is_none());
    assert!(json.get("tx_hash_hex").is_none());
}
#[tokio::test]
async fn handle_post_v1_subscription_actions_return_exact_unsigned_drafts() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400fa");
    let plan = sample_plan(provider.clone());
    let active_id: NftId = "sub-active-actions$wonderland.universal".parse().unwrap();
    let paused_id: NftId = "sub-paused-actions$wonderland.universal".parse().unwrap();
    let active_state = sample_subscription_state(
        plan_id.clone(),
        provider.clone(),
        subscriber.clone(),
        SubscriptionStatus::Active,
        "bill_active_actions".parse().unwrap(),
    );
    let paused_state = sample_subscription_state(
        plan_id.clone(),
        provider.clone(),
        subscriber.clone(),
        SubscriptionStatus::Paused,
        "bill_paused_actions".parse().unwrap(),
    );
    let keep_id: NftId = "sub-keep-actions$wonderland.universal".parse().unwrap();
    let mut keep_state = sample_subscription_state(
        plan_id.clone(),
        provider.clone(),
        subscriber.clone(),
        SubscriptionStatus::Active,
        "bill_keep_actions".parse().unwrap(),
    );
    keep_state.cancel_at_period_end = true;
    keep_state.cancel_at_ms = Some(keep_state.current_period_end_ms);
    let state = state_with_plans_and_subscriptions(
        provider,
        subscriber.clone(),
        vec![(plan_id, plan)],
        vec![
            (active_id.clone(), active_state, None),
            (paused_id.clone(), paused_state, None),
            (keep_id.clone(), keep_state, None),
        ],
    );
    let pause_req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: None,
        cancel_mode: None,
    };
    let resp =
        handle_post_v1_subscription_pause(state.clone(), active_id.clone(), NoritoJson(pause_req))
            .await
            .expect("pause ok")
            .into_response();
    let pause = assert_action_draft(resp, &active_id, &subscriber, "pause", "none").await;
    assert_eq!(
        pause["details"]["resulting_subscription"]["status"]["status"].as_str(),
        Some("paused")
    );
    let resume_req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: Some(5_000),
        cancel_mode: None,
    };
    let resp = handle_post_v1_subscription_resume(
        state.clone(),
        paused_id.clone(),
        NoritoJson(resume_req),
    )
    .await
    .expect("resume ok")
    .into_response();
    let resume = assert_action_draft(resp, &paused_id, &subscriber, "resume", "register").await;
    assert_eq!(
        resume["details"]["effective_charge_ms"].as_u64(),
        Some(5_000)
    );
    let cancel_req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: None,
        cancel_mode: Some(SubscriptionCancelMode::Immediate),
    };
    let resp = handle_post_v1_subscription_cancel(
        state.clone(),
        active_id.clone(),
        NoritoJson(cancel_req),
    )
    .await
    .expect("cancel ok")
    .into_response();
    let cancel = assert_action_draft(resp, &active_id, &subscriber, "cancel", "none").await;
    assert_eq!(
        cancel["details"]["resulting_subscription"]["status"]["status"].as_str(),
        Some("canceled")
    );
    let keep_req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: None,
        cancel_mode: None,
    };
    let resp =
        handle_post_v1_subscription_keep(state.clone(), keep_id.clone(), NoritoJson(keep_req))
            .await
            .expect("keep ok")
            .into_response();
    assert_action_draft(resp, &keep_id, &subscriber, "keep", "none").await;
    let charge_req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: Some(9_000),
        cancel_mode: None,
    };
    let resp = handle_post_v1_subscription_charge_now(
        state.clone(),
        active_id.clone(),
        NoritoJson(charge_req),
    )
    .await
    .expect("charge-now ok")
    .into_response();
    let charge = assert_action_draft(resp, &active_id, &subscriber, "charge_now", "register").await;
    assert_eq!(
        charge["details"]["effective_charge_ms"].as_u64(),
        Some(9_000)
    );
    let queue = test_queue();
    let usage_req = SubscriptionUsageRequest {
        authority: subscriber,
        unit_key: "requests".parse().unwrap(),
        delta: Quantity::from(5_u32),
        usage_trigger_id: None,
    };
    let resp = handle_post_v1_subscription_usage(
        queue.clone(),
        state,
        active_id.clone(),
        NoritoJson(usage_req),
    )
    .await
    .expect("usage ok")
    .into_response();
    assert_eq!(queue.queued_len(), 0);
    assert_eq!(resp.status(), StatusCode::OK);
    let usage = response_json(resp).await;
    assert_eq!(usage["submitted"].as_bool(), Some(false));
    assert_eq!(
        usage["subscription_id"].as_str(),
        Some(active_id.to_string().as_str())
    );
    assert!(usage["transaction_payload_b64"].as_str().is_some());
    assert!(usage["signing_message_b64"].as_str().is_some());
    assert!(usage.get("private_key").is_none());
    assert!(usage.get("tx_hash_hex").is_none());
}
#[tokio::test]
async fn handle_post_v1_subscription_cancel_period_end_marks_cancellation_window() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id: AssetDefinitionId =
        test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554403fa");
    let plan = sample_plan(provider.clone());
    let subscription_id: NftId = "sub-cancel-period-end$wonderland.universal"
        .parse()
        .unwrap();
    let subscription_state = sample_subscription_state(
        plan_id.clone(),
        provider.clone(),
        subscriber.clone(),
        SubscriptionStatus::Active,
        "bill_cancel_period_end".parse().unwrap(),
    );
    let expected_cancel_at_ms = subscription_state.current_period_end_ms;
    let state = state_with_plans_and_subscriptions(
        provider,
        subscriber.clone(),
        vec![(plan_id, plan)],
        vec![(subscription_id.clone(), subscription_state, None)],
    );
    let req = SubscriptionActionRequest {
        authority: subscriber.clone(),
        charge_at_ms: None,
        cancel_mode: Some(SubscriptionCancelMode::PeriodEnd),
    };
    let resp =
        handle_post_v1_subscription_cancel(state.clone(), subscription_id.clone(), NoritoJson(req))
            .await
            .expect("cancel at period end ok")
            .into_response();
    let draft = assert_action_draft(resp, &subscription_id, &subscriber, "cancel", "none").await;
    assert_eq!(
        draft["details"]["resulting_subscription"]["cancel_at_period_end"].as_bool(),
        Some(true)
    );
    assert_eq!(
        draft["details"]["resulting_subscription"]["cancel_at_ms"].as_u64(),
        Some(expected_cancel_at_ms)
    );
    let view = state.view();
    let nft = view
        .world()
        .nft(&subscription_id)
        .expect("subscription nft should exist");
    let updated_state = subscription_state_from_metadata(&nft.content)
        .unwrap()
        .expect("subscription metadata present");
    assert_eq!(updated_state.status, SubscriptionStatus::Active);
    assert!(!updated_state.cancel_at_period_end);
    assert_eq!(updated_state.cancel_at_ms, None);
}
#[test]
fn subscription_mutation_requests_reject_private_key_and_unknown_fields() {
    let plan = SubscriptionPlanCreateRequest {
        authority: ALICE_ID.clone(),
        plan_id: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554404f9"),
        plan: sample_plan(ALICE_ID.clone()),
    };
    let mut plan_value = norito::json::to_value(&plan)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap();
    plan_value.insert(
        "private_key".to_owned(),
        Value::String("forbidden".to_owned()),
    );
    assert!(
        norito::json::from_value::<SubscriptionPlanCreateRequest>(Value::Object(plan_value))
            .is_err()
    );
    let create = SubscriptionCreateRequest {
        authority: BOB_ID.clone(),
        subscription_id: "sub-strict-create$wonderland.universal".parse().unwrap(),
        plan_id: test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554404fa"),
        billing_trigger_id: None,
        usage_trigger_id: None,
        first_charge_ms: Some(1_000),
        grant_usage_to_provider: None,
    };
    let mut create_value = norito::json::to_value(&create)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap();
    create_value.insert(
        "private_key".to_owned(),
        Value::String("forbidden".to_owned()),
    );
    assert!(
        norito::json::from_value::<SubscriptionCreateRequest>(Value::Object(create_value)).is_err()
    );
    let action = SubscriptionActionRequest {
        authority: BOB_ID.clone(),
        charge_at_ms: None,
        cancel_mode: None,
    };
    let mut action_value = norito::json::to_value(&action)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap();
    action_value.insert(
        "legacy_action".to_owned(),
        Value::String("pause".to_owned()),
    );
    assert!(
        norito::json::from_value::<SubscriptionActionRequest>(Value::Object(action_value)).is_err()
    );
    let usage = SubscriptionUsageRequest {
        authority: BOB_ID.clone(),
        unit_key: "requests".parse().unwrap(),
        delta: Quantity::from(1_u32),
        usage_trigger_id: None,
    };
    let mut usage_value = norito::json::to_value(&usage)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap();
    usage_value.insert(
        "private_key".to_owned(),
        Value::String("forbidden".to_owned()),
    );
    assert!(
        norito::json::from_value::<SubscriptionUsageRequest>(Value::Object(usage_value)).is_err()
    );
}
#[test]
fn subscription_cancel_mode_has_one_exact_tagged_shape() {
    assert_eq!(
        norito::json::to_value(&SubscriptionCancelMode::PeriodEnd).unwrap(),
        norito::json!({
            "mode": "period_end",
            "value": null
        })
    );
    assert!(
        norito::json::from_str::<SubscriptionCancelMode>(r#""period_end""#).is_err(),
        "legacy string cancellation modes must not decode"
    );
}
#[tokio::test]
async fn subscription_action_routes_reject_irrelevant_or_defaulted_options() {
    let provider = ALICE_ID.clone();
    let subscriber = BOB_ID.clone();
    let plan_id = test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554405fa");
    let subscription_id: NftId = "sub-strict-action$wonderland.universal".parse().unwrap();
    let state = state_with_plans_and_subscriptions(
        provider.clone(),
        subscriber.clone(),
        vec![(plan_id.clone(), sample_plan(provider.clone()))],
        vec![(
            subscription_id.clone(),
            sample_subscription_state(
                plan_id,
                provider,
                subscriber.clone(),
                SubscriptionStatus::Active,
                "bill_strict_action".parse().unwrap(),
            ),
            None,
        )],
    );
    let pause = handle_post_v1_subscription_pause(
        state.clone(),
        subscription_id.clone(),
        NoritoJson(SubscriptionActionRequest {
            authority: subscriber.clone(),
            charge_at_ms: Some(1_000),
            cancel_mode: None,
        }),
    )
    .await;
    assert!(pause.is_err(), "pause must reject charge options");
    let cancel = handle_post_v1_subscription_cancel(
        state,
        subscription_id,
        NoritoJson(SubscriptionActionRequest {
            authority: subscriber,
            charge_at_ms: None,
            cancel_mode: None,
        }),
    )
    .await;
    assert!(
        cancel.is_err(),
        "cancel must not default an omitted cancellation mode"
    );
}
