// Appeal-finance and authenticated publisher endpoint test support.
struct OrderbookAccountFixture {
    account: AccountId,
    keypair: KeyPair,
}
struct OrderbookAuthFixture {
    provider: OrderbookAccountFixture,
    buyer: OrderbookAccountFixture,
}
fn orderbook_account(seed: u8) -> OrderbookAccountFixture {
    let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("derive orderbook auth fixture keypair");
    let account = AccountId::of(keypair.public_key().clone());
    OrderbookAccountFixture { account, keypair }
}
fn orderbook_auth_fixture() -> OrderbookAuthFixture {
    OrderbookAuthFixture {
        provider: orderbook_account(0xA1),
        buyer: orderbook_account(0xB1),
    }
}
fn orderbook_world(auth: &OrderbookAuthFixture) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&auth.provider.account);
    let provider = Account::new(auth.provider.account.clone()).build(&auth.provider.account);
    let buyer = Account::new(auth.buyer.account.clone()).build(&auth.buyer.account);
    World::with([domain], [provider, buyer], [])
}
fn orderbook_world_with_appeal_finance_asset(auth: &OrderbookAuthFixture) -> World {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id).build(&auth.provider.account);
    let provider = Account::new(auth.provider.account.clone()).build(&auth.provider.account);
    let buyer = Account::new(auth.buyer.account.clone()).build(&auth.buyer.account);
    let asset_definition_id =
        iroha_config::parameters::defaults::torii::sorafs_appeal_finance::asset_definition_id();
    let asset_definition = AssetDefinition::new(
        asset_definition_id.clone(),
        "XOR".to_owned(),
        iroha_primitives::numeric::NumericSpec::fractional(9),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&auth.provider.account);
    let provider_asset = Asset::new(
        AssetId::of(asset_definition_id, auth.provider.account.clone()),
        Quantity::from(1_000_u32),
    );
    World::with_assets(
        [domain],
        [provider, buyer],
        [asset_definition],
        [provider_asset],
        [],
    )
}
fn orderbook_world_with_moderation_operator(auth: &OrderbookAuthFixture) -> World {
    let mut world = orderbook_world_with_appeal_finance_asset(auth);
    world.grant_role_for_tests(
        auth.provider.account.clone(),
        sorafs_moderation_operator_role_id().clone(),
    );
    world
}
fn grant_governance_publication_roles(world: &mut World, auth: &OrderbookAuthFixture) {
    for role in [
        sorafs_transparency_source_publisher_role_id(),
        sorafs_transparency_cycle_publisher_role_id(),
        sorafs_appeal_finance_publisher_role_id(),
    ] {
        world.grant_role_for_tests(auth.provider.account.clone(), role.clone());
    }
}
fn orderbook_world_with_governance_publishers(auth: &OrderbookAuthFixture) -> World {
    let mut world = orderbook_world(auth);
    grant_governance_publication_roles(&mut world, auth);
    world
}
fn orderbook_world_with_appeal_finance_publisher(auth: &OrderbookAuthFixture) -> World {
    let mut world = orderbook_world_with_appeal_finance_asset(auth);
    grant_governance_publication_roles(&mut world, auth);
    world
}
fn sorafs_app_state_with_orderbook_auth() -> (SharedAppState, TempDir, OrderbookAuthFixture) {
    let auth = orderbook_auth_fixture();
    let mut app =
        mk_app_state_for_tests_with_world(orderbook_world_with_governance_publishers(&auth));
    let (node, temp_dir) = sorafs_node_with_temp_storage();
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, auth)
}
fn sorafs_app_state_with_orderbook_auth_without_screening_authority()
-> (SharedAppState, TempDir, OrderbookAuthFixture) {
    let auth = orderbook_auth_fixture();
    let mut app = mk_app_state_for_tests_with_world(orderbook_world(&auth));
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let temp_root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize orderbook auth temp dir");
    let cfg = StorageConfig::builder()
        .enabled(true)
        .data_dir(temp_root.join("storage"))
        .moderation_quarantine_key_provider(Some(torii_test_quarantine_key_provider_config()))
        .build();
    let node = sorafs_node::NodeHandle::try_new_with_quarantine_key_wrapper(
        cfg,
        torii_test_quarantine_key_wrapper(),
    )
    .expect("initialise test node without screening authority");
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, auth)
}
fn sorafs_app_state_with_moderation_operator_auth()
-> (SharedAppState, TempDir, OrderbookAuthFixture) {
    let auth = orderbook_auth_fixture();
    let mut app =
        mk_app_state_for_tests_with_world(orderbook_world_with_moderation_operator(&auth));
    let (node, temp_dir) = sorafs_node_with_temp_storage();
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, auth)
}
fn sorafs_app_state_with_appeal_finance_governance_publisher()
-> (SharedAppState, TempDir, OrderbookAuthFixture) {
    let auth = orderbook_auth_fixture();
    let mut app =
        mk_app_state_for_tests_with_world(orderbook_world_with_appeal_finance_publisher(&auth));
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let temp_root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize appeal finance governance temp dir");
    let governance_dir = temp_root.join("governance");
    fs::create_dir_all(&governance_dir).expect("create governance dir");
    let node = node_with_test_governance_publisher(
        StorageConfig::builder()
            .enabled(true)
            .data_dir(temp_root.join("storage"))
            .governance_dir(Some(governance_dir)),
        NodeRuntimeDeps::default(),
    );
    assert!(node.has_governance_publisher());
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, auth)
}
fn sorafs_app_state_with_privacy_aggregate_schedule()
-> (SharedAppState, TempDir, OrderbookAuthFixture) {
    #[derive(Default)]
    struct TestPrivacyReleaseAnchor {
        heads: Mutex<BTreeMap<[u8; 32], PrivacyReleaseAnchorHeadV1>>,
    }
    impl PrivacyReleaseAnchorV1 for TestPrivacyReleaseAnchor {
        fn finalized_head(
            &self,
            query_id: [u8; 32],
        ) -> Result<PrivacyReleaseAnchorHeadV1, PrivacyReleaseAnchorErrorV1> {
            Ok(self
                .heads
                .lock()
                .map_err(|_| PrivacyReleaseAnchorErrorV1::Internal)?
                .get(&query_id)
                .copied()
                .unwrap_or_else(|| PrivacyReleaseAnchorHeadV1::genesis(query_id)))
        }
        fn compare_and_set_finalized_head(
            &self,
            expected: PrivacyReleaseAnchorHeadV1,
            next: PrivacyReleaseAnchorHeadV1,
            _lease: &sorafs_node::TransparencyLeaderLeaseGrantV1,
        ) -> Result<(), PrivacyReleaseAnchorErrorV1> {
            if expected.query_id() != next.query_id()
                || next.sequence() != expected.sequence().saturating_add(1)
            {
                return Err(PrivacyReleaseAnchorErrorV1::InvalidState);
            }
            let mut heads = self
                .heads
                .lock()
                .map_err(|_| PrivacyReleaseAnchorErrorV1::Internal)?;
            let current = heads
                .get(&expected.query_id())
                .copied()
                .unwrap_or_else(|| PrivacyReleaseAnchorHeadV1::genesis(expected.query_id()));
            if current != expected {
                return Err(PrivacyReleaseAnchorErrorV1::Conflict);
            }
            heads.insert(next.query_id(), next);
            Ok(())
        }
    }
    impl ProductionTransparencyRuntimeProviderV1 for TestPrivacyReleaseAnchor {
        fn handle(&self) -> &'static str {
            "governance-dag:transparency:primary"
        }
        fn qualification(&self) -> Result<TransparencyRuntimeProviderQualificationV1, String> {
            Ok(TransparencyRuntimeProviderQualificationV1::new(
                1, [0xD7; 32],
            ))
        }
    }
    #[derive(Default)]
    struct TestTransparencyLeaderLeaseProvider {
        active: Mutex<Option<sorafs_node::TransparencyLeaderLeaseGrantV1>>,
        fencing_token: AtomicU64,
    }
    impl ProductionTransparencyRuntimeProviderV1 for TestTransparencyLeaderLeaseProvider {
        fn handle(&self) -> &'static str {
            "sealed-cas:transparency:leader-primary"
        }
        fn qualification(&self) -> Result<TransparencyRuntimeProviderQualificationV1, String> {
            Ok(TransparencyRuntimeProviderQualificationV1::new(
                1, [0xE7; 32],
            ))
        }
    }
    impl sorafs_node::TransparencyLeaderLeaseProviderV1 for TestTransparencyLeaderLeaseProvider {
        fn acquire(
            &self,
            request: &sorafs_node::TransparencyLeaderLeaseAcquireRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseGrantV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            let mut active = self
                .active
                .lock()
                .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
            if active
                .as_ref()
                .is_some_and(|grant| request.acquire_at_unix() < grant.expires_at_unix())
            {
                return Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Conflict);
            }
            let fencing_token = self
                .fencing_token
                .load(Ordering::SeqCst)
                .max(request.fencing_floor())
                .checked_add(1)
                .ok_or(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
            self.fencing_token.store(fencing_token, Ordering::SeqCst);
            let mut lease_id = [0xA7; 32];
            lease_id[..8].copy_from_slice(&fencing_token.to_le_bytes());
            let grant = sorafs_node::TransparencyLeaderLeaseGrantV1::try_new(
                lease_id,
                request.scope(),
                fencing_token,
                request.acquire_at_unix(),
                request.expires_at_unix(),
                TransparencyRuntimeProviderBindingV1::try_new(
                    "sealed-cas:transparency:leader-primary",
                    1,
                    [0xE7; 32],
                )
                .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?,
            )
            .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
            *active = Some(grant.clone());
            Ok(grant)
        }
        fn renew(
            &self,
            _request: &sorafs_node::TransparencyLeaderLeaseRenewRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseGrantV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)
        }
        fn release(
            &self,
            request: &sorafs_node::TransparencyLeaderLeaseReleaseRequestV1,
        ) -> Result<
            sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1,
            sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
        > {
            let mut active = self
                .active
                .lock()
                .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?;
            if active.as_ref() != Some(request.current_grant()) {
                return Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Conflict);
            }
            let grant = active
                .take()
                .ok_or(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Conflict)?;
            sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1::try_new(
                grant.lease_id(),
                grant.scope(),
                grant.fencing_token(),
                request.release_at_unix(),
                TransparencyRuntimeProviderBindingV1::try_new(
                    "sealed-cas:transparency:leader-primary",
                    1,
                    [0xE7; 32],
                )
                .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)?,
            )
            .map_err(|_| sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)
        }
    }
    let auth = orderbook_auth_fixture();
    let mut app =
        mk_app_state_for_tests_with_world(orderbook_world_with_governance_publishers(&auth));
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let temp_root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize privacy aggregate temp dir");
    let governance_dir = temp_root.join("governance");
    fs::create_dir_all(&governance_dir).expect("create governance dir");
    let node = node_with_test_governance_publisher(
        StorageConfig::builder()
            .enabled(true)
            .provider_id(Some(iroha_data_model::sorafs::capacity::ProviderId::new(
                [0x91; 32],
            )))
            .data_dir(temp_root.join("storage"))
            .governance_dir(Some(governance_dir))
            .privacy_aggregate_schedule(Some(sorafs_node::PrivacyAggregateScheduleConfig {
                first_cycle_start_unix: 100,
                cycle_seconds: 100,
                publish_delay_seconds: 10,
            }))
            .privacy_aggregate_policy(Some(privacy_aggregate_api_policy_config()))
            .privacy_release_anchor_provider_binding(Some(
                TransparencyRuntimeProviderBindingV1::try_new(
                    "governance-dag:transparency:primary",
                    1,
                    [0xD7; 32],
                )
                .expect("valid test release-anchor provider binding"),
            ))
            .privacy_leader_lease_provider_binding(Some(
                TransparencyRuntimeProviderBindingV1::try_new(
                    "sealed-cas:transparency:leader-primary",
                    1,
                    [0xE7; 32],
                )
                .expect("valid test leader-lease provider binding"),
            ))
            .privacy_fenced_publisher_binding(Some(
                TransparencyRuntimeProviderBindingV1::try_new(
                    ApiTestFencedPrivacyProvider::HANDLE,
                    1,
                    [0x86; 32],
                )
                .expect("valid test fused privacy target binding"),
            )),
        with_test_fenced_privacy_runtime(
            NodeRuntimeDeps::default()
                .with_privacy_release_anchor(Arc::new(TestPrivacyReleaseAnchor::default()))
                .with_transparency_leader_lease_provider(Arc::new(
                    TestTransparencyLeaderLeaseProvider::default(),
                )),
        ),
    );
    assert!(node.has_governance_publisher());
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, auth)
}
fn appeal_finance_report_fixture() -> SoraFsAppealFinanceReportV1 {
    SoraFsAppealFinanceReportV1 {
        version: SORAFS_APPEAL_FINANCE_REPORT_VERSION_V1,
        report_id: [0x42; 16],
        case_id: "case-42".to_string(),
        round_id: Some("round-1".to_string()),
        generated_at_unix_ms: 1_800_000_031_000,
        appeal_finance_config_version: "baseline-v1".to_string(),
        evidence_bundle_digest: Some([0xA7; 32]),
        outcome: SoraFsAppealFinanceOutcomeV1::Overturn,
        deposit_xor: "420".parse().expect("canonical XOR amount"),
        refund: SoraFsAppealFinanceAccountFlowV1 {
            account_id: "refund-account".to_string(),
            amount_xor: "420".parse().expect("canonical XOR amount"),
        },
        treasury: SoraFsAppealFinanceAccountFlowV1 {
            account_id: "treasury-account".to_string(),
            amount_xor: "50".parse().expect("canonical XOR amount"),
        },
        held: SoraFsAppealFinanceAccountFlowV1 {
            account_id: "escrow-account".to_string(),
            amount_xor: "0".parse().expect("canonical XOR amount"),
        },
        panel_size: 3,
        panel_reward_total_xor: "85".parse().expect("canonical XOR amount"),
        rewards_paid_total_xor: "60".parse().expect("canonical XOR amount"),
        rewards_forfeited_treasury_xor: "25".parse().expect("canonical XOR amount"),
        juror_payouts: vec![
            SoraFsAppealFinanceJurorPayoutV1 {
                juror_id: "juror-a".to_string(),
                stipend_xor: "25".parse().expect("canonical XOR amount"),
                bonus_xor: "5".parse().expect("canonical XOR amount"),
                total_xor: "30".parse().expect("canonical XOR amount"),
            },
            SoraFsAppealFinanceJurorPayoutV1 {
                juror_id: "juror-b".to_string(),
                stipend_xor: "25".parse().expect("canonical XOR amount"),
                bonus_xor: "5".parse().expect("canonical XOR amount"),
                total_xor: "30".parse().expect("canonical XOR amount"),
            },
        ],
        no_show_juror_ids: vec!["juror-c".to_string()],
    }
}
fn appeal_finance_weekly_rollup_fixture() -> SoraFsAppealFinanceWeeklyRollupV1 {
    let report = appeal_finance_report_fixture();
    SoraFsAppealFinanceWeeklyRollupV1::from_reports(
        PorReportIsoWeek {
            year: 2026,
            week: 26,
        },
        1_800_000_100_000,
        &[report],
    )
    .expect("appeal finance weekly rollup fixture")
}
fn appeal_finance_report_body(report: SoraFsAppealFinanceReportV1) -> Bytes {
    Bytes::from(norito::json::to_vec(&report).expect("encode appeal finance report"))
}
fn assert_governance_publish_provenance(
    app: &SharedAppState,
    payload_kind: &str,
    publisher_account: &AccountId,
    origin: &str,
) {
    let index = read_publication_section_fixture(app, "publish_index");
    let labels = index
        .json_array(&["entries"])
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.json_str(&["payload_kind"]) == Some(payload_kind))
        })
        .and_then(|entry| entry.get("labels"))
        .and_then(Value::as_object)
        .expect("authenticated governance publish labels");
    let expected_account_digest = encode(
        sorafs_manifest::governance_dag_submission_account_digest_v1(&publisher_account.encode()),
    );
    assert_eq!(
        labels.json_str(&["authenticated_publisher_account_digest_hex"]),
        Some(expected_account_digest.as_str())
    );
    assert_eq!(
        labels.json_str(&["authenticated_publisher_origin"]),
        Some(origin)
    );
}
async fn assert_forbidden_role(response: Response, required_role: &str) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let value = api_test_response_json(response).await;
    assert!(
        value
            .json_str(&["error"])
            .is_some_and(|message| message.contains(required_role)),
        "forbidden response must name the exact required role"
    );
}
fn privacy_aggregate_source_event_request(
    event_id: &str,
) -> TransparencyPrivacyAggregateSourceEventRequestDto {
    privacy_aggregate_source_event_request_at(event_id, 1_800_000_010)
}
fn privacy_aggregate_source_event_request_at(
    event_id: &str,
    occurred_at_unix: u64,
) -> TransparencyPrivacyAggregateSourceEventRequestDto {
    TransparencyPrivacyAggregateSourceEventRequestDto {
        event_id: event_id.to_string(),
        occurred_at_unix,
        population_label: "jurisdiction-a".to_string(),
        population_digest_hex: hex::encode([0xA0; 32]),
        subject_digest_hex: hex::encode(blake3::hash(event_id.as_bytes()).as_bytes()),
        metrics: vec![
            TransparencyPrivacyAggregateSourceMetricDto {
                key: "appeals_upheld".to_string(),
                value: 1,
                unit: "count".to_string(),
            },
            TransparencyPrivacyAggregateSourceMetricDto {
                key: "moderation_actions".to_string(),
                value: 3,
                unit: "count".to_string(),
            },
        ],
        policy_digest_hex: hex::encode([0xC0; 32]),
    }
}
fn privacy_aggregate_source_event_body(
    request: TransparencyPrivacyAggregateSourceEventRequestDto,
) -> Bytes {
    Bytes::from(
        norito::json::to_vec(&request).expect("encode privacy aggregate source event request"),
    )
}
fn privacy_aggregate_publish_due_request(
    _now_unix: u64,
) -> TransparencyPrivacyAggregatePublishDueRequestDto {
    TransparencyPrivacyAggregatePublishDueRequestDto {
        expected_cycle_id_hex: hex::encode(sorafs_node::privacy_aggregate_cycle_id(
            [0xB0; 32], 100, 200,
        )),
        idempotency_key: "privacy-publish-cycle-1".to_string(),
    }
}
fn privacy_aggregate_publish_due_body(
    request: TransparencyPrivacyAggregatePublishDueRequestDto,
) -> Bytes {
    Bytes::from(
        norito::json::to_vec(&request).expect("encode privacy aggregate publish due request"),
    )
}
fn privacy_aggregate_api_cycle_config() -> sorafs_node::PrivacyAggregateCycleConfig {
    sorafs_node::PrivacyAggregateCycleConfig {
        query_id: [0xB0; 32],
        first_cycle_start_unix: 100,
        cycle_seconds: 100,
        aggregate_id_prefix: "torii-source".to_string(),
        populations: vec![sorafs_node::PrivacyAggregatePopulationV1 {
            label: "jurisdiction-a".to_string(),
            digest: [0xA0; 32],
        }],
        metrics: vec![
            sorafs_node::PrivacyAggregateMetricSchemaV1 {
                key: "appeals_upheld".to_string(),
                unit: "count".to_string(),
            },
            sorafs_node::PrivacyAggregateMetricSchemaV1 {
                key: "moderation_actions".to_string(),
                unit: "count".to_string(),
            },
        ],
        privacy: iroha_data_model::sorafs::transparency::ModerationPrivacyParametersV1 {
            version:
                iroha_data_model::sorafs::transparency::MODERATION_PRIVACY_PARAMETERS_VERSION_V1,
            mode: iroha_data_model::sorafs::transparency::ModerationPrivacyModeV1::Suppression,
            epsilon_numerator: None,
            epsilon_denominator: None,
            delta_ppb: None,
            per_subject_metric_cap: None,
            suppression_threshold: Some(1),
        },
        policy_digest: [0xC0; 32],
        metadata: Vec::new(),
    }
}
fn privacy_aggregate_api_policy_config() -> sorafs_node::config::PrivacyAggregatePolicyConfig {
    let cycle = privacy_aggregate_api_cycle_config();
    sorafs_node::config::PrivacyAggregatePolicyConfig::new(
        cycle,
        sorafs_node::PrivacyCompositionBudgetPolicyV1 {
            budget_id: [0xB0; 32],
            epsilon_limit_numerator: 10,
            epsilon_limit_denominator: 1,
            max_publications: 10,
        },
    )
    .expect("privacy API test policy")
}
fn appeal_finance_weekly_rollup_body(rollup: SoraFsAppealFinanceWeeklyRollupV1) -> Bytes {
    Bytes::from(norito::json::to_vec(&rollup).expect("encode appeal finance weekly rollup"))
}
fn appeal_finance_deposit_request(
    payer_account: &AccountId,
    destination_account: &AccountId,
    release_authority_account: Option<&AccountId>,
) -> AppealFinanceDepositRequestDto {
    let asset_definition_id =
        iroha_config::parameters::defaults::torii::sorafs_appeal_finance::asset_definition_id();
    AppealFinanceDepositRequestDto {
        case_id: "case-42".to_owned(),
        round_id: Some("round-1".to_owned()),
        payer_account: payer_account.to_string(),
        destination_account: destination_account.to_string(),
        release_authority_account: release_authority_account.map(ToString::to_string),
        asset_definition_id: asset_definition_id.to_string(),
        deposit_xor: "420".parse().expect("canonical XOR amount"),
        expires_at_ms: Some(1_800_086_400_000),
        idempotency_key: "deposit-attempt-1".to_owned(),
        evidence_hashes_hex: Some(vec![Hash::prehashed([0xD1; Hash::LENGTH]).to_string()]),
    }
}
fn appeal_finance_deposit_body(req: AppealFinanceDepositRequestDto) -> Bytes {
    Bytes::from(norito::json::to_vec(&req).expect("encode appeal finance deposit request"))
}
fn appeal_finance_deposit_confirm_request(
    req: &AppealFinanceDepositRequestDto,
    escrow_id_hex: String,
) -> AppealFinanceDepositConfirmRequestDto {
    AppealFinanceDepositConfirmRequestDto {
        escrow_id_hex,
        case_id: req.case_id.clone(),
        round_id: req.round_id.clone(),
        payer_account: req.payer_account.clone(),
        destination_account: req.destination_account.clone(),
        release_authority_account: req.release_authority_account.clone(),
        asset_definition_id: req.asset_definition_id.clone(),
        deposit_xor: req.deposit_xor.clone(),
        expires_at_ms: req.expires_at_ms,
        idempotency_key: req.idempotency_key.clone(),
        evidence_hashes_hex: req.evidence_hashes_hex.clone(),
    }
}
fn appeal_finance_deposit_confirm_body(req: AppealFinanceDepositConfirmRequestDto) -> Bytes {
    Bytes::from(
        norito::json::to_vec(&req).expect("encode appeal finance deposit confirmation request"),
    )
}
fn appeal_finance_deposit_settle_body(
    deposit_confirmation: AppealFinanceDepositConfirmRequestDto,
    outcome: &str,
) -> Bytes {
    let req = AppealFinanceDepositSettleRequestDto {
        deposit_confirmation,
        outcome: outcome.to_owned(),
        panel_size: Some(7),
    };
    Bytes::from(
        norito::json::to_vec(&req).expect("encode appeal finance deposit settlement request"),
    )
}
fn assert_appeal_finance_reconciliation_digest_hex(value: &Value) -> &str {
    let digest = value
        .json_str(&["reconciliation_digest_hex"])
        .expect("reconciliation digest hex");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    digest
}
fn assert_hex_32(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
}
struct TestAppealFinanceRuntimeSigner {
    handle: String,
    keypair: KeyPair,
}
impl crate::SoraFsAppealFinanceTransactionSigner for TestAppealFinanceRuntimeSigner {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn public_key(&self) -> Result<PublicKey, crate::SoraFsAppealFinanceSigningError> {
        Ok(self.keypair.public_key().clone())
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1,
        crate::SoraFsAppealFinanceSigningError,
    >{
        Ok(
            sorafs_node::appeal_finance_transaction_forwarder::AppealFinanceRuntimeProviderQualificationV1::new(
                1, [0xA1; 32],
            ),
        )
    }
    fn sign(
        &self,
        payload: iroha_data_model::transaction::TransactionPayload,
    ) -> Result<SignedTransaction, crate::SoraFsAppealFinanceSigningError> {
        TransactionBuilder::from_payload(payload)
            .and_then(|builder| builder.try_sign(self.keypair.private_key()))
            .map_err(|_| crate::SoraFsAppealFinanceSigningError::Refused)
    }
}
#[derive(Debug)]
struct TestAppealFinanceCheckpointRuntime {
    identity: AppealFinanceCheckpointRuntimeIdentityV1,
    signing_key: SigningKey,
    latest: Mutex<Option<AppealFinanceSealedCheckpointRecordV1>>,
}
impl TestAppealFinanceCheckpointRuntime {
    fn new(seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        Self {
            identity: AppealFinanceCheckpointRuntimeIdentityV1 {
                provider_handle: "provider:appeal-finance-checkpoint-primary".to_owned(),
                public_key: signing_key.verifying_key().to_bytes(),
                qualification: AppealFinanceRuntimeProviderQualificationV1::new(1, [seed; 32]),
            },
            signing_key,
            latest: Mutex::new(None),
        }
    }
    fn authentication_policy(&self) -> AppealFinanceCheckpointAuthenticationPolicyV1 {
        AppealFinanceCheckpointAuthenticationPolicyV1 {
            version: APPEAL_FINANCE_CHECKPOINT_AUTHENTICATION_POLICY_VERSION_V1,
            provider_handle: self.identity.provider_handle.clone(),
            public_key: self.identity.public_key,
            revision: self.identity.qualification.revision,
            policy_digest: self.identity.qualification.policy_digest,
        }
    }
}
impl AppealFinanceCheckpointRuntime for TestAppealFinanceCheckpointRuntime {
    fn identity(
        &self,
    ) -> Result<AppealFinanceCheckpointRuntimeIdentityV1, AppealFinanceCheckpointExternalError>
    {
        Ok(self.identity.clone())
    }
    fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<[u8; 64], AppealFinanceCheckpointExternalError> {
        Ok(self.signing_key.sign(&digest).to_bytes())
    }
    fn load_latest(
        &self,
    ) -> Result<Option<AppealFinanceSealedCheckpointRecordV1>, AppealFinanceCheckpointExternalError>
    {
        self.latest
            .lock()
            .map(|latest| latest.clone())
            .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)
    }
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &AppealFinanceSealedCheckpointRecordV1,
    ) -> Result<(), AppealFinanceCheckpointExternalError> {
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| AppealFinanceCheckpointExternalError::Unavailable)?;
        if latest.as_ref().map(|record| record.revision) != expected_revision
            || latest
                .as_ref()
                .map_or(1, |record| record.checkpoint_sequence.saturating_add(1))
                != next.checkpoint_sequence
        {
            return Err(AppealFinanceCheckpointExternalError::Rejected);
        }
        *latest = Some(next.clone());
        Ok(())
    }
}
fn configure_appeal_finance_settlement_submitter(
    app: &mut SharedAppState,
    signer: &OrderbookAccountFixture,
    state_root: &std::path::Path,
) {
    let handle = "provider:appeal-finance-a".to_owned();
    let runtime_signer: Arc<dyn crate::SoraFsAppealFinanceTransactionSigner> =
        Arc::new(TestAppealFinanceRuntimeSigner {
            handle: handle.clone(),
            keypair: signer.keypair.clone(),
        });
    let runtime_signers = crate::SoraFsAppealFinanceRuntimeSignersV1::new(vec![runtime_signer])
        .expect("valid test appeal-finance runtime signer");
    let checkpoint_runtime = Arc::new(TestAppealFinanceCheckpointRuntime::new(0xC5));
    let checkpoint_authentication = checkpoint_runtime.authentication_policy();
    let forwarder = AppealFinanceTransactionForwarder::open(
        &state_root.join("appeal-finance-transaction-forwarder"),
        AppealFinanceTransactionForwarderPolicyV1 {
            max_pending: 32,
            max_completed: 64,
            max_dead_letters: 16,
            max_attempts: 3,
            max_transaction_bytes: APPEAL_FINANCE_TRANSACTION_MAX_CANONICAL_BYTES_V1,
            checkpoint_max_bytes: 8 * 1024 * 1024,
        },
        checkpoint_authentication,
        checkpoint_runtime,
    )
    .expect("durable appeal-finance forwarder");
    let app_inner = Arc::get_mut(app).expect("unique app state");
    app_inner.sorafs_appeal_settlement_submitter = Some(crate::SoraFsAppealSettlementSubmitter {
        bindings: vec![
            iroha_config::parameters::actual::SorafsAppealFinanceSignerBinding {
                handle,
                authority: signer.account.clone(),
                public_key: signer.keypair.public_key().clone(),
                revision: 1,
                policy_digest: [0xA1; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: None,
            },
        ],
        runtime_signers: Some(Arc::new(runtime_signers)),
        forwarder,
        worker_scan_interval: Duration::from_millis(30_000),
    });
}
fn appeal_finance_deposit_status_record(
    seller: AccountId,
    buyer: Option<AccountId>,
    release_authority: Option<AccountId>,
) -> AssetEscrowRecord {
    let asset_definition_id =
        iroha_config::parameters::defaults::torii::sorafs_appeal_finance::asset_definition_id();
    AssetEscrowRecord {
        id: EscrowId::new(Hash::new("appeal deposit status fixture")),
        seller: seller.clone(),
        buyer,
        asset_definition: asset_definition_id,
        amount: Quantity::from(420_u32),
        custody: seller,
        status: AssetEscrowStatus::Locked,
        kind: AssetEscrowKind::Lock,
        remaining_amount: Quantity::from(420_u32),
        release_authority,
        expires_at_ms: Some(1_800_086_400_000),
        evidence_hashes: vec![Hash::new("appeal deposit status evidence")],
        conditions: Vec::new(),
        created_at_ms: 1_800_000_001_000,
        accepted_at_ms: None,
        payment_sent_at_ms: None,
        disputed_at_ms: None,
        closed_at_ms: None,
        resolution: None,
    }
}
fn appeal_finance_asset_lock_world(
    auth: &OrderbookAuthFixture,
    asset_definition_id: &AssetDefinitionId,
) -> World {
    appeal_finance_asset_lock_world_with_scale(auth, asset_definition_id, 9)
}
fn appeal_finance_asset_lock_world_with_scale(
    auth: &OrderbookAuthFixture,
    asset_definition_id: &AssetDefinitionId,
    scale: u32,
) -> World {
    let asset_definition = AssetDefinition::new(
        asset_definition_id.clone(),
        "XOR".to_owned(),
        iroha_primitives::numeric::NumericSpec::fractional(scale),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&auth.provider.account);
    let seller_asset_id = AssetId::of(asset_definition_id.clone(), auth.provider.account.clone());
    let seller_asset = Asset::new(seller_asset_id, Quantity::from(1_000_u32));
    World::with_assets(
        [],
        [
            Account::new(auth.provider.account.clone()).build(&auth.provider.account),
            Account::new(auth.buyer.account.clone()).build(&auth.buyer.account),
        ],
        [asset_definition],
        [seller_asset],
        [],
    )
}
fn sorafs_app_state_with_appeal_finance_asset_lock_world(
    auth: &OrderbookAuthFixture,
    asset_definition_id: &AssetDefinitionId,
) -> (
    SharedAppState,
    TempDir,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    let config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        appeal_finance_asset_lock_world(auth, asset_definition_id),
        1,
    );
    let prepared = iroha_core::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("original appeal asset-lock genesis");
    let validator = prepared.validator_keys[0].clone();
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
        .expect("execute appeal asset-lock genesis");
    let mut app = mk_app_state_for_tests();
    {
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.chain_id = Arc::new(chain.state().view().chain_id().clone());
        inner.signed_query_admission = Arc::new(
            crate::routing::SignedQueryAdmission::new(
                chain.network_id(),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(120),
                std::num::NonZeroUsize::new(1_024).unwrap(),
            )
            .expect("native appeal-finance query admission"),
        );
        inner.state = chain.state().clone();
        inner.kura = chain.kura().clone();
        inner.local_peer_id = Some(iroha_model_base::peer::PeerId::new(
            validator.public_key().clone(),
        ));
        inner.torii_proxy_bridge_signer = validator;
    }
    let (node, temp_dir) = sorafs_node_with_temp_storage();
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, chain)
}
fn sorafs_app_state_with_appeal_finance_asset_lock_world_and_governance(
    auth: &OrderbookAuthFixture,
    asset_definition_id: &AssetDefinitionId,
) -> (
    SharedAppState,
    TempDir,
    iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    let config = iroha_core::sumeragi::test_chain::TestChainConfig::new(
        appeal_finance_asset_lock_world(auth, asset_definition_id),
        1,
    );
    let prepared = iroha_core::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("original appeal asset-lock genesis");
    let validator = prepared.validator_keys[0].clone();
    let chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::from_prepared(prepared)
        .expect("execute appeal asset-lock genesis");
    let mut app = mk_app_state_for_tests();
    {
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.chain_id = Arc::new(chain.state().view().chain_id().clone());
        inner.signed_query_admission = Arc::new(
            crate::routing::SignedQueryAdmission::new(
                chain.network_id(),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(120),
                std::num::NonZeroUsize::new(1_024).unwrap(),
            )
            .expect("native appeal-finance query admission"),
        );
        inner.state = chain.state().clone();
        inner.kura = chain.kura().clone();
        inner.local_peer_id = Some(iroha_model_base::peer::PeerId::new(
            validator.public_key().clone(),
        ));
        inner.torii_proxy_bridge_signer = validator;
    }
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let temp_root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize asset-lock governance temp dir");
    let governance_dir = temp_root.join("governance");
    fs::create_dir_all(&governance_dir).expect("create governance dir");
    let node = node_with_test_governance_publisher(
        StorageConfig::builder()
            .enabled(true)
            .data_dir(temp_root.join("storage"))
            .governance_dir(Some(governance_dir)),
        NodeRuntimeDeps::default(),
    );
    let app_inner = Arc::get_mut(&mut app).expect("unique app state");
    app_inner.sorafs_node = node;
    #[cfg(feature = "telemetry")]
    {
        app_inner.telemetry = isolated_test_telemetry();
    }
    (app, temp_dir, chain)
}
fn commit_appeal_finance_instruction(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    authority: &AccountId,
    instruction: InstructionBox,
) {
    let auth = orderbook_auth_fixture();
    let signer = if authority == &auth.provider.account {
        auth.provider.keypair
    } else {
        assert_eq!(authority, &auth.buyer.account);
        auth.buyer.keypair
    };
    let transaction = iroha_data_model::transaction::TransactionBuilder::new(
        chain.network_id(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction])
    .sign(signer.private_key());
    let applied = chain.commit(vec![transaction]);
    let committed = chain.committed(chain.height());
    assert_eq!(
        applied,
        vec![true],
        "actual asset-lock instruction must execute: {:?}",
        committed
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result),
    );
}
fn seed_appeal_finance_asset_lock(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    expected: &AppealFinanceDepositExpectation,
) {
    let instruction = OpenAssetLock::with_options(
        expected.escrow_id,
        expected.asset_definition_id.clone(),
        expected.destination_account.clone(),
        expected.deposit_xor.clone(),
        expected.release_authority_account.clone(),
        expected.expires_at_ms,
        expected.evidence_hashes.clone(),
    );
    commit_appeal_finance_instruction(chain, &expected.payer_account, instruction.into());
}
fn seed_appeal_finance_finalized_anchor(
    chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain,
) {
    assert_eq!(
        chain.height(),
        1,
        "original nonempty genesis anchors pre-deposit reads"
    );
}
fn drawdown_appeal_finance_asset_lock(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    expected: &AppealFinanceDepositExpectation,
    authority: &AccountId,
    amount: iroha_primitives::numeric::Quantity,
    height: u64,
) {
    assert_eq!(
        chain.height(),
        height,
        "native genesis precedes the requested instruction height"
    );
    let remaining = chain
        .state()
        .world_view()
        .asset_escrows()
        .get(&expected.escrow_id)
        .unwrap()
        .remaining_amount
        .clone();
    commit_appeal_finance_instruction(
        chain,
        authority,
        DrawdownAssetLock::new(expected.escrow_id, amount, remaining).into(),
    );
}
fn cancel_appeal_finance_asset_lock(
    chain: &mut iroha_core::sumeragi::test_chain::CertifiedTestChain,
    expected: &AppealFinanceDepositExpectation,
    authority: &AccountId,
    height: u64,
) {
    assert_eq!(chain.height(), height);
    let remaining = chain
        .state()
        .world_view()
        .asset_escrows()
        .get(&expected.escrow_id)
        .unwrap()
        .remaining_amount
        .clone();
    commit_appeal_finance_instruction(
        chain,
        authority,
        CancelAssetLock::new(expected.escrow_id, remaining).into(),
    );
}
