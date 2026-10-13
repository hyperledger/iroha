use iroha_core::tx::external_entrypoint_hash_from_signed_hash as entrypoint_hash;

// ISO lifecycle settlement must use the same authenticated execution outcome as reconciliation.

struct IsoPaymentOutcomeFixture {
    app: SharedAppState,
    hash: HashOf<SignedTransaction>,
    operator: KeyPair,
    config: iroha_config::parameters::actual::IsoBridge,
    pending_payment: Option<SignedTransaction>,
    original_bytes: String,
    chain: iroha_core::sumeragi::test_chain::CertifiedTestChain,
    _store: tempfile::TempDir,
    _reference: tempfile::NamedTempFile,
}

impl IsoPaymentOutcomeFixture {
    fn new(rejected: bool) -> Self {
        Self::with_committed_payment(rejected, true)
    }

    fn with_committed_payment(rejected: bool, committed: bool) -> Self {
        use iroha_config::parameters::actual;
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

        let signer = checked_torii_test_ed25519_keypair(0x24, "ISO payment authority");
        let recipient_key = checked_torii_test_ed25519_keypair(0x35, "ISO payment recipient");
        let originator = checked_torii_test_ed25519_keypair(0x81, "ISO originator operator");
        let operator = checked_torii_test_ed25519_keypair(0x82, "ISO counterparty operator");
        let sender = AccountId::new(signer.public_key().clone());
        let recipient = AccountId::new(recipient_key.public_key().clone());
        let definition = SumeragiNposParameters::default().xor_asset_definition_id;
        let store = tempfile::tempdir().expect("durable ISO store");
        let reference = tempfile::NamedTempFile::new().expect("BIC reference snapshot");
        std::fs::write(
            reference.path(),
            br#"{"version":"2026-01-01","source":"ISO outcome test","entries":[{"bic":"DEUTDEFF","lei":"5493001KJTIIGC8Y1R12"},{"bic":"MARKDEFF","lei":"5493001KJTIIGC8Y1R12"}]}"#,
        )
        .expect("write BIC reference snapshot");
        let config = actual::IsoBridge {
            enabled: true,
            max_body_bytes: defaults::torii::ISO_BRIDGE_MAX_BODY_BYTES,
            dedupe_ttl_secs: 3_600,
            default_profile: "generic-iso20022".to_owned(),
            profiles: Vec::new(),
            store_dir: Some(store.path().to_owned()),
            store_retention_secs: defaults::torii::ISO_BRIDGE_STORE_RETENTION_SECS,
            store_max_records: defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS,
            audit_export_dir: None,
            embedded_signature_policy: None,
            signer: Some(actual::IsoBridgeSigner {
                account_id: sender.to_string(),
                private_key: signer.private_key().clone(),
            }),
            participants: [
                ("originator-bank", "DEUTDEFF", originator.public_key()),
                ("counterparty-bank", "MARKDEFF", operator.public_key()),
            ]
            .map(|(id, bic, key)| actual::IsoBridgeParticipant {
                id: id.to_owned(),
                operator_keys: vec![key.clone()],
                financial_identifiers: vec![bic.to_owned()],
                allowed_profiles: vec!["generic-iso20022".to_owned()],
                roles: vec!["originator".to_owned(), "counterparty".to_owned()],
            })
            .to_vec(),
            audit_admin_keys: Vec::new(),
            account_aliases: [
                ("GB82WEST12345698765432", &sender),
                ("GB33BUKB20201555555555", &recipient),
            ]
            .map(|(iban, account)| actual::IsoAccountAlias {
                iban: iban.to_owned(),
                account_id: account.to_string(),
            })
            .to_vec(),
            currency_assets: vec![actual::IsoCurrencyAsset {
                currency: "USD".to_owned(),
                asset_definition: definition.to_string(),
                max_amount: Quantity::from(1_000_u32),
            }],
            reference_data: actual::IsoReferenceData {
                bic_lei_path: Some(reference.path().to_owned()),
                ..actual::IsoReferenceData::default()
            },
        };
        let world = World::with_assets(
            [],
            [sender.clone(), recipient.clone()].map(|id| Account::new(id).build(&sender)),
            [AssetDefinition::numeric(
                definition.clone(),
                "USD".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&sender)],
            [Asset::new(
                AssetId::new(definition.clone(), sender.clone()),
                Quantity::from(if rejected { 5_u32 } else { 10_u32 }),
            )],
            [],
        );
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000))
            .expect("certified payment chain");
        let mut app = mk_app_state_for_tests_with_iso_bridge(Some(config.clone()));
        let unique = Arc::get_mut(&mut app).expect("unique fixture app");
        unique.state = chain.state().clone();
        unique.kura = chain.kura().clone();
        let runtime = app.iso_bridge.as_ref().expect("ISO bridge enabled");
        let original_fields = "AppHdr/Fr/FIId/FinInstnId/BICFI=DEUTDEFF\nAppHdr/To/FIId/FinInstnId/BICFI=MARKDEFF\nAppHdr/BizSvc=generic-iso20022\nMsgId=outcome-payment\nIntrBkSttlmCcy=USD\nIntrBkSttlmAmt=10\nIntrBkSttlmDt=2026-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=MARKDEFF";
        let original_bytes = format!(
            "{original_fields}\nUETR=123e4567-e89b-42d3-a456-426614174000\nNexusSettlement/NetworkId={}\nNexusSettlement/ExpiresAtHeight=100\nNexusSettlement/SourceAccountId={sender}\nNexusSettlement/TargetAccountId={recipient}\nNexusSettlement/AssetDefinitionId={definition}",
            chain.network_id()
        );
        let original = ivm::iso20022::parse_message("pacs.008", original_bytes.as_bytes())
            .expect("valid original payment");
        let parties = runtime
            .authorize_initial_submission(
                originator.public_key(),
                runtime.default_profile(),
                &original,
            )
            .expect("authenticated originator owns the original payment");
        let metadata = runtime
            .validate_profile_submission(
                runtime.default_profile(),
                "pacs.008",
                &original,
                original_bytes.as_bytes(),
            )
            .expect("original payment profile");
        runtime
            .admit_authenticated_inbound("outcome-payment", metadata, parties)
            .expect("durable original payment");
        let (mut payload, context) = {
            let world = app.state.world_view();
            runtime
                .build_pacs008_payload(
                    &original,
                    &world,
                    1_001,
                    app.chain_id.as_ref(),
                    &chain.network_id(),
                    &app.telemetry,
                )
                .expect("exact ISO native payment")
        };
        payload.creation_time_ms = 1_001;
        let transaction = runtime
            .sign_transaction_payload(payload)
            .expect("signed native payment");
        let hash = transaction.hash();
        assert!(runtime.update_message_context("outcome-payment", context));
        runtime.mark_accepted("outcome-payment", &hash.to_string());
        let pending_payment = if committed {
            assert_eq!(chain.commit(vec![transaction]), vec![!rejected]);
            None
        } else {
            Some(transaction)
        };
        if committed {
            let view = app.state.view();
            let recipient_asset = AssetId::new(definition, recipient);
            if rejected {
                assert!(view.world().asset(&recipient_asset).is_err());
            } else {
                assert_eq!(
                    view.world()
                        .asset(&recipient_asset)
                        .expect("successful payment credits the intended recipient")
                        .value()
                        .clone()
                        .into_inner(),
                    Quantity::from(10_u32)
                );
            }
        }
        assert_eq!(
            app.state.has_committed_entrypoint(entrypoint_hash(hash)),
            committed
        );
        assert_eq!(
            runtime
                .message_status("outcome-payment")
                .unwrap()
                .status_label(),
            "Accepted"
        );
        Self {
            app,
            hash,
            operator,
            config,
            pending_payment,
            original_bytes,
            chain,
            _store: store,
            _reference: reference,
        }
    }

    async fn submit_settlement(
        &self,
    ) -> Result<(StatusCode, JsonBody<norito::json::native::Value>), Error> {
        let body = include_str!("../../../../../fixtures/iso20022/live_pacs002_test_template.xml")
            .replace("{business_message_id}-orig", "outcome-payment")
            .replace("{business_message_id}", "outcome-settlement")
            .replace("{msg_def_id}", "pacs.002.001.10")
            .replace("{business_service}", "generic-iso20022")
            .replace("ACSP", "ACSC");
        handler_iso_lifecycle_submit(
            self.app.clone(),
            operator_signatures::AuthenticatedOperatorPublicKey(self.operator.public_key().clone()),
            HeaderMap::new(),
            HashMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
            body.into(),
            "pacs.002",
            "v1/iso20022/pacs002",
        )
        .await
    }
}

#[tokio::test]
async fn iso_settlement_rejects_included_but_rejected_payment_before_reconciliation() {
    let fixture = IsoPaymentOutcomeFixture::new(true);
    let error = fixture
        .submit_settlement()
        .await
        .expect_err("included rejection cannot settle");
    assert!(
        matches!(
            error,
            Error::AppServiceUnavailable {
                code: "iso_settlement_outcome_pending",
                ..
            }
        ),
        "{error:?}"
    );
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    assert_ne!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    reconcile_iso_bridge_transactions(runtime, &fixture.app.state)
        .expect("canonical reconciliation");
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .status_label(),
        "Rejected"
    );
    assert_eq!(
        fixture.chain.height(),
        2,
        "no unrelated traffic drives settlement"
    );
}

#[tokio::test]
async fn iso_settlement_accepts_successful_payment_without_later_network_traffic() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    assert_eq!(
        fixture
            .submit_settlement()
            .await
            .expect("authenticated successful settlement")
            .0,
        StatusCode::ACCEPTED
    );
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    let canonical_time = SystemTime::UNIX_EPOCH
        .checked_add(fixture.chain.committed(2).block().header().creation_time())
        .expect("fixture carrier time");
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .settled_at(),
        Some(canonical_time)
    );
    reconcile_iso_bridge_transactions(runtime, &fixture.app.state)
        .expect("idempotent reconciliation");
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .settled_at(),
        Some(canonical_time)
    );
    assert_eq!(
        fixture.chain.height(),
        2,
        "the final payment needs no later block"
    );
}

#[tokio::test]
async fn iso_settlement_rejects_absent_canonical_payment() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    let mut membership = fixture.app.state.transactions.block_and_revert();
    membership.insert_block(HashSet::new(), NonZeroUsize::new(2).unwrap());
    membership
        .commit()
        .expect("remove canonical payment membership");
    assert!(
        !fixture
            .app
            .state
            .has_committed_entrypoint(entrypoint_hash(fixture.hash))
    );
    assert!(fixture.submit_settlement().await.is_err());
    assert_ne!(
        fixture
            .app
            .iso_bridge
            .as_ref()
            .unwrap()
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    assert!(
        fixture
            .app
            .iso_bridge
            .as_ref()
            .unwrap()
            .message_status("outcome-settlement")
            .is_none(),
        "missing finality must leave the lifecycle identity retryable"
    );
    let mut membership = fixture.app.state.transactions.block_and_revert();
    membership.insert_block(
        HashSet::from([entrypoint_hash(fixture.hash)]),
        NonZeroUsize::new(2).unwrap(),
    );
    membership.commit().expect("restore canonical membership");
    assert_eq!(
        fixture
            .submit_settlement()
            .await
            .expect("the same notification resumes when finality is available")
            .0,
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn iso_settlement_rejects_conflicting_canonical_carrier() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    let canonical_hash = fixture.chain.committed(2).block().hash();
    let mut journal = fixture.app.state.block_hashes.block_and_revert();
    journal.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
        b"conflicting ISO payment carrier",
    )));
    journal.commit_for_tests();
    assert!(
        fixture
            .app
            .state
            .has_committed_entrypoint(entrypoint_hash(fixture.hash))
    );
    assert!(fixture.submit_settlement().await.is_err());
    assert_ne!(
        fixture
            .app
            .iso_bridge
            .as_ref()
            .unwrap()
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    assert!(
        fixture
            .app
            .iso_bridge
            .as_ref()
            .unwrap()
            .message_status("outcome-settlement")
            .is_none(),
        "an unavailable authenticated outcome must leave lifecycle admission retryable"
    );
    let mut journal = fixture.app.state.block_hashes.block_and_revert();
    journal.push_for_tests(canonical_hash);
    journal.commit_for_tests();
    assert_eq!(
        fixture
            .submit_settlement()
            .await
            .expect("the same lifecycle identity resumes after authenticated evidence recovers")
            .0,
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn iso_settlement_rejects_a_different_authenticated_participant() {
    let mut fixture = IsoPaymentOutcomeFixture::new(false);
    let counterparty = fixture.operator.clone();
    fixture.operator = checked_torii_test_ed25519_keypair(0x81, "ISO originator operator");
    assert!(fixture.submit_settlement().await.is_err());
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    assert!(runtime.message_status("outcome-settlement").is_none());
    assert_ne!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    fixture.operator = counterparty;
    assert_eq!(
        fixture
            .submit_settlement()
            .await
            .expect("the original counterparty owns settlement")
            .0,
        StatusCode::ACCEPTED
    );
}
#[tokio::test]
async fn iso_reported_return_preserves_native_success_and_balances() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    fixture
        .submit_settlement()
        .await
        .expect("successful original payment");
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    let before = runtime.message_status("outcome-payment").unwrap();
    let body = include_str!("../../../../../fixtures/iso20022/live_pacs004_test_template.xml")
        .replace("{business_message_id}-orig", "outcome-payment")
        .replace("{business_message_id}", "outcome-return")
        .replace("{msg_def_id}", "pacs.004.001.09")
        .replace("{business_service}", "generic-iso20022");
    let (status, JsonBody(report)) = handler_iso_lifecycle_submit(
        fixture.app.clone(),
        operator_signatures::AuthenticatedOperatorPublicKey(fixture.operator.public_key().clone()),
        HeaderMap::new(),
        HashMap::new(),
        "127.0.0.1:8080".parse().unwrap(),
        body.into(),
        "pacs.004",
        "v1/iso20022/pacs004",
    )
    .await
    .expect("authenticated external return report");
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(report["lifecycle_action"].as_str(), Some("recorded_return"));
    let external = &report["reported_return"];
    assert_eq!(external["disposition"].as_str(), Some("external_report"));
    assert_eq!(
        external["original_message_id"].as_str(),
        Some("outcome-payment")
    );
    assert_eq!(
        external["original_transaction_hash"].as_str(),
        Some(fixture.hash.to_string().as_str())
    );
    assert_eq!(external["amount"].as_str(), Some("10"));
    assert_eq!(external["currency"].as_str(), Some("USD"));
    assert_eq!(external["reason_code"].as_str(), Some("AC01"));
    let after = runtime.message_status("outcome-payment").unwrap();
    assert_eq!(after.pacs002_code(), "ACSC");
    assert_eq!(after.transaction_hash(), before.transaction_hash());
    assert_eq!(after.settled_at(), before.settled_at());
    assert_eq!(after.updated_at(), before.updated_at());
    assert_eq!(after.status_history().len(), before.status_history().len());
    assert_eq!(after.detail(), before.detail());
    let lifecycle = runtime
        .message_status("outcome-return")
        .expect("separate durable lifecycle");
    assert!(lifecycle.transaction_hash().is_none());
    assert!(lifecycle.settled_at().is_none());
    assert_eq!(lifecycle.reported_return_json(), *external);
    let recipient_key = checked_torii_test_ed25519_keypair(0x35, "ISO payment recipient");
    let recipient = AccountId::new(recipient_key.public_key().clone());
    let definition = SumeragiNposParameters::default().xor_asset_definition_id;
    let view = fixture.app.state.view();
    assert_eq!(
        view.world()
            .asset(&AssetId::new(definition, recipient))
            .unwrap()
            .value()
            .clone()
            .into_inner(),
        Quantity::from(10_u32),
        "an external report does not execute a native reverse payment"
    );
    assert_eq!(
        fixture.chain.height(),
        2,
        "report needs no later network traffic"
    );
}

impl IsoPaymentOutcomeFixture {
    async fn submit_return(
        &self,
    ) -> Result<(StatusCode, JsonBody<norito::json::native::Value>), Error> {
        let body = include_str!("../../../../../fixtures/iso20022/live_pacs004_test_template.xml")
            .replace("{business_message_id}-orig", "outcome-payment")
            .replace("{business_message_id}", "outcome-return")
            .replace("{msg_def_id}", "pacs.004.001.09")
            .replace("{business_service}", "generic-iso20022");
        handler_iso_lifecycle_submit(
            self.app.clone(),
            operator_signatures::AuthenticatedOperatorPublicKey(self.operator.public_key().clone()),
            HeaderMap::new(),
            HashMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
            body.into(),
            "pacs.004",
            "v1/iso20022/pacs004",
        )
        .await
    }
}

#[tokio::test]
async fn iso_reported_return_wakes_idle_worker_after_final_payment() {
    let mut fixture = IsoPaymentOutcomeFixture::with_committed_payment(false, false);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap().clone();
    let events = tokio::sync::broadcast::channel(8).0;
    let shutdown = ShutdownSignal::new();
    let worker = start_iso_bridge_projection_worker(
        runtime.clone(),
        fixture.app.state.clone(),
        &events,
        shutdown.clone(),
    )
    .unwrap();
    let transaction = fixture.pending_payment.take().unwrap();
    assert_eq!(fixture.chain.commit(vec![transaction]), vec![true]);
    // No block event is forwarded: the final report itself must wake the existing worker.
    let (_, JsonBody(report)) = fixture.submit_return().await.unwrap();
    assert_eq!(
        report["reported_return"]["disposition"].as_str(),
        Some("pending_original")
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .message_status("outcome-return")
                .unwrap()
                .reported_return_json()["disposition"]
                .as_str()
                == Some("external_report")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending return resolves on durable publication notification");
    assert_eq!(fixture.chain.height(), 2);
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    shutdown.send();
    assert!(matches!(
        worker.await.unwrap(),
        ToriiCriticalWorkerExit::StoppedByShutdown
    ));
}

#[tokio::test]
async fn iso_reported_return_recovers_original_outcome_after_restart() {
    for rejected in [false, true] {
        let fixture = IsoPaymentOutcomeFixture::new(rejected);
        let (_, JsonBody(report)) = fixture.submit_return().await.unwrap();
        assert_eq!(
            report["reported_return"]["disposition"].as_str(),
            Some("pending_original")
        );
        let restored = Arc::new(
            Iso20022BridgeRuntime::from_config(&fixture.config)
                .unwrap()
                .unwrap(),
        );
        let events = tokio::sync::broadcast::channel(8).0;
        let shutdown = ShutdownSignal::new();
        let worker = start_iso_bridge_projection_worker(
            restored.clone(),
            fixture.app.state.clone(),
            &events,
            shutdown.clone(),
        )
        .unwrap();
        let report = restored.message_status("outcome-return").unwrap();
        assert_eq!(
            report.reported_return_json()["disposition"].as_str(),
            Some(if rejected {
                // Rejection of this gateway's carrier cannot prove another exact carrier
                // will never settle the same business intent before its committed expiry.
                "pending_original"
            } else {
                "external_report"
            })
        );
        assert!(report.transaction_hash().is_none());
        assert!(report.settled_at().is_none());
        assert_eq!(
            restored
                .message_status("outcome-payment")
                .unwrap()
                .pacs002_code(),
            if rejected { "RJCT" } else { "ACSC" }
        );
        assert_eq!(fixture.chain.height(), 2);
        shutdown.send();
        assert!(matches!(
            worker.await.unwrap(),
            ToriiCriticalWorkerExit::StoppedByShutdown
        ));
    }
}

#[tokio::test]
async fn iso_settlement_canonical_success_supersedes_local_rejection_with_exact_carrier() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    assert!(runtime.mark_rejected(
        "outcome-payment",
        Some("local submission observation failed".to_owned()),
        None
    ));
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .transaction_hash(),
        Some(fixture.hash.to_string().as_str())
    );
    fixture
        .submit_settlement()
        .await
        .expect("authenticated canonical success overrides only local status");
    let original = runtime.message_status("outcome-payment").unwrap();
    assert_eq!(original.pacs002_code(), "ACSC");
    assert_eq!(
        original.settled_at(),
        SystemTime::UNIX_EPOCH
            .checked_add(fixture.chain.committed(2).block().header().creation_time())
    );
    assert_eq!(fixture.chain.height(), 2);
}

#[tokio::test]
async fn iso_reported_return_canonical_success_supersedes_local_queue_expiry() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    assert!(runtime.mark_transaction_expired(&fixture.hash.to_string()));
    fixture
        .submit_return()
        .await
        .expect("retain report against exact expired carrier");
    reconcile_iso_bridge_transactions(runtime, &fixture.app.state)
        .expect("canonical original recovery");
    assert_eq!(
        runtime
            .message_status("outcome-payment")
            .unwrap()
            .pacs002_code(),
        "ACSC"
    );
    assert_eq!(
        runtime
            .message_status("outcome-return")
            .unwrap()
            .reported_return_json()["disposition"]
            .as_str(),
        Some("external_report")
    );
    assert_eq!(fixture.chain.height(), 2);
}

impl IsoPaymentOutcomeFixture {
    fn second_gateway(
        &self,
        amount: &str,
    ) -> (
        SharedAppState,
        SignedTransaction,
        tempfile::TempDir,
        iroha_config::parameters::actual::IsoBridge,
    ) {
        let store = tempfile::tempdir().unwrap();
        let mut config = self.config.clone();
        config.store_dir = Some(store.path().to_owned());
        let mut app = mk_app_state_for_tests_with_iso_bridge(Some(config.clone()));
        let unique = Arc::get_mut(&mut app).unwrap();
        unique.state = self.chain.state().clone();
        unique.kura = self.chain.kura().clone();
        let runtime = app.iso_bridge.as_ref().unwrap();
        let bytes = self
            .original_bytes
            .replace("MsgId=outcome-payment", "MsgId=other-gateway-payment")
            .replace("IntrBkSttlmAmt=10", &format!("IntrBkSttlmAmt={amount}"));
        let parsed = ivm::iso20022::parse_message("pacs.008", bytes.as_bytes()).unwrap();
        let originator = checked_torii_test_ed25519_keypair(0x81, "ISO originator operator");
        let parties = runtime
            .authorize_initial_submission(
                originator.public_key(),
                runtime.default_profile(),
                &parsed,
            )
            .unwrap();
        let metadata = runtime
            .validate_profile_submission(
                runtime.default_profile(),
                "pacs.008",
                &parsed,
                bytes.as_bytes(),
            )
            .unwrap();
        runtime
            .admit_authenticated_inbound("other-gateway-payment", metadata, parties)
            .unwrap();
        let (mut payload, context) = runtime
            .build_pacs008_payload(
                &parsed,
                &app.state.world_view(),
                1_002,
                app.chain_id.as_ref(),
                &self.chain.network_id(),
                &app.telemetry,
            )
            .unwrap();
        payload.creation_time_ms = 1_002;
        assert!(runtime.update_message_context("other-gateway-payment", context));
        let transaction = runtime.sign_transaction_payload(payload).unwrap();
        assert!(
            runtime.bind_transaction_hash("other-gateway-payment", &transaction.hash().to_string())
        );
        runtime.mark_accepted("other-gateway-payment", &transaction.hash().to_string());
        (app, transaction, store, config)
    }

    async fn settle_other_gateway(
        &self,
        app: SharedAppState,
    ) -> Result<(StatusCode, JsonBody<norito::json::native::Value>), Error> {
        let body = include_str!("../../../../../fixtures/iso20022/live_pacs002_test_template.xml")
            .replace("{business_message_id}-orig", "other-gateway-payment")
            .replace("{business_message_id}", "other-gateway-settlement")
            .replace("{msg_def_id}", "pacs.002.001.10")
            .replace("{business_service}", "generic-iso20022")
            .replace("ACSP", "ACSC");
        handler_iso_lifecycle_submit(
            app,
            operator_signatures::AuthenticatedOperatorPublicKey(self.operator.public_key().clone()),
            HeaderMap::new(),
            HashMap::new(),
            "127.0.0.1:8080".parse().unwrap(),
            body.into(),
            "pacs.002",
            "v1/iso20022/pacs002",
        )
        .await
    }
}

#[tokio::test]
async fn iso_native_two_gateways_recover_one_business_effect_and_honest_rejected_retry_after_restart()
 {
    let mut fixture = IsoPaymentOutcomeFixture::new(false);
    let (app, transaction, _store, config) = fixture.second_gateway("10");
    let attempted = transaction.hash();
    assert_ne!(attempted, fixture.hash);
    assert_eq!(fixture.chain.commit(vec![transaction]), vec![false]);
    fixture
        .settle_other_gateway(app.clone())
        .await
        .expect("original business success recovers the rejected retry");
    let status = app
        .iso_bridge
        .as_ref()
        .unwrap()
        .message_status("other-gateway-payment")
        .unwrap();
    let native = status.native_payment_json();
    assert_eq!(status.pacs002_code(), "ACSC");
    assert_eq!(
        status.transaction_hash(),
        Some(attempted.to_string().as_str())
    );
    assert_eq!(native["carrier"]["applied"].as_bool(), Some(false));
    assert_eq!(
        native["business_settlement"]["transaction_hash"].as_str(),
        Some(fixture.hash.to_string().as_str())
    );
    assert_eq!(native["verified"].as_bool(), Some(true));
    let restored = Iso20022BridgeRuntime::from_config(&config)
        .unwrap()
        .unwrap();
    assert_eq!(
        restored
            .message_status("other-gateway-payment")
            .unwrap()
            .pacs002_code(),
        "PDNG"
    );
    reconcile_iso_bridge_transactions(&restored, &app.state).unwrap();
    let recovered = restored.message_status("other-gateway-payment").unwrap();
    assert_eq!(recovered.pacs002_code(), "ACSC");
    assert_eq!(recovered.native_payment_json(), native);
    let recipient = AccountId::new(
        checked_torii_test_ed25519_keypair(0x35, "ISO payment recipient")
            .public_key()
            .clone(),
    );
    let asset = AssetId::new(
        SumeragiNposParameters::default().xor_asset_definition_id,
        recipient,
    );
    assert_eq!(
        app.state
            .view()
            .world()
            .asset(&asset)
            .unwrap()
            .value()
            .clone()
            .into_inner(),
        Quantity::from(10_u32)
    );
    assert_eq!(
        fixture.chain.height(),
        3,
        "no unrelated network traffic follows the retry"
    );
}

#[tokio::test]
async fn iso_native_same_reference_different_terms_never_recovers_original_as_requested_payment() {
    let mut fixture = IsoPaymentOutcomeFixture::new(false);
    let (app, transaction, _store, _config) = fixture.second_gateway("11");
    assert_eq!(fixture.chain.commit(vec![transaction]), vec![false]);
    assert!(fixture.settle_other_gateway(app.clone()).await.is_err());
    let status = app
        .iso_bridge
        .as_ref()
        .unwrap()
        .message_status("other-gateway-payment")
        .unwrap();
    assert_eq!(status.pacs002_code(), "RJCT");
    let native = status.native_payment_json();
    assert_eq!(native["conflicting_intent"].as_bool(), Some(true));
    assert!(matches!(
        native["business_settlement"],
        norito::json::Value::Null
    ));
    assert_eq!(native["carrier"]["applied"].as_bool(), Some(false));
    assert!(status.settled_at().is_none());
    assert_eq!(fixture.chain.height(), 3);
}

#[test]
fn iso_native_business_locator_refuses_absent_and_private_root_authority() {
    let fixture = IsoPaymentOutcomeFixture::new(false);
    let runtime = fixture.app.iso_bridge.as_ref().unwrap();
    let request = runtime.native_payment_requests().unwrap().remove(0);
    assert!(
        canonical_iso_business_locator(&fixture.app.state, &request)
            .unwrap()
            .is_some()
    );
    let absent_root = mk_app_state_for_tests_with_world(World::default());
    let mut block = absent_root.state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut transaction = block.transaction();
    assert!(
        transaction
            .world_mut_for_testing()
            .parameters_mut_for_testing()
            .remove_custom_parameter(
                &iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id()
            )
            .is_some(),
        "remove the Global root metadata seeded by the general test app helper"
    );
    transaction.apply();
    block.commit_world_overlay_for_testing().unwrap();
    for app in [
        absent_root,
        app_with_root_scope_for_handler_test(World::default(), true),
    ] {
        assert_ne!(
            iroha_core::sumeragi::lanes::routing::committed_root_scope(app.state.view().world()),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
        );
        let mut selected = request.clone();
        selected.intent.network_id = *app.state.network_id_ref();
        // Even an exact selected network cannot turn missing/private root authority
        // into an observation of Global business absence or success.
        assert!(canonical_iso_business_locator(&app.state, &selected).is_err());
    }
}
