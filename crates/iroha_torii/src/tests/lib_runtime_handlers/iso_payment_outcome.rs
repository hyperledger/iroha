// ISO lifecycle settlement must use the same authenticated execution outcome as reconciliation.

struct IsoPaymentOutcomeFixture {
    app: SharedAppState,
    hash: HashOf<SignedTransaction>,
    operator: KeyPair,
    chain: iroha_core::sumeragi::test_chain::CertifiedTestChain,
    _store: tempfile::TempDir,
    _reference: tempfile::NamedTempFile,
}

impl IsoPaymentOutcomeFixture {
    fn new(rejected: bool) -> Self {
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
                AssetId::new(definition.clone(), sender),
                Quantity::from(if rejected { 5_u32 } else { 10_u32 }),
            )],
            [],
        );
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000))
            .expect("certified payment chain");
        let mut app = mk_app_state_for_tests_with_iso_bridge(Some(config));
        let unique = Arc::get_mut(&mut app).expect("unique fixture app");
        unique.state = chain.state().clone();
        unique.kura = chain.kura().clone();
        let runtime = app.iso_bridge.as_ref().expect("ISO bridge enabled");
        let original_bytes = b"AppHdr/Fr/FIId/FinInstnId/BICFI=DEUTDEFF\nAppHdr/To/FIId/FinInstnId/BICFI=MARKDEFF\nAppHdr/BizSvc=generic-iso20022\nMsgId=outcome-payment\nIntrBkSttlmCcy=USD\nIntrBkSttlmAmt=10\nIntrBkSttlmDt=2026-01-01\nDbtrAcct=GB82WEST12345698765432\nCdtrAcct=GB33BUKB20201555555555\nDbtrAgt=DEUTDEFF\nCdtrAgt=MARKDEFF";
        let original = ivm::iso20022::parse_message("pacs.008", original_bytes)
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
                original_bytes,
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
                .expect("exact ISO payment transfer")
        };
        payload.creation_time_ms = 1_001;
        let transaction = runtime
            .sign_transaction_payload(payload)
            .expect("signed transfer");
        let hash = transaction.hash();
        assert!(runtime.update_message_context("outcome-payment", context));
        runtime.mark_accepted("outcome-payment", &hash.to_string());
        assert_eq!(chain.commit(vec![transaction]), vec![!rejected]);
        {
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
        assert!(app.state.has_committed_entrypoint(entrypoint_hash(hash)));
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
    assert!(matches!(error, Error::Query(_)), "{error:?}");
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
    reconcile_iso_bridge_transactions(runtime, &fixture.app.state)
        .expect("idempotent reconciliation");
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
    journal.push_for_tests(fixture.chain.committed(2).block().hash());
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
