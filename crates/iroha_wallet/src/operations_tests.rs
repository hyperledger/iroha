//! Native transfer, journal, quote and recovery boundary tests.
use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use norito::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub fn fixture_config() -> Config {
    // Published deterministic SDK fixture, never an operational wallet identity.
    let source = br#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "http://127.0.0.1:8080/"
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
[transaction]
time_to_live_ms = 100000
status_timeout_ms = 1000
nonce = false
"#;
    Config::load_bytes_with_musubi_publication(Path::new("public-wallet-fixture.toml"), source)
        .unwrap()
        .0
}

#[derive(Debug, Default)]
pub(super) struct Transport {
    pub(super) requests: AtomicUsize,
    pub(super) quote_count: AtomicUsize,
    pub(super) dispatch_count: AtomicUsize,
    pub(super) cancel_on_path: Mutex<Option<(String, Arc<AtomicBool>)>>,
    journal: Mutex<Option<std::path::PathBuf>>,
    wrong_payer: AtomicBool,
    pub(super) incompatible_submission: AtomicBool,
    alias_plan: Mutex<Option<AliasTransactionPlanV1>>,
}
impl HttpTransport for Transport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if let Some((path, signal)) = self.cancel_on_path.lock().unwrap().as_ref() {
            if request.url.path() == path.as_str() {
                signal.store(true, Ordering::Release);
            }
        }
        let (status, body) = match request.url.path() {
            "/v1/node/capabilities" => (
                200,
                json::to_vec(
                    &norito::json!({"data_model_version": (iroha::data_model::DATA_MODEL_VERSION),
                    "signed_transaction_schema_hash_hex": (if self.incompatible_submission.load(Ordering::SeqCst) { "00".repeat(16) } else { hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()) })}),
                )?,
            ),
            "/v1/aliases/setup/plan" => (
                200,
                json::to_vec(self.alias_plan.lock().unwrap().as_ref().unwrap())?,
            ),
            "/v1/fees/quote" => {
                self.quote_count.fetch_add(1, Ordering::SeqCst);
                let request: iroha_torii_shared::FeeQuoteRequest = json::from_slice(&request.body)?;
                let payload = request.payload;
                let intent = if self.wrong_payer.load(Ordering::SeqCst) {
                    FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(999))
                } else {
                    payload.fee_payment_intent().clone()
                };
                let quote = FeeQuoteResponse {
                    intent,
                    observation: iroha_torii_shared::FeeQuoteObservation {
                        ledger_time_ms: 1,
                        next_block_height: 1,
                        route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    },
                    components: Vec::new(),
                    capacities: Vec::new(),
                    decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
                        debit_source: iroha::data_model::nexus::FeeDebitSource::Account(
                            payload.authority().clone(),
                        ),
                        program_revision: None,
                    },
                };
                (200, json::to_vec(&quote)?)
            }
            "/v1/query" => {
                return BalanceTransport {
                    missing: None,
                    foreign: false,
                }
                .send_blocking(request);
            }
            "/v1/pipeline/transactions/status" => {
                assert_eq!(request.method, iroha::http::Method::GET);
                assert!(request.body.is_empty());
                let hash = request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "hash")
                    .expect("status lookup includes its exact transaction hash")
                    .1
                    .parse::<iroha_crypto::HashOf<SignedTransaction>>()?;
                assert!(
                    request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "scope" && value == "global")
                );
                let absence = iroha_torii_shared::ErrorEnvelope::new(
                    iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                    "Missing status.",
                )
                .with_details(iroha_torii_shared::ErrorDetails {
                    pipeline_transaction_status_not_found: Some(
                        iroha_torii_shared::PipelineTransactionStatusNotFoundV1::new(
                            &hash, "global",
                        ),
                    ),
                    ..iroha_torii_shared::ErrorDetails::default()
                });
                (404, json::to_vec(&absence)?)
            }
            _ => {
                self.dispatch_count.fetch_add(1, Ordering::SeqCst);
                let path = self
                    .journal
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("dispatch may occur only after preparation");
                assert!(path.join("operation.json").is_file());
                assert!(
                    path.join("submission.json").is_file(),
                    "attempt must be durable before native dispatch"
                );
                (503, b"unavailable".to_vec())
            }
        };
        Ok(Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(body)?)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}
pub(super) fn service() -> (AccountService, Arc<Transport>) {
    let config = fixture_config();
    let transport = Arc::new(Transport::default());
    let client = Client::with_http_transport(config.clone(), transport.clone()).unwrap();
    (
        AccountService {
            config,
            client,
            deadline: None,
            cancellation: None,
        },
        transport,
    )
}
pub(super) fn request() -> TransferRequest {
    TransferRequest {
        destination: iroha_test_samples::BOB_ID.clone(),
        amount: Quantity::from(3_u32),
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
    }
}

#[test]
fn prepare_quotes_exact_transfer_and_persists_before_any_dispatch() {
    let (service, transport) = service();
    let _profile = ChainDiscriminantGuard::enter(service.config.account_chain_discriminant);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    let result = service.prepare_transfer(&request(), &path).unwrap();
    assert_eq!(result.status, OperationStatus::Prepared);
    assert!(!result.status.is_complete());
    assert!(result.data["deadline_ms"].as_u64().unwrap() > current_unix_ms().unwrap());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let transaction = record.verify(&service.config).unwrap();
    assert_eq!(
        transaction.hash().to_string(),
        result.data["transaction_hash"].as_str().unwrap()
    );
    let public = std::fs::read_to_string(path.join("operation.json")).unwrap();
    for secret in ["private_key", "onboarding_token", "basic_auth"] {
        assert!(!public.contains(secret));
    }
    let repeated = service.prepare_transfer(&request(), &path).unwrap();
    assert_eq!(
        repeated.data["transaction_hash"],
        result.data["transaction_hash"]
    );
    assert_eq!(
        std::fs::read_to_string(path.join("operation.json")).unwrap(),
        public
    );
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    let mut changed = request();
    changed.amount = Quantity::from(4_u32);
    assert!(
        service.prepare_transfer(&changed, &path).is_err(),
        "changed preparation cannot overwrite an earlier signed operation"
    );
}

#[test]
fn transferred_amount_destination_fee_and_network_are_bound_to_exact_wire() {
    let (service, _) = service();
    let _profile = ChainDiscriminantGuard::enter(service.config.account_chain_discriminant);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    service.prepare_transfer(&request(), &path).unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let mut changed = record.clone();
    if let NativeOperation::Transfer { amount, .. } = &mut changed.operation {
        *amount = Quantity::from(4_u32);
    }
    assert!(changed.verify(&service.config).is_err());
    let mut changed = record.clone();
    if let NativeOperation::Transfer { destination, .. } = &mut changed.operation {
        *destination = service.config.account.clone();
    }
    assert!(changed.verify(&service.config).is_err());
    let mut foreign = service.config.clone();
    foreign.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign wallet network"),
        ));
    assert!(record.verify(&foreign).is_err());
    let mut changed = record.clone();
    changed.requested_fee = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(changed.verify(&service.config).is_err());
    let mut changed = record.clone();
    changed.deadline_ms += 1;
    assert!(changed.verify(&service.config).is_err());
    let mut changed = record;
    changed.signed_transaction_hex = changed.signed_transaction_hex.to_uppercase();
    assert!(changed.verify(&service.config).is_err());
}

#[test]
fn ambiguous_submission_is_never_repeated_and_resume_is_read_only() {
    let (service, transport) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    service.prepare_transfer(&request(), &path).unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let outcome = service
        .submit(&path, NativeOperationKind::Transfer)
        .unwrap();
    assert_eq!(outcome.status, OperationStatus::Pending);
    assert!(outcome.data["deadline_ms"].as_u64().is_some());
    let attempted = transport.dispatch_count.load(Ordering::SeqCst);
    assert!(attempted > 0);
    assert_eq!(
        service
            .submit(&path, NativeOperationKind::Transfer)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        service
            .resume(&path, NativeOperationKind::Transfer)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), attempted);
    assert!(!path.join("applied.json").exists());
}

#[test]
fn hostile_quote_and_invalid_transfer_never_sign_or_dispatch() {
    let (service, transport) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    let mut invalid = request();
    invalid.amount = Quantity::from(0_u32);
    assert!(service.prepare_transfer(&invalid, &path).is_err());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    invalid.amount = Quantity::from(78_u32);
    let insufficient = service
        .prepare_transfer(&invalid, &path)
        .unwrap_err()
        .to_string();
    assert!(insufficient.contains("required 78"), "{insufficient}");
    assert!(path.join("preparation.json").is_file());
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    let hostile = temporary.path().join("hostile");
    transport.wrong_payer.store(true, Ordering::SeqCst);
    assert!(service.prepare_transfer(&request(), &hostile).is_err());
    assert!(hostile.join("preparation.json").is_file());
    assert!(!hostile.join("payload.json").exists());
    assert!(!hostile.join("operation.json").exists());
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn xor_balance_uses_the_canonical_native_account_holding() {
    let (service, _) = service();
    let balance = service.xor_balance().unwrap();
    assert_eq!(balance.amount, Quantity::from(77_u32));
    assert_eq!(
        balance.asset_id,
        AssetId::new(
            XOR_ASSET_DEFINITION.parse().unwrap(),
            service.config.account.clone()
        )
    );
}

#[test]
fn account_context_and_public_endpoint_are_validated_without_io() {
    let mut config = fixture_config();
    assert!(AccountService::new(config.clone()).is_ok());
    config.account = iroha_test_samples::BOB_ID.clone();
    assert!(AccountService::new(config).is_err());
    for url in [
        "https://user:secret@example.com",
        "https://example.com?token=secret",
        "https://example.com#fragment",
    ] {
        assert!(iroha::account_bootstrap::validate_endpoint(&url.parse().unwrap()).is_err());
    }
    assert!(
        OperationReport {
            status: OperationStatus::Prepared,
            data: Value::Null
        }
        .require_complete()
        .is_err()
    );
    assert!(
        OperationReport {
            status: OperationStatus::Applied,
            data: Value::Null
        }
        .require_complete()
        .is_ok()
    );
}

#[derive(Debug)]
struct BalanceTransport {
    missing: Option<&'static str>,
    foreign: bool,
}
impl HttpTransport for BalanceTransport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        use iroha::data_model::{
            Registrable as _,
            account::Account,
            asset::{Asset, AssetBalancePolicy, AssetDefinition},
            query::{
                QueryRequest, QueryResponse, SignedQuery, SingularQueryBox, SingularQueryOutputBox,
            },
        };
        if request.url.path() == "/v1/node/capabilities" {
            return Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(json::to_vec(
                    &norito::json!({"data_model_version": (iroha::data_model::DATA_MODEL_VERSION)}),
                )?)?);
        }
        assert_eq!(request.url.path(), "/v1/query");
        let signed = SignedQuery::decode_all_versioned(&request.body)?;
        signed.verify_signature()?;
        let authority = signed.authority().clone();
        let (name, output) = match signed.request() {
            QueryRequest::Singular(SingularQueryBox::FindAccountById(_)) => (
                "account",
                SingularQueryOutputBox::Account(
                    Account::new(if self.foreign {
                        iroha_test_samples::BOB_ID.clone()
                    } else {
                        authority.clone()
                    })
                    .build(&authority),
                ),
            ),
            QueryRequest::Singular(SingularQueryBox::FindAssetDefinitionById(_)) => (
                "definition",
                SingularQueryOutputBox::AssetDefinition(
                    AssetDefinition::numeric(
                        XOR_ASSET_DEFINITION.parse()?,
                        "XOR",
                        AssetBalancePolicy::Global,
                        None,
                    )
                    .build(&authority),
                ),
            ),
            QueryRequest::Singular(SingularQueryBox::FindAssetById(query)) => (
                "holding",
                SingularQueryOutputBox::Asset(Asset::new(query.asset_id().clone(), 77_u32)),
            ),
            _ => panic!("unexpected wallet query"),
        };
        if self.missing == Some(name) {
            return Ok(Response::builder()
                .status(404)
                .header("Content-Type", "application/x-norito")
                .body(norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
                    "query_validation_failed",
                    "fixture missing holding",
                ))?)?);
        }
        Ok(Response::builder()
            .status(200)
            .header("Content-Type", "application/x-norito")
            .body(norito::to_bytes(&QueryResponse::Singular(output))?)?)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

#[test]
fn typed_command_mismatch_rejects_saved_transfer_before_dispatch() {
    let (service, transport) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    service.prepare_transfer(&request(), &path).unwrap();
    assert!(
        service
            .submit(&path, NativeOperationKind::AliasSetup)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::AliasSetup)
            .is_err()
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    assert!(!path.join("submission.json").exists());
}

fn alias_fixture(
    config: &Config,
    noop: bool,
    amount: u32,
) -> (AliasSetupPlanRequestV1, AliasTransactionPlanV1) {
    use iroha::data_model::{alias_setup::*, isi::alias_setup::EnsureAlias};
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    let intent = AliasIntentV1::Domain(AliasDomainIntentV1 {
        domain: ResolvedDomainV1::new(
            DomainId::try_new("developer", "universal").unwrap(),
            DataSpaceId::UNIVERSAL,
        ),
        owner: config.account.clone(),
    });
    let guard = AliasQuoteGuardV1 {
        expected_policy_version: 1,
        expected_payment_asset: XOR_ASSET_DEFINITION.parse().unwrap(),
        max_amount: Quantity::from(amount),
        valid_until_ms: current_unix_ms().unwrap() + 60_000,
    };
    let ensure = EnsureAlias::new(
        intent.clone(),
        AliasLeaseAcquisitionV1::new(1, None),
        guard.clone(),
    );
    let (wire_id, framed_payload) =
        iroha::data_model::isi::framed_instruction_payload(&InstructionBox::from(ensure.clone()))
            .unwrap();
    let plan = AliasTransactionPlanV1::new(AliasTransactionPlanBodyV1 {
        version: AliasTransactionPlanBodyV1::VERSION,
        authority: config.account.clone(),
        network_id: config.network_id,
        anchor: AliasPlanAnchorV1 {
            block_height: 1,
            block_hash: iroha_crypto::Hash::new(b"native-wallet-alias-fixture"),
        },
        resources: vec![AliasPlanResourceV1 {
            intent: intent.clone(),
            disposition: if noop {
                AliasPlanDispositionV1::NoOp
            } else {
                AliasPlanDispositionV1::Create
            },
            quote: (!noop).then(|| AliasLeaseQuoteV1 {
                target: intent.target(),
                pricing_class: 0,
                exact_amount: Quantity::from(amount),
                guard: guard.clone(),
                expires_at_ms: 10,
                grace_expires_at_ms: 20,
                redemption_expires_at_ms: 30,
            }),
            instruction_index: Some(0),
        }],
        instructions: vec![AliasFramedInstructionV1 {
            wire_id: wire_id.to_owned(),
            framed_payload,
        }],
        totals_by_asset: if noop {
            vec![]
        } else {
            vec![AliasAssetTotalV1 {
                payment_asset: guard.expected_payment_asset.clone(),
                amount: Quantity::from(amount),
            }]
        },
        warnings: vec![],
        blockers: vec![],
        valid_until_ms: guard.valid_until_ms - 1,
    });
    (AliasSetupPlanRequestV1::new(vec![ensure]), plan)
}
#[test]
fn existing_alias_returns_verified_already_present_without_signing_or_journal() {
    let (service, transport) = service();
    let (request, plan) = alias_fixture(&service.config, true, 5);
    *transport.alias_plan.lock().unwrap() = Some(plan);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("alias");
    let report = service
        .prepare_alias(&request, FeePaymentIntent::authority(vec![], None), &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::AlreadyPresent);
    assert_eq!(report.data["transaction_hash"], Value::Null);
    assert_eq!(report.data["journal"], Value::Null);
    assert!(!path.exists());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    let invalid_fee = FeePaymentIntent::sponsor(
        iroha::data_model::nexus::FeeSponsorProgramId::new(
            service.config.account.clone(),
            "invalid".parse().unwrap(),
        ),
        0,
        vec![],
        None,
    );
    assert!(service.prepare_alias(&request, invalid_fee, &path).is_err());
    assert!(!path.exists());
}
#[test]
fn alias_creation_preserves_the_exact_plan_and_checks_its_rent_before_signing() {
    for amount in [5_u32, 78] {
        let (service, transport) = service();
        let (request, plan) = alias_fixture(&service.config, false, amount);
        *transport.alias_plan.lock().unwrap() = Some(plan.clone());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("alias");
        let result =
            service.prepare_alias(&request, FeePaymentIntent::authority(vec![], None), &path);
        if amount == 5 {
            assert_eq!(result.unwrap().status, OperationStatus::Prepared);
            let journal = Journal::open(&path).unwrap();
            let record: TransactionJournal = journal.read_operation().unwrap();
            assert_eq!(record.operation.kind(), NativeOperationKind::AliasSetup);
            let NativeOperation::AliasSetup {
                request: retained_request,
                plan: retained_plan,
                ..
            } = &record.operation
            else {
                panic!("alias operation required")
            };
            assert_eq!(retained_request, &request);
            assert_eq!(retained_plan.as_ref(), &plan);
            record.verify(&service.config).unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("required 78"), "{error}");
            assert!(path.join("preparation.json").is_file());
            assert!(!path.join("payload.json").exists());
            assert!(!path.join("operation.json").exists());
        }
        assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn incompatible_submission_surface_preserves_an_unattempted_operation() {
    let (service, transport) = service();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("transfer");
    transport
        .incompatible_submission
        .store(true, Ordering::SeqCst);
    assert!(service.prepare_transfer(&request(), &path).is_err());
    assert!(path.join("preparation.json").is_file());
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    transport
        .incompatible_submission
        .store(false, Ordering::SeqCst);
    service.prepare_transfer(&request(), &path).unwrap();
    transport
        .incompatible_submission
        .store(true, Ordering::SeqCst);
    let error = service
        .submit(&path, NativeOperationKind::Transfer)
        .unwrap_err();
    assert!(error.to_string().contains("unattempted"));
    assert!(!path.join("submission.json").exists());
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

pub(super) fn private_root_fixture() -> (
    iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture,
    PrivateDataspaceRegistration,
) {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
        sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
    };
    let dataspace = iroha_model_base::topology::DataSpaceId::from_hash(
        &NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "walletroot")
            .unwrap()
            .name_hash(),
    );
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: fixture_config().network_id,
        dataspace_id: dataspace,
    };
    let fixture = NativeFinalityFixture::start_with_scope("wallet-private-root", scope);
    let genesis = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let registration = PrivateDataspaceRegistration::new(
        scope,
        fixture.chain_id().parse().unwrap(),
        fixture.network_id(),
        genesis.result().0,
        authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    (fixture, registration)
}

pub(super) fn private_options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            XOR_ASSET_DEFINITION.parse().unwrap(),
            Quantity::from(10_u32),
        )]),
        deadline: std::time::Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn private_registration_is_exact_bounded_and_recovery_never_resubmits() {
    let (service, transport) = service();
    let (_fixture, registration) = private_root_fixture();
    let request = PrivateRootRegistrationRequest {
        alias: "walletroot".into(),
        expected_ownership_generation: u64::MAX,
        registration,
        options: private_options(),
    };
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("registration");
    let report = service
        .prepare_private_root_registration(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    assert_eq!(
        report.data["operation"].as_str(),
        Some("private_root_registration")
    );
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let transaction = record.verify(&service.config).unwrap();
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("native registration")
    };
    assert_eq!(instructions.len(), 1);
    let isi = instructions[0]
        .as_any()
        .downcast_ref::<iroha_data_model::isi::private_dataspace::RegisterPrivateDataspace>()
        .unwrap();
    assert_eq!(isi.alias(), "walletroot");
    assert_eq!(*isi.expected_ownership_generation(), u64::MAX);
    assert_eq!(
        PrivateDataspaceRegistration::decode(isi.registration()).unwrap(),
        request.registration
    );
    assert!(record.deadline_ms <= record.operation.bounded_terms().unwrap().deadline_ms);
    assert!(
        record.deadline_ms - u64::try_from(transaction.creation_time().as_millis()).unwrap()
            <= 5000
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::PrivateRootAnchor)
            .is_err()
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    service
        .verify_private_root_registration_journal(&path, &request)
        .unwrap();
    let mut changed_request = request.clone();
    changed_request.expected_ownership_generation = 1;
    assert!(
        service
            .submit_private_root_registration(&path, &changed_request)
            .is_err()
    );
    changed_request = request.clone();
    changed_request
        .options
        .max_total_fees
        .values_mut()
        .for_each(|maximum| *maximum = Quantity::from(20_u32));
    assert!(
        service
            .verify_private_root_registration_journal(&path, &changed_request)
            .is_err()
    );
    assert!(
        service
            .submit(&path, NativeOperationKind::PrivateRootRegistration)
            .is_err()
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    *transport.journal.lock().unwrap() = Some(path.clone());
    assert_eq!(
        service
            .submit_private_root_registration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        service
            .submit_private_root_registration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        service
            .resume_private_root_registration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let mut recovery = request.clone();
    recovery.options.deadline = std::time::Instant::now() + Duration::from_secs(60);
    assert_eq!(
        service
            .resume_private_root_registration(&path, &recovery)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let recovered: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(
        norito::json::to_vec(&record).unwrap(),
        norito::json::to_vec(&recovered).unwrap(),
        "a fresh recovery I/O deadline never extends the signed deadline or original fee limits"
    );
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 1);
    let mut changed: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    if let NativeOperation::PrivateRootRegistration {
        expected_ownership_generation,
        ..
    } = &mut changed.operation
    {
        *expected_ownership_generation = 1;
    }
    assert!(changed.verify(&service.config).is_err());
}

#[test]
fn private_operation_http_deadline_cannot_be_extended() {
    let (service, transport) = service();
    let original = std::time::Instant::now() + Duration::from_secs(5);
    let bounded = service.with_deadline(original).unwrap();
    let repeated = bounded
        .with_deadline(original + Duration::from_secs(30))
        .unwrap();
    assert_eq!(repeated.deadline, Some(original));
    assert!(repeated.with_deadline(std::time::Instant::now()).is_err());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn wallet_deadline_view_keeps_identity_cancellation_and_signed_journal_after_drop() {
    let (source, transport) = service();
    let signal = Arc::new(AtomicBool::new(false));
    let source = source.with_cancellation(Arc::clone(&signal)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let bounded = source.with_deadline(deadline).unwrap();
    assert_eq!(source.deadline, None);
    assert_eq!(bounded.deadline, Some(deadline));
    assert!(Arc::ptr_eq(
        source.cancellation.as_ref().unwrap(),
        bounded.cancellation.as_ref().unwrap()
    ));
    assert_eq!(
        source.client.account_client().authority(),
        bounded.client.account_client().authority()
    );
    assert_eq!(
        source.client.account_client().network_id(),
        bounded.client.account_client().network_id()
    );
    assert_eq!(
        source.client.account_client().endpoint(),
        bounded.client.account_client().endpoint()
    );
    assert_eq!(
        source.client.account_client().signing_capability(),
        bounded.client.account_client().signing_capability()
    );
    assert_eq!(
        source.client.client().key_pair().public_key(),
        bounded.client.client().key_pair().public_key()
    );
    assert_eq!(
        source.client.client().headers(),
        bounded.client.client().headers()
    );
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("deadline-transfer");
    let expected = request();
    let prepared = bounded.prepare_transfer(&expected, &path).unwrap();
    assert_eq!(prepared.status, OperationStatus::Prepared);
    let signed = std::fs::read(path.join("operation.json")).unwrap();
    let retained = bounded
        .inspect_transfer_preparation(&path, &expected)
        .unwrap();
    let original_hash = retained.signed_transaction().unwrap().hash();
    assert_eq!(retained.phase(), NativePreparationPhase::Signed);
    drop(bounded);
    let before = transport.requests.load(Ordering::SeqCst);
    let inspected = source
        .inspect_transfer_preparation(&path, &expected)
        .unwrap();
    assert_eq!(inspected.phase(), NativePreparationPhase::Signed);
    assert_eq!(
        inspected.signed_transaction().unwrap().hash(),
        original_hash
    );
    assert!(source.with_deadline(std::time::Instant::now()).is_err());
    let shorter = source
        .with_deadline(deadline - Duration::from_secs(10))
        .unwrap();
    signal.store(true, Ordering::Release);
    assert!(
        shorter
            .prepare_transfer(&expected, &temporary.path().join("cancelled"))
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), signed);
    assert_eq!(source.deadline, None);
}

#[test]
fn bounded_alias_preserves_exact_request_fee_limits_and_wire_through_recovery() {
    let (service, transport) = service();
    let (request, plan) = alias_fixture(&service.config, false, 5);
    *transport.alias_plan.lock().unwrap() = Some(plan);
    let options = private_options();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("bounded-alias");
    assert_eq!(
        service
            .prepare_alias_bounded(&request, &options, &path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert!(record.operation.bounded_terms().is_some());
    record.verify(&service.config).unwrap();
    service
        .verify_alias_journal(&path, &request, &options)
        .unwrap();
    let (changed_request, _) = alias_fixture(&service.config, false, 6);
    assert!(
        service
            .submit_alias_bounded(&path, &changed_request, &options)
            .is_err()
    );
    let mut changed_options = options.clone();
    changed_options.max_total_fees.clear();
    assert!(
        service
            .resume_alias_bounded(&path, &request, &changed_options)
            .is_err()
    );
    assert!(
        service
            .submit(&path, NativeOperationKind::AliasSetup)
            .is_err()
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    *transport.journal.lock().unwrap() = Some(path.clone());
    assert_eq!(
        service
            .submit_alias_bounded(&path, &request, &options)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let mut recovery = options;
    recovery.deadline = std::time::Instant::now() + Duration::from_secs(60);
    assert_eq!(
        service
            .resume_alias_bounded(&path, &request, &recovery)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        service
            .submit_alias_bounded(&path, &request, &recovery)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let after: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(
        norito::json::to_vec(&record).unwrap(),
        norito::json::to_vec(&after).unwrap()
    );
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 1);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 1);
    let mut missing: Value = norito::json::to_value(&record).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .get_mut("operation")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("value")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("bounds");
    assert!(norito::json::from_value::<TransactionJournal>(missing).is_err());
}

#[test]
fn bounded_alias_expiry_and_verified_noop_never_create_a_journal_or_submit() {
    let (service, transport) = service();
    let (request, plan) = alias_fixture(&service.config, true, 5);
    *transport.alias_plan.lock().unwrap() = Some(plan);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("bounded-alias");
    let mut options = private_options();
    options.deadline = std::time::Instant::now();
    assert!(
        service
            .prepare_alias_bounded(&request, &options, &path)
            .is_err()
    );
    assert!(!path.exists());
    options.deadline = std::time::Instant::now() + Duration::from_secs(5);
    assert_eq!(
        service
            .prepare_alias_bounded(&request, &options, &path)
            .unwrap()
            .status,
        OperationStatus::AlreadyPresent
    );
    assert!(!path.exists());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn private_registration_rejects_foreign_parent_alias_and_expiry_before_http_or_journal() {
    let (service, transport) = service();
    let (_fixture, registration) = private_root_fixture();
    let temporary = tempfile::tempdir().unwrap();
    for alias in ["different", "WalletRoot", "universal"] {
        let request = PrivateRootRegistrationRequest {
            alias: alias.into(),
            expected_ownership_generation: 1,
            registration: registration.clone(),
            options: private_options(),
        };
        assert!(
            service
                .prepare_private_root_registration(&request, &temporary.path().join(alias))
                .is_err()
        );
    }
    let mut request = PrivateRootRegistrationRequest {
        alias: "walletroot".into(),
        expected_ownership_generation: 0,
        registration,
        options: private_options(),
    };
    assert!(
        service
            .prepare_private_root_registration(&request, &temporary.path().join("zero"))
            .is_err()
    );
    request.expected_ownership_generation = 1;
    let mut other = service.config.clone();
    other.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"foreign wallet parent",
        )),
    );
    assert!(
        private_root::registration_instruction(&other, &request.alias, 1, &request.registration)
            .is_err()
    );
    request.options.deadline = std::time::Instant::now();
    assert!(
        service
            .prepare_private_root_registration(&request, &temporary.path().join("expired"))
            .is_err()
    );
    assert!(service.with_deadline(request.options.deadline).is_err());
    assert_eq!(transport.quote_count.load(Ordering::SeqCst), 0);
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn private_anchor_preparation_requires_a_genuine_contiguous_scoped_certificate() {
    let (service, transport) = service();
    let (mut fixture, registration) = private_root_fixture();
    let state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration.clone()).unwrap();
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    let anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap();
    let request = PrivateRootAnchorRequest {
        state,
        anchor,
        options: private_options(),
    };
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("anchor");
    let report = service
        .prepare_private_root_anchor(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    assert_eq!(
        report.data["operation"].as_str(),
        Some("private_root_anchor")
    );
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let transaction = record.verify(&service.config).unwrap();
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("native anchor")
    };
    assert_eq!(instructions.len(), 1);
    let isi = instructions[0]
        .as_any()
        .downcast_ref::<iroha_data_model::isi::private_dataspace::AnchorPrivateDataspace>()
        .unwrap();
    assert_eq!(
        PrivateDataspaceAnchor::decode(isi.anchor()).unwrap(),
        request.anchor
    );
    service
        .verify_private_root_anchor_journal(&path, &request)
        .unwrap();
    assert_eq!(
        service
            .resume_private_root_anchor(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    let mut hostile = request.clone();
    hostile.anchor.child_network_id = service.config.network_id;
    assert!(
        service
            .verify_private_root_anchor_journal(&path, &hostile)
            .is_err()
    );
    assert!(service.submit_private_root_anchor(&path, &hostile).is_err());

    assert!(
        service
            .prepare_private_root_anchor(&hostile, &temporary.path().join("foreign"))
            .is_err()
    );
    let mut advanced = request.state.clone();
    advanced.apply(&request.anchor).unwrap();
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    hostile.anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap();
    assert!(
        service
            .prepare_private_root_anchor(&hostile, &temporary.path().join("gap"))
            .is_err()
    );
    hostile.state = advanced;
    assert!(
        service
            .prepare_private_root_anchor(&hostile, &temporary.path().join("next"))
            .is_ok()
    );
    assert_eq!(transport.dispatch_count.load(Ordering::SeqCst), 0);
}

#[test]
fn private_fee_totals_and_explicit_component_maxima_cannot_be_increased_by_a_quote() {
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit};
    let asset: AssetDefinitionId = XOR_ASSET_DEFINITION.parse().unwrap();
    let limit = |kind, amount| FeeChargeLimit::new(kind, asset.clone(), Quantity::from(amount));
    let options = private_options();
    let terms = BoundedTerms::new(&options).unwrap();
    let mut quote = FeeQuoteResponse {
        intent: FeePaymentIntent::authority(
            vec![
                limit(FeeChargeKind::Nexus, 6_u32),
                limit(FeeChargeKind::PipelineGas, 5_u32),
            ],
            None,
        ),
        observation: iroha_torii_shared::FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 2,
            route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        },
        components: Vec::new(),
        capacities: Vec::new(),
        decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(
                fixture_config().account,
            ),
            program_revision: None,
        },
    };
    assert!(
        terms.verify_quote(&quote).is_err(),
        "combined fee11 exceeds explicit total10"
    );
    quote.intent = FeePaymentIntent::authority(
        vec![
            limit(FeeChargeKind::Nexus, 5_u32),
            limit(FeeChargeKind::PipelineGas, 5_u32),
        ],
        None,
    );
    assert!(terms.verify_quote(&quote).is_ok());
    let requested = FeePaymentIntent::authority(
        vec![
            limit(FeeChargeKind::Nexus, 4_u32),
            limit(FeeChargeKind::PipelineGas, 5_u32),
        ],
        None,
    );
    assert!(
        verify_quote_limits(&requested, &quote).is_err(),
        "a fitting total cannot enlarge explicit component4 to5"
    );
    let empty_terms = BoundedTerms::new(&BoundedTransactionOptions {
        max_total_fees: BTreeMap::new(),
        ..options
    })
    .unwrap();
    assert!(
        empty_terms.verify_quote(&quote).is_err(),
        "unlisted currencies are never authorized"
    );
}
