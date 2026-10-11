//! Structural top-up intent and real journal tests; mock quotes/status confer no native authority.
//! No successful movement, transfer, approval, collateral or service readiness is simulated.

use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::sorafs::{
    pin_registry::StorageClass,
    reserve::{
        RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveDuration, ReserveLifecycleStage,
        ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
    },
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

#[derive(Debug, Default)]
struct Transport {
    requests: AtomicUsize,
    quotes: AtomicUsize,
    submitted: Mutex<Vec<Vec<u8>>>,
    journal: Mutex<Option<std::path::PathBuf>>,
}
impl HttpTransport for Transport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let (status, body) = match request.url.path() {
            "/v1/node/capabilities" => (
                200,
                norito::json::to_vec(&norito::json!({
                    "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                    "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
                }))?,
            ),
            "/v1/fees/quote" => {
                self.quotes.fetch_add(1, Ordering::SeqCst);
                let request: iroha_torii_shared::FeeQuoteRequest =
                    norito::json::from_slice(&request.body)?;
                (
                    200,
                    norito::json::to_vec(&empty_quote(
                        request.payload.authority(),
                        request.payload.fee_payment_intent(),
                    ))?,
                )
            }
            "/v1/pipeline/transactions/status" => {
                assert_eq!(request.method, iroha::http::Method::GET);
                let hash = request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "hash")
                    .unwrap()
                    .1
                    .parse::<iroha_crypto::HashOf<SignedTransaction>>()?;
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
                (404, norito::json::to_vec(&absence)?)
            }
            path if path == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path() => {
                assert_eq!(request.method, iroha::http::Method::POST);
                let held = self.journal.lock().unwrap();
                let path = held
                    .as_ref()
                    .expect("top_up must be retained before dispatch");
                assert!(path.join("operation.json").is_file());
                assert!(path.join("submission.json").is_file());
                self.submitted.lock().unwrap().push(request.body);
                (503, b"unavailable".to_vec())
            }
            path => panic!("unexpected top_up HTTP request {path}"),
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

fn empty_quote(authority: &AccountId, intent: &FeePaymentIntent) -> FeeQuoteResponse {
    FeeQuoteResponse {
        intent: intent.clone(),
        observation: iroha_torii_shared::FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 1,
            route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        },
        components: Vec::new(),
        capacities: Vec::new(),
        decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(authority.clone()),
            program_revision: None,
        },
    }
}
fn service_with(config: Config, transport: Arc<Transport>) -> AccountService {
    let client = Client::with_http_transport(config.clone(), transport).unwrap();
    AccountService {
        config,
        client,
        deadline: None,
        cancellation: None,
    }
}
fn service() -> (AccountService, Arc<Transport>) {
    let transport = Arc::new(Transport::default());
    (
        service_with(super::super::tests::fixture_config(), transport.clone()),
        transport,
    )
}
fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
fn request(config: &Config, now: u64) -> ReserveTopUpRequest {
    let policy = ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: XOR_ASSET_DEFINITION.parse().unwrap(),
        custody_account: account(20),
        treasury_account: account(21),
        // A top-up is provider-owned, unlike operations-authorized registration.
        operations_authority: account(22),
        decision_authority: account(23),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    };
    let partition = ReserveProviderAccountV1 {
        terms: ReserveProviderTermsV1 {
            provider_id: ProviderId::new([42; 32]),
            provider_account: config.account.clone(),
            tier: ReserveTier::TierA,
            storage_class: StorageClass::Hot,
            duration: ReserveDuration::Monthly,
            capacity_gib: 1,
        },
        policy_digest: policy.digest().unwrap(),
        revision: 7,
        reserve_balance: XorQuantity::zero(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::zero(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    };
    ReserveTopUpRequest {
        selection: ReserveTopUpSelection {
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            operations_authority: policy.operations_authority.clone(),
            provider_id: partition.terms.provider_id,
            provider_account: partition.terms.provider_account.clone(),
            expected_provider_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy,
        partition,
        movement_id: [51; 32],
        amount: XorQuantity::try_from_micro(5_000_000).unwrap(),
        deadline_unix_ms: now + 180_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(180),
        },
    }
}

#[test]
fn top_up_reports_exact_provider_signed_request_without_claiming_native_state() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("top_up");
    let report = service.prepare_reserve_top_up(&request, &path).unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    assert!(!report.status.is_complete());
    assert_eq!(
        report.data["operation"].as_str(),
        Some("reserve_top_up_request")
    );
    let calls = transport.requests.load(Ordering::SeqCst);
    let signed = service
        .verify_reserve_top_up_journal(&path, &request)
        .unwrap();
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(
        signed.encode_versioned(),
        hex::decode(&record.signed_transaction_hex).unwrap()
    );
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("native top-up request")
    };
    assert_eq!(instructions.len(), 1);
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<RequestSorafsReserveMovement>()
        .unwrap();
    assert_eq!(instruction.provider_id, request.selection.provider_id);
    assert_eq!(instruction.kind, ReserveMovementKindV1::TopUp);
    assert_eq!(instruction.movement_id, request.movement_id);
    assert_eq!(instruction.amount, request.amount);
    assert_eq!(
        instruction.expected_provider_revision,
        request.selection.expected_provider_revision
    );
    assert_eq!(report.data["request_kind"].as_str(), Some("top_up"));
    assert_eq!(
        report.data["transfers_reserve_assets"].as_bool(),
        Some(false)
    );
    assert_eq!(instruction.policy_digest, request.policy.digest().unwrap());
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    assert_eq!(signed.authority(), &request.selection.provider_account);
    assert_ne!(signed.authority(), &request.policy.operations_authority);
    assert_ne!(signed.authority(), &request.policy.decision_authority);
    assert!(
        record
            .operation
            .principal(&service.config.account)
            .unwrap()
            .is_empty()
    );
    assert!(record.deadline_ms <= request.deadline_unix_ms);
    // No authenticated policy, partition, movement or backing exists in this transport.
    assert!(
        service
            .submit(&path, NativeOperationKind::ReserveTopUpRequest)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::ReserveTopUpRequest)
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn every_identity_and_structural_term_refuses_before_http_or_publication() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let mut variants = Vec::new();
    macro_rules! changed {
        ($value:ident, $body:block) => {{
            let mut $value = request.clone();
            $body
            variants.push($value);
        }};
    }
    changed!(r, {
        r.selection.chain_id.push('x');
    });
    changed!(r, {
        r.selection.network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other genesis")),
        );
    });
    changed!(r, {
        r.selection.operations_authority = account(99);
    });
    changed!(r, {
        // Keeping the selected owner and partition consistent still cannot change the signer.
        r.partition.terms.provider_account = r.policy.operations_authority.clone();
        r.selection.provider_account = r.partition.terms.provider_account.clone();
    });
    changed!(r, {
        r.selection.provider_id = ProviderId::new([43; 32]);
    });
    changed!(r, {
        r.selection.provider_account = account(99);
    });
    changed!(r, {
        r.selection.policy_digest[0] ^= 1;
    });
    changed!(r, {
        r.selection.asset_definition = different_asset(44);
    });
    changed!(r, {
        r.selection.custody_account = account(99);
    });
    changed!(r, {
        r.selection.treasury_account = account(99);
    });
    changed!(r, {
        r.selection.decision_authority = account(99);
    });
    changed!(r, {
        r.partition.terms.provider_id = ProviderId::default();
        r.selection.provider_id = r.partition.terms.provider_id;
    });
    changed!(r, {
        r.partition.terms.provider_account = r.policy.custody_account.clone();
        r.selection.provider_account = r.partition.terms.provider_account.clone();
    });
    changed!(r, {
        r.partition.terms.capacity_gib = 0;
    });
    changed!(r, {
        r.selection.expected_provider_revision += 1;
    });
    changed!(r, {
        r.partition.revision = 0;
        r.selection.expected_provider_revision = 0;
    });
    changed!(r, {
        r.partition.revision = u64::MAX;
        r.selection.expected_provider_revision = u64::MAX;
    });
    changed!(r, {
        r.selection.partition_policy_digest[0] ^= 1;
    });
    changed!(r, {
        r.partition.policy_digest = [0; 32];
        r.selection.partition_policy_digest = [0; 32];
    });
    changed!(r, {
        r.movement_id = [0; 32];
    });
    changed!(r, {
        r.amount = XorQuantity::zero();
    });
    changed!(r, {
        r.partition.pending_movements = r.policy.max_pending_movements_per_provider;
    });
    changed!(r, {
        r.partition.updated_at_unix = 0;
    });
    changed!(r, {
        r.partition.rent_charged_through_unix = r.partition.updated_at_unix + 1;
    });
    changed!(r, {
        r.partition.debt_principal = XorQuantity::try_from_micro(1).unwrap();
    });
    changed!(r, {
        r.policy.max_pending_movements_per_provider = 0;
        r.selection.policy_digest = r.policy.digest().unwrap();
    });
    changed!(r, {
        r.policy
            .economics
            .rent_rates
            .retain(|rate| rate.storage_class != r.partition.terms.storage_class);
        r.selection.policy_digest = r.policy.digest().unwrap();
    });
    changed!(r, {
        r.policy
            .economics
            .tiers
            .retain(|tier| tier.tier != r.partition.terms.tier);
        r.selection.policy_digest = r.policy.digest().unwrap();
    });
    for deadline in [0, current_unix_ms().unwrap() - 1, u64::MAX] {
        changed!(r, {
            r.deadline_unix_ms = deadline;
        });
    }
    let root = tempfile::tempdir().unwrap();
    for (index, changed) in variants.iter().enumerate() {
        let path = root.path().join(index.to_string());
        assert!(
            service.prepare_reserve_top_up(changed, &path).is_err(),
            "variant {index}"
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

fn different_asset(value: u8) -> AssetDefinitionId {
    let mut bytes = [value; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    AssetDefinitionId::from_uuid_bytes(bytes).unwrap()
}

#[test]
fn held_journal_rejects_policy_partition_and_fee_substitution_before_once_only_reopen() {
    let (service, transport) = service();
    let mut request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("top_up");
    service.prepare_reserve_top_up(&request, &path).unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let before = std::fs::read(path.join("operation.json")).unwrap();
    let wire = service
        .verify_reserve_top_up_journal(&path, &request)
        .unwrap()
        .encode_versioned();
    let mut variants = Vec::new();
    macro_rules! changed {
        ($value:ident, $body:block) => {{ let mut $value = request.clone(); $body variants.push($value); }};
    }
    changed!(r, {
        r.deadline_unix_ms += 1;
    });
    changed!(r, {
        r.movement_id[0] ^= 1;
    });
    changed!(r, {
        r.amount = XorQuantity::try_from_micro(6_000_000).unwrap();
    });
    changed!(r, {
        r.partition.revision += 1;
        r.selection.expected_provider_revision += 1;
    });
    changed!(r, {
        r.partition.policy_digest[0] ^= 1;
        r.selection.partition_policy_digest = r.partition.policy_digest;
    });
    changed!(r, {
        r.partition.reserve_balance = XorQuantity::try_from_micro(1).unwrap();
    });
    changed!(r, {
        r.partition.pending_movements += 1;
    });
    changed!(r, {
        r.partition.updated_at_unix += 1;
    });
    changed!(r, {
        r.policy.grace_period_days += 1;
        r.selection.policy_digest = r.policy.digest().unwrap();
    });
    changed!(r, {
        r.policy.custody_account = account(98);
        r.selection.custody_account = r.policy.custody_account.clone();
        r.selection.policy_digest = r.policy.digest().unwrap();
    });
    changed!(r, {
        r.partition.terms.provider_id = ProviderId::new([43; 32]);
        r.selection.provider_id = r.partition.terms.provider_id;
    });
    changed!(r, {
        r.partition.terms.provider_account = account(99);
        r.selection.provider_account = r.partition.terms.provider_account.clone();
    });
    changed!(r, {
        r.partition.terms.capacity_gib += 1;
    });
    changed!(r, {
        r.partition.terms.tier = ReserveTier::TierB;
    });
    changed!(r, {
        r.partition.terms.storage_class = StorageClass::Cold;
    });
    changed!(r, {
        r.partition.terms.duration = ReserveDuration::Annual;
    });
    changed!(r, {
        r.options
            .max_total_fees
            .insert(r.policy.asset_definition.clone(), Quantity::from(1u32));
    });
    changed!(r, {
        r.options.fee_payment =
            FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(99));
    });
    let calls = transport.requests.load(Ordering::SeqCst);
    for changed in variants {
        assert!(
            service
                .verify_reserve_top_up_journal(&path, &changed)
                .is_err()
        );
        assert!(service.submit_reserve_top_up(&path, &changed).is_err());
        assert!(service.resume_reserve_top_up(&path, &changed).is_err());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(
        service
            .resume_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        service
            .submit_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let marker = std::fs::read(path.join("submission.json")).unwrap();
    let config = service.config.clone();
    drop(service);
    let reopened = service_with(config, transport.clone());
    request.options.deadline = Instant::now() + Duration::from_secs(300);
    assert_eq!(
        reopened
            .submit_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        reopened
            .resume_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        reopened
            .verify_reserve_top_up_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        wire
    );
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(std::fs::read(path.join("submission.json")).unwrap(), marker);
    assert_eq!(transport.submitted.lock().unwrap().as_slice(), &[wire]);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_original_is_readable_but_fresh_prepare_and_dispatch_cannot_renew_it() {
    let (service, transport) = service();
    let original_time = current_unix_ms().unwrap() - 400_000;
    let mut request = request(&service.config, original_time);
    let plan = Plan::new(&request, original_time).unwrap();
    let mut terms = BoundedTerms::new(&request.options).unwrap();
    terms.deadline_ms = request.deadline_unix_ms;
    let operation = NativeOperation::ReserveTopUpRequest {
        plan: encode_bounded(&plan, MAX_PLAN_BYTES).unwrap(),
        terms,
    };
    let mut builder = iroha_data_model::transaction::TransactionBuilder::new(
        service.config.network_id,
        service.config.account.clone(),
        request.options.fee_payment.clone(),
    )
    .with_instructions(operation.instructions(&service.config).unwrap());
    builder.set_creation_time(Duration::from_millis(original_time));
    builder.set_ttl(Duration::from_millis(
        request.deadline_unix_ms - original_time,
    ));
    let signed = builder.sign(service.config.key_pair.private_key());
    let record = TransactionJournal {
        schema: "iroha.wallet.native-transaction.v1".into(),
        torii_url: service.config.torii_api_url.to_string(),
        chain_id: service.config.chain.to_string(),
        network_id: service.config.network_id,
        chain_discriminant: service.config.account_chain_discriminant,
        account_id: service.config.account.clone(),
        operation,
        requested_fee: request.options.fee_payment.clone(),
        quote: empty_quote(&service.config.account, &request.options.fee_payment),
        transaction_hash: signed.hash().to_string(),
        signed_transaction_hex: hex::encode(signed.encode_versioned()),
        deadline_ms: request.deadline_unix_ms,
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("historical");
    drop(preparation::retain_signed_fixture(&path, &record).unwrap());
    let before = std::fs::read(path.join("operation.json")).unwrap();
    request.options.deadline = Instant::now() + Duration::from_secs(300);
    assert_eq!(
        service
            .verify_reserve_top_up_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_reserve_top_up(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_reserve_top_up(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!root.path().join("fresh").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn component_fee_and_canonical_plan_bounds_reject_before_publication() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.selection.chain_id = "x".repeat(MAX_SELECTION_BYTES);
    variants.push(changed);
    let mut changed = request.clone();
    changed.policy.economics.rent_rates =
        vec![changed.policy.economics.rent_rates[0].clone(); MAX_POLICY_BYTES];
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.deadline = Instant::now() - Duration::from_secs(1);
    variants.push(changed);
    let mut changed = request.clone();
    changed
        .options
        .max_total_fees
        .insert(request.policy.asset_definition.clone(), Quantity::zero());
    variants.push(changed);
    let mut changed = request.clone();
    for value in 1..=17u8 {
        changed
            .options
            .max_total_fees
            .insert(different_asset(value), Quantity::from(1u32));
    }
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.fee_payment = FeePaymentIntent::authority(
        (1..=17u8)
            .map(|value| {
                iroha_data_model::transaction::FeeChargeLimit::new(
                    iroha_data_model::transaction::FeeChargeKind::Nexus,
                    different_asset(value),
                    Quantity::from(1u32),
                )
            })
            .collect(),
        None,
    );
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.fee_payment = FeePaymentIntent::sponsor(
        iroha_data_model::nexus::FeeSponsorProgramId::new(account(98), "top_up".parse().unwrap()),
        1,
        Vec::new(),
        None,
    );
    variants.push(changed);
    let root = tempfile::tempdir().unwrap();
    for (index, changed) in variants.iter().enumerate() {
        let path = root.path().join(index.to_string());
        assert!(service.prepare_reserve_top_up(changed, &path).is_err());
        assert!(!path.exists());
    }
    let plan = Plan::new(&request, current_unix_ms().unwrap()).unwrap();
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(instructions(&service.config, &bytes, request.deadline_unix_ms + 1).is_err());
    assert!(instructions(&service.config, &bytes, plan.validated_at_unix_ms).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(instructions(&service.config, &trailing, request.deadline_unix_ms).is_err());
    assert!(
        instructions(
            &service.config,
            &vec![0; MAX_PLAN_BYTES + 1],
            request.deadline_unix_ms
        )
        .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn retained_top_up_rejects_extra_signed_instruction_wire_and_purpose() {
    let (service, _) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("top_up");
    service.prepare_reserve_top_up(&request, &path).unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    let mut changed = record.clone();
    changed.signed_transaction_hex.push_str("00");
    assert!(changed.verify(&service.config).is_err());
    let instruction = Plan::new(&request, current_unix_ms().unwrap())
        .unwrap()
        .instruction(&service.config)
        .unwrap();
    let mut payload = original.payload().clone();
    payload.instructions = vec![instruction.clone(), instruction].into();
    let signed = service
        .client
        .account_client()
        .sign_transaction(payload)
        .unwrap();
    let mut changed = record.clone();
    changed.signed_transaction_hex = hex::encode(signed.encode_versioned());
    changed.transaction_hash = signed.hash().to_string();
    assert!(changed.verify(&service.config).is_err());
    let mut payload = original.payload().clone();
    payload.instructions = vec![InstructionBox::from(RequestSorafsReserveMovement::new(
        request.movement_id,
        request.selection.provider_id,
        ReserveMovementKindV1::Withdrawal,
        request.amount.clone(),
        request.selection.expected_provider_revision,
        request.selection.policy_digest,
    ))]
    .into();
    let signed = service
        .client
        .account_client()
        .sign_transaction(payload)
        .unwrap();
    let mut changed = record.clone();
    changed.signed_transaction_hex = hex::encode(signed.encode_versioned());
    changed.transaction_hash = signed.hash().to_string();
    assert!(changed.verify(&service.config).is_err());
    let mut payload = original.payload().clone();
    payload.metadata.insert(
        "unexpected".parse().unwrap(),
        iroha_primitives::json::Json::new(true),
    );
    let signed = service
        .client
        .account_client()
        .sign_transaction(payload)
        .unwrap();
    let mut changed = record.clone();
    changed.signed_transaction_hex = hex::encode(signed.encode_versioned());
    changed.transaction_hash = signed.hash().to_string();
    assert!(changed.verify(&service.config).is_err());
    let mut changed = record;
    changed.operation = NativeOperation::InitialReservePolicy {
        plan: Vec::new(),
        terms: BoundedTerms::new(&request.options).unwrap(),
    };
    assert!(
        ReserveTopUpExpectation(&request)
            .verify(&preparation::Selection {
                operation: &changed.operation,
                requested_fee: &changed.requested_fee,
                deadline_ms: changed.deadline_ms
            })
            .is_err()
    );
}

#[test]
fn lagging_partition_is_retained_under_rotated_policy_without_signer_role_substitution() {
    let (service, transport) = service();
    let mut request = request(&service.config, current_unix_ms().unwrap());
    request.policy.revision = 2;
    request.policy.predecessor_policy_digest = Some(request.selection.policy_digest);
    request.selection.policy_digest = request.policy.digest().unwrap();
    assert_ne!(
        request.partition.policy_digest,
        request.selection.policy_digest
    );
    let original_partition = encode_bounded(&request.partition, MAX_PARTITION_BYTES).unwrap();
    let plan = Plan::new(&request, current_unix_ms().unwrap()).unwrap();
    let instruction = plan.instruction(&service.config).unwrap();
    assert_eq!(
        encode_bounded(&plan.partition, MAX_PARTITION_BYTES).unwrap(),
        original_partition
    );
    let mut operator_config = service.config.clone();
    operator_config.account = request.policy.operations_authority.clone();
    assert!(plan.instruction(&operator_config).is_err());
    assert_eq!(
        instruction
            .as_any()
            .downcast_ref::<RequestSorafsReserveMovement>()
            .unwrap()
            .policy_digest,
        request.selection.policy_digest
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_original_recovery_never_creates_a_request_or_uses_http() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("never-prepared");
    assert!(
        service
            .verify_reserve_top_up_journal(&path, &request)
            .is_err()
    );
    assert!(service.resume_reserve_top_up(&path, &request).is_err());
    assert!(service.submit_reserve_top_up(&path, &request).is_err());
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn retain_reserve_top_up_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_reserve_top_up_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_reserve_top_up_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_reserve_top_up_request(&changed, &path)
            .is_err()
    );
    assert_eq!(
        transport.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );

    service.prepare_reserve_top_up(&request, &path).unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_reserve_top_up_request(&request, &path)
        .unwrap();
    assert_eq!(signed.phase(), NativePreparationPhase::Signed);
    assert_eq!(signed.request_sha256(), Some(commitment.as_str()));
    assert_eq!(
        std::fs::read(path.join("preparation.json")).unwrap(),
        original
    );
    // Genuine durable prefix before signature publication; retain cannot finish the payload.
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let partial = service
        .retain_reserve_top_up_request(&request, &path)
        .unwrap();
    assert_eq!(partial.phase(), NativePreparationPhase::PayloadRetained);
    assert_eq!(partial.request_sha256(), Some(commitment.as_str()));
    assert!(!path.join("operation.json").exists());
    assert_eq!(
        transport.requests.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
}

#[test]
fn retained_parent_inspection_keeps_exact_signed_preparation_and_offline_refusals() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open_or_create(root.path().join("parent")).unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    assert_eq!(
        service
            .inspect_reserve_top_up_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    assert_eq!(
        service
            .prepare_reserve_top_up(&request, &path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let calls = transport.requests.load(Ordering::SeqCst);
    let before = ["preparation.json", "payload.json", "operation.json"]
        .map(|record| std::fs::read(path.join(record)).unwrap());
    let absolute = service
        .inspect_reserve_top_up_preparation(&path, &request)
        .unwrap();
    let retained = service
        .inspect_reserve_top_up_preparation_in_parent(&parent, name, &request)
        .unwrap();
    assert_eq!(retained.phase(), NativePreparationPhase::Signed);
    assert_eq!(retained.phase(), absolute.phase());
    assert_eq!(retained.request_sha256(), absolute.request_sha256());
    assert_eq!(
        retained.signed_transaction().unwrap().encode_versioned(),
        absolute.signed_transaction().unwrap().encode_versioned()
    );
    let mut changed = request.clone();
    changed.deadline_unix_ms -= 1;
    assert!(
        service
            .inspect_reserve_top_up_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert_eq!(
        service
            .inspect_reserve_top_up_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .into_signed_transaction()
            .unwrap()
            .encode_versioned(),
        absolute
            .into_signed_transaction()
            .unwrap()
            .encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        ["preparation.json", "payload.json", "operation.json"]
            .map(|record| std::fs::read(path.join(record)).unwrap()),
        before
    );
}
