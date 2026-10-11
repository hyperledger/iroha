//! Structural provider-credit intent and genuine wallet journals; mock responses confer no native authority.
//! Current record absence, policy, custody backing and successful native CAS are never simulated.

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
use sorafs_manifest::deal::XorQuantity;
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
                    .expect("provider_credit must be retained before dispatch");
                assert!(path.join("operation.json").is_file());
                assert!(path.join("submission.json").is_file());
                self.submitted.lock().unwrap().push(request.body);
                (503, b"unavailable".to_vec())
            }
            path => panic!("unexpected provider_credit HTTP request {path}"),
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
fn request(config: &Config, now: u64, update: bool) -> ProviderCreditUpsertRequest {
    let policy = ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: XOR_ASSET_DEFINITION.parse().unwrap(),
        custody_account: account(20),
        treasury_account: account(21),
        operations_authority: account(22),
        // CanUpsert credit authority is independent of reserve policy roles.
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
            provider_account: account(24),
            tier: ReserveTier::TierA,
            storage_class: StorageClass::Hot,
            duration: ReserveDuration::Monthly,
            capacity_gib: 1,
        },
        policy_digest: policy.digest().unwrap(),
        revision: 3,
        reserve_balance: XorQuantity::try_from_micro(12_000_000).unwrap(),
        debt_principal: XorQuantity::try_from_micro(2_000_000).unwrap(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::try_from_micro(2_000_000).unwrap(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: 1,
        interest_accrued_at_unix: 1,
        updated_at_unix: 1,
    };
    let mut record = ProviderCreditRecord::new(
        partition.terms.provider_id,
        Quantity::zero(),
        Quantity::from(10u32),
        Quantity::from(5u32),
        Quantity::from(1u32),
        1,
        1,
        Metadata::default(),
    );
    let current_credit = update.then(|| {
        let mut current = record.clone();
        current.slashed = Quantity::from(2u32);
        current.bonded = Quantity::from(8u32);
        current.last_penalty_epoch = Some(2);
        current.under_delivery_strikes = 3;
        current.last_settlement_epoch = 4;
        record = current.clone();
        record.available_credit = Quantity::from(7u32);
        current
    });
    ProviderCreditUpsertRequest {
        selection: ProviderCreditUpsertSelection {
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            credit_authority: config.account.clone(),
            provider_id: record.provider_id,
            provider_account: partition.terms.provider_account.clone(),
            expected_current: current_credit
                .as_ref()
                .map(|value| HashOf::try_new(value).unwrap()),
            desired_record_hash: HashOf::try_new(&record).unwrap(),
            partition_revision: partition.revision,
            partition_policy_digest: partition.policy_digest,
            policy_digest: policy.digest().unwrap(),
            asset_definition: policy.asset_definition.clone(),
            custody_account: policy.custody_account.clone(),
            treasury_account: policy.treasury_account.clone(),
            operations_authority: policy.operations_authority.clone(),
            decision_authority: policy.decision_authority.clone(),
        },
        policy,
        partition,
        current_credit,
        record,
        deadline_unix_ms: now + 180_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(180),
        },
    }
}

fn different_asset(value: u8) -> AssetDefinitionId {
    let mut bytes = [value; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    AssetDefinitionId::from_uuid_bytes(bytes).unwrap()
}

#[test]
fn explicit_absence_and_current_hash_produce_exact_sole_credit_wire_and_fee_only_principal() {
    for update in [false, true] {
        let (service, transport) = service();
        let request = request(&service.config, current_unix_ms().unwrap(), update);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credit");
        let report = service
            .prepare_provider_credit_upsert(&request, &path)
            .unwrap();
        assert_eq!(report.status, OperationStatus::Prepared);
        assert!(!report.status.is_complete());
        assert_eq!(
            report.data["operation"].as_str(),
            Some("provider_credit_upsert")
        );
        assert!(report.data.get("funded").is_none() && report.data.get("ready").is_none());
        let calls = transport.requests.load(Ordering::SeqCst);
        let signed = service
            .verify_provider_credit_upsert_journal(&path, &request)
            .unwrap();
        assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
        let retained: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
        assert_eq!(
            signed.encode_versioned(),
            hex::decode(&retained.signed_transaction_hex).unwrap()
        );
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("native upsert")
        };
        assert_eq!(instructions.len(), 1);
        let upsert = instructions[0]
            .as_any()
            .downcast_ref::<UpsertProviderCredit>()
            .unwrap();
        assert_eq!(upsert.expected_current, request.selection.expected_current);
        assert_eq!(upsert.record, request.record);
        assert_eq!(upsert.expected_current.is_some(), update);
        assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
        assert_eq!(signed.authority(), &request.selection.credit_authority);
        assert_ne!(signed.authority(), &request.policy.decision_authority);
        assert_ne!(signed.authority(), &request.policy.operations_authority);
        assert!(
            retained
                .operation
                .principal(&service.config.account)
                .unwrap()
                .is_empty()
        );
        assert!(retained.deadline_ms <= request.deadline_unix_ms);
        assert!(
            service
                .submit(&path, NativeOperationKind::ProviderCreditUpsert)
                .is_err()
        );
        assert!(
            service
                .resume(&path, NativeOperationKind::ProviderCreditUpsert)
                .is_err()
        );
        assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
        assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
        assert!(transport.submitted.lock().unwrap().is_empty());
    }
}

#[test]
fn independent_identity_hash_and_claim_mismatches_refuse_before_http() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap(), true);
    let mut variants = Vec::new();
    macro_rules! changed { ($v:ident,$body:block) => {{let mut $v=request.clone(); $body variants.push($v);}}; }
    changed!(r, {
        r.selection.chain_id.push('x');
    });
    changed!(r, {
        r.selection.network_id =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"other")));
    });
    changed!(r, {
        r.selection.credit_authority = account(99);
    });
    changed!(r, {
        r.selection.provider_id = ProviderId::new([43; 32]);
    });
    changed!(r, {
        r.selection.provider_account = account(99);
    });
    changed!(r, {
        r.selection.provider_id = ProviderId::default();
        r.record.provider_id = ProviderId::default();
        r.partition.terms.provider_id = ProviderId::default();
    });
    changed!(r, {
        r.selection.expected_current = None;
    });
    changed!(r, {
        r.current_credit = None;
    });
    changed!(r, {
        r.current_credit.as_mut().unwrap().available_credit = Quantity::from(8u32);
    });
    changed!(r, {
        r.current_credit.as_mut().unwrap().provider_id = ProviderId::new([43; 32]);
        r.selection.expected_current =
            Some(HashOf::try_new(r.current_credit.as_ref().unwrap()).unwrap());
    });
    changed!(r, {
        r.record.available_credit = Quantity::from(8u32);
    });
    changed!(r, {
        r.selection.partition_revision += 1;
    });
    changed!(r, {
        r.selection.partition_policy_digest[0] ^= 1;
    });
    changed!(r, {
        r.selection.policy_digest[0] ^= 1;
    });
    changed!(r, {
        r.selection.asset_definition = different_asset(71);
    });
    changed!(r, {
        r.selection.custody_account = account(91);
    });
    changed!(r, {
        r.selection.treasury_account = account(92);
    });
    changed!(r, {
        r.selection.operations_authority = account(93);
    });
    changed!(r, {
        r.selection.decision_authority = account(94);
    });
    changed!(r, {
        r.partition.revision = 0;
        r.selection.partition_revision = 0;
    });
    changed!(r, {
        r.partition.reserve_balance = XorQuantity::zero();
    });
    changed!(r, {
        r.partition.debt_principal = XorQuantity::zero();
    });
    changed!(r, {
        r.deadline_unix_ms = 0;
    });
    changed!(r, {
        r.deadline_unix_ms = u64::MAX;
    });
    let root = tempfile::tempdir().unwrap();
    for (index, variant) in variants.iter().enumerate() {
        let path = root.path().join(index.to_string());
        assert!(
            service
                .prepare_provider_credit_upsert(variant, &path)
                .is_err(),
            "variant {index}"
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn native_slash_lien_rules_are_preserved_without_invented_strike_or_time_restrictions() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let mut initial = request(&service.config, now, false);
    initial.record.slashed = Quantity::from(2u32);
    initial.record.bonded = Quantity::from(8u32);
    initial.selection.desired_record_hash = HashOf::try_new(&initial.record).unwrap();
    assert!(
        Plan::new(&initial, now)
            .unwrap()
            .instruction(&service.config)
            .is_err()
    );
    initial.record.slashed = Quantity::zero();
    initial.record.bonded = Quantity::from(10u32);
    initial.record.last_penalty_epoch = Some(2);
    initial.selection.desired_record_hash = HashOf::try_new(&initial.record).unwrap();
    assert!(
        Plan::new(&initial, now)
            .unwrap()
            .instruction(&service.config)
            .is_err()
    );
    let mut update = request(&service.config, now, true);
    for slash in [true, false] {
        let mut changed = update.clone();
        if slash {
            changed.record.slashed = Quantity::zero();
            changed.record.bonded = Quantity::from(10u32);
        } else {
            changed.record.last_penalty_epoch = None;
        }
        changed.selection.desired_record_hash = HashOf::try_new(&changed.record).unwrap();
        assert!(
            Plan::new(&changed, now)
                .unwrap()
                .instruction(&service.config)
                .is_err()
        );
    }
    // These fields are governed replacement data. Native Upsert does not enforce additional
    // strike/settlement monotonicity, and this wallet must not invent those consensus rules.
    update.record.under_delivery_strikes = 0;
    update.record.last_settlement_epoch = 1;
    update.record.low_balance_since_epoch = Some(0);
    update.selection.desired_record_hash = HashOf::try_new(&update.record).unwrap();
    let wire = Plan::new(&update, now)
        .unwrap()
        .instruction(&service.config)
        .unwrap();
    assert_eq!(
        wire.as_any()
            .downcast_ref::<UpsertProviderCredit>()
            .unwrap()
            .record,
        update.record
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn retained_policy_partition_claims_do_not_create_native_policy_cas_or_readiness() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let original = request(&service.config, now, true);
    let old = Plan::new(&original, now).unwrap();
    let mut other = original.clone();
    other.policy.revision = 2;
    other.policy.predecessor_policy_digest = Some(original.selection.policy_digest);
    other.selection.policy_digest = other.policy.digest().unwrap();
    other.partition.revision += 1;
    other.selection.partition_revision = other.partition.revision;
    let newer = Plan::new(&other, now).unwrap();
    assert_ne!(
        newer.selection.policy_digest,
        newer.selection.partition_policy_digest
    );
    assert_eq!(
        old.instruction(&service.config).unwrap(),
        newer.instruction(&service.config).unwrap()
    );
    assert_ne!(
        encode_bounded(&old, MAX_PLAN_BYTES).unwrap(),
        encode_bounded(&newer, MAX_PLAN_BYTES).unwrap()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn full_record_and_original_terms_cannot_change_before_once_only_reopen() {
    for update in [false, true] {
        let (service, transport) = service();
        let mut request = request(&service.config, current_unix_ms().unwrap(), update);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credit");
        service
            .prepare_provider_credit_upsert(&request, &path)
            .unwrap();
        *transport.journal.lock().unwrap() = Some(path.clone());
        let before = std::fs::read(path.join("operation.json")).unwrap();
        let wire = service
            .verify_provider_credit_upsert_journal(&path, &request)
            .unwrap()
            .encode_versioned();
        let mut variants = Vec::new();
        macro_rules! changed { ($v:ident,$body:block) => {{let mut $v=request.clone(); $body variants.push($v);}}; }
        changed!(r, {
            r.deadline_unix_ms += 1;
        });
        changed!(r, {
            r.policy.grace_period_days += 1;
            r.selection.policy_digest = r.policy.digest().unwrap();
        });
        changed!(r, {
            r.partition.updated_at_unix += 1;
        });
        changed!(r, {
            r.partition.revision += 1;
            r.selection.partition_revision += 1;
        });
        changed!(r, {
            r.partition.policy_digest[0] ^= 1;
            r.selection.partition_policy_digest = r.partition.policy_digest;
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
        // Every complete replacement field is retained, even when the caller supplies its new hash.
        for field in 0..13 {
            let mut changed = request.clone();
            let row = &mut changed.record;
            match field {
                0 => row.provider_id = ProviderId::new([82; 32]),
                1 => row.available_credit = Quantity::from(83u32),
                2 => row.bonded = Quantity::from(84u32),
                3 => row.required_bond = Quantity::from(85u32),
                4 => row.expected_settlement = Quantity::from(86u32),
                5 => row.onboarding_epoch += 1,
                6 => row.last_settlement_epoch += 1,
                7 => row.low_balance_since_epoch = Some(87),
                8 => row.slashed = Quantity::from(88u32),
                9 => row.under_delivery_strikes += 1,
                10 => row.last_penalty_epoch = Some(89),
                11 => {
                    row.metadata.insert(
                        "note".parse().unwrap(),
                        iroha_primitives::json::Json::new("replacement"),
                    );
                }
                _ => {
                    changed.selection.expected_current = Some(HashOf::try_new(row).unwrap());
                    changed.current_credit = Some(row.clone());
                }
            }
            changed.selection.desired_record_hash = HashOf::try_new(&changed.record).unwrap();
            variants.push(changed);
        }
        if update {
            changed!(r, {
                r.current_credit.as_mut().unwrap().metadata.insert(
                    "original".parse().unwrap(),
                    iroha_primitives::json::Json::new("changed"),
                );
                r.selection.expected_current =
                    Some(HashOf::try_new(r.current_credit.as_ref().unwrap()).unwrap());
            });
        }
        let calls = transport.requests.load(Ordering::SeqCst);
        for changed in variants {
            assert!(
                service
                    .verify_provider_credit_upsert_journal(&path, &changed)
                    .is_err()
            );
            assert!(
                service
                    .submit_provider_credit_upsert(&path, &changed)
                    .is_err()
            );
            assert!(
                service
                    .resume_provider_credit_upsert(&path, &changed)
                    .is_err()
            );
        }
        assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
        assert_eq!(
            service
                .resume_provider_credit_upsert(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Absent
        );
        assert!(!path.join("submission.json").exists());
        assert_eq!(
            service
                .submit_provider_credit_upsert(&path, &request)
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
                .submit_provider_credit_upsert(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            reopened
                .resume_provider_credit_upsert(&path, &request)
                .unwrap()
                .status,
            OperationStatus::Pending
        );
        assert_eq!(
            reopened
                .verify_provider_credit_upsert_journal(&path, &request)
                .unwrap()
                .encode_versioned(),
            wire
        );
        assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
        assert_eq!(std::fs::read(path.join("submission.json")).unwrap(), marker);
        assert_eq!(transport.submitted.lock().unwrap().as_slice(), &[wire]);
        assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn expired_original_is_readable_but_fresh_prepare_and_dispatch_cannot_renew_it() {
    let (service, transport) = service();
    let original_time = current_unix_ms().unwrap() - 400_000;
    let mut request = request(&service.config, original_time, true);
    let plan = Plan::new(&request, original_time).unwrap();
    let mut terms = BoundedTerms::new(&request.options).unwrap();
    terms.deadline_ms = request.deadline_unix_ms;
    let operation = NativeOperation::ProviderCreditUpsert {
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
            .verify_provider_credit_upsert_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_provider_credit_upsert(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_provider_credit_upsert(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_provider_credit_upsert(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!root.path().join("fresh").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn component_fee_and_canonical_bounds_refuse_without_publication_or_lost_resource_cause() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap(), true);
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.selection.chain_id = "x".repeat(MAX_SELECTION_BYTES);
    variants.push(changed);
    let mut changed = request.clone();
    changed.policy.economics.rent_rates =
        vec![changed.policy.economics.rent_rates[0].clone(); MAX_POLICY_BYTES];
    variants.push(changed);
    let mut changed = request.clone();
    changed.record.metadata.insert(
        "large".parse().unwrap(),
        iroha_primitives::json::Json::new("x".repeat(MAX_CREDIT_BYTES)),
    );
    variants.push(changed);
    let mut changed = request.clone();
    changed.current_credit.as_mut().unwrap().metadata.insert(
        "large".parse().unwrap(),
        iroha_primitives::json::Json::new("x".repeat(MAX_CREDIT_BYTES)),
    );
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.deadline = Instant::now() - Duration::from_secs(1);
    variants.push(changed);
    let mut changed = request.clone();
    changed
        .options
        .max_total_fees
        .insert(changed.policy.asset_definition.clone(), Quantity::zero());
    variants.push(changed);
    let mut changed = request.clone();
    for byte in 1..=17 {
        changed
            .options
            .max_total_fees
            .insert(different_asset(byte), Quantity::from(1u32));
    }
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.fee_payment = FeePaymentIntent::authority(
        (1..=17)
            .map(|v| {
                iroha_data_model::transaction::FeeChargeLimit::new(
                    iroha_data_model::transaction::FeeChargeKind::Nexus,
                    different_asset(v),
                    Quantity::from(1u32),
                )
            })
            .collect(),
        None,
    );
    variants.push(changed);
    let mut changed = request.clone();
    changed.options.fee_payment = FeePaymentIntent::sponsor(
        iroha_data_model::nexus::FeeSponsorProgramId::new(account(98), "credit".parse().unwrap()),
        1,
        Vec::new(),
        None,
    );
    variants.push(changed);
    let root = tempfile::tempdir().unwrap();
    for (index, changed) in variants.iter().enumerate() {
        let path = root.path().join(index.to_string());
        assert!(
            service
                .prepare_provider_credit_upsert(changed, &path)
                .is_err()
        );
        assert!(!path.exists());
    }
    let plan = Plan::new(&request, current_unix_ms().unwrap()).unwrap();
    let bytes = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    assert!(instructions(&service.config, &bytes, request.deadline_unix_ms + 1).is_err());
    assert!(instructions(&service.config, &bytes, plan.validated_at_unix_ms).is_err());
    let mut trailing = bytes.clone();
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
    // Exercise the real inherited bounded decoder allocation owner. No fabricated hash failure
    // is injected into an otherwise allocation-free streaming HashOf serialization.
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || instructions(&service.config, &bytes, request.deadline_unix_ms),
    )
    .unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<norito::Error>(),
            Some(norito::Error::TotalAllocationExceeded { .. })
        ),
        "original allocation refusal must not become a stale-CAS error: {error:?}"
    );
    assert!(instructions(&service.config, &bytes, request.deadline_unix_ms).is_ok());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_signed_wire_rejects_extra_instruction_cas_record_metadata_and_purpose_changes() {
    let (service, _) = service();
    let request = request(&service.config, current_unix_ms().unwrap(), true);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("credit");
    service
        .prepare_provider_credit_upsert(&request, &path)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    let mut changed = record.clone();
    let NativeOperation::ProviderCreditUpsert { plan, .. } = &mut changed.operation else {
        panic!("credit purpose")
    };
    plan.push(0);
    assert!(changed.verify(&service.config).is_err());
    assert!(
        ProviderCreditExpectation(&request)
            .verify(&preparation::Selection {
                operation: &changed.operation,
                requested_fee: &changed.requested_fee,
                deadline_ms: changed.deadline_ms
            })
            .is_err()
    );
    let mut changed = record.clone();
    changed.signed_transaction_hex.push_str("00");
    assert!(changed.verify(&service.config).is_err());
    let instruction = Plan::new(&request, current_unix_ms().unwrap())
        .unwrap()
        .instruction(&service.config)
        .unwrap();
    for variant in 0..4 {
        let mut payload = original.payload().clone();
        match variant {
            0 => payload.instructions = vec![instruction.clone(), instruction.clone()].into(),
            1 => {
                payload.instructions = vec![InstructionBox::from(UpsertProviderCredit::new(
                    None,
                    request.record.clone(),
                ))]
                .into()
            }
            2 => {
                let mut altered = request.record.clone();
                altered.available_credit = Quantity::from(99u32);
                payload.instructions = vec![InstructionBox::from(UpsertProviderCredit::new(
                    request.selection.expected_current,
                    altered,
                ))]
                .into();
            }
            _ => {
                payload.metadata.insert(
                    "unexpected".parse().unwrap(),
                    iroha_primitives::json::Json::new(true),
                );
            }
        }
        let signed = service
            .client
            .account_client()
            .sign_transaction(payload)
            .unwrap();
        let mut changed = record.clone();
        changed.signed_transaction_hex = hex::encode(signed.encode_versioned());
        changed.transaction_hash = signed.hash().to_string();
        assert!(
            changed.verify(&service.config).is_err(),
            "signed wire variant {variant}"
        );
    }
    let mut changed = record;
    changed.operation = NativeOperation::InitialReservePolicy {
        plan: Vec::new(),
        terms: BoundedTerms::new(&request.options).unwrap(),
    };
    assert!(
        ProviderCreditExpectation(&request)
            .verify(&preparation::Selection {
                operation: &changed.operation,
                requested_fee: &changed.requested_fee,
                deadline_ms: changed.deadline_ms
            })
            .is_err()
    );
}

#[test]
fn missing_original_recovery_never_creates_credit_or_uses_http() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap(), false);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("never-prepared");
    assert!(
        service
            .verify_provider_credit_upsert_journal(&path, &request)
            .is_err()
    );
    assert!(
        service
            .resume_provider_credit_upsert(&path, &request)
            .is_err()
    );
    assert!(
        service
            .submit_provider_credit_upsert(&path, &request)
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn retain_provider_credit_upsert_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap(), false);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_provider_credit_upsert_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_provider_credit_upsert_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_provider_credit_upsert_request(&changed, &path)
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

    service
        .prepare_provider_credit_upsert(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_provider_credit_upsert_request(&request, &path)
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
        .retain_provider_credit_upsert_request(&request, &path)
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
    let request = request(&service.config, current_unix_ms().unwrap(), false);
    let root = tempfile::tempdir().unwrap();
    let parent = iroha_fs::PrivateDirectory::open_or_create(root.path().join("parent")).unwrap();
    let name = std::ffi::OsStr::new("transaction");
    let path = parent.path().join(name);
    assert_eq!(
        service
            .inspect_provider_credit_upsert_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    assert_eq!(
        service
            .prepare_provider_credit_upsert(&request, &path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let calls = transport.requests.load(Ordering::SeqCst);
    let before = ["preparation.json", "payload.json", "operation.json"]
        .map(|record| std::fs::read(path.join(record)).unwrap());
    let absolute = service
        .inspect_provider_credit_upsert_preparation(&path, &request)
        .unwrap();
    let retained = service
        .inspect_provider_credit_upsert_preparation_in_parent(&parent, name, &request)
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
            .inspect_provider_credit_upsert_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert_eq!(
        service
            .inspect_provider_credit_upsert_preparation_in_parent(&parent, name, &request)
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
