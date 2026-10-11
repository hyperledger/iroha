//! Structural provider-capacity intent and genuine wallet journals; mock responses confer no native authority.
//! Selected policy/partition/credit are claims; no native capacity application or admission is simulated.

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
use sorafs_manifest::{
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityMetadataEntry, ChunkerCommitmentV1,
        LaneCommitmentV1, PricingScheduleV1,
    },
    deal::XorQuantity,
    provider_advert::StakePointer,
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
                    .expect("provider_capacity must be retained before dispatch");
                assert!(path.join("operation.json").is_file());
                assert!(path.join("submission.json").is_file());
                self.submitted.lock().unwrap().push(request.body);
                (503, b"unavailable".to_vec())
            }
            path => panic!("unexpected provider_capacity HTTP request {path}"),
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
fn request(config: &Config, now: u64) -> ProviderCapacityDeclarationRequest {
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let policy = ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: XOR_ASSET_DEFINITION.parse().unwrap(),
        custody_account: account(20),
        treasury_account: account(21),
        operations_authority: account(22),
        // Provider owner is independent of reserve operations and decision roles.
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
    let credit = ProviderCreditRecord::new(
        partition.terms.provider_id,
        Quantity::zero(),
        Quantity::from(10u32),
        Quantity::from(5u32),
        Quantity::from(1u32),
        1,
        1,
        Metadata::default(),
    );
    let declaration = CapacityDeclarationV1 {
        version: CAPACITY_DECLARATION_VERSION_V1,
        provider_id: *partition.terms.provider_id.as_bytes(),
        stake: StakePointer {
            pool_id: [43; 32],
            stake_amount: "3".parse().unwrap(),
        },
        committed_capacity_gib: 1,
        chunker_commitments: vec![ChunkerCommitmentV1 {
            profile_id: "sorafs.sf1@1.0.0".into(),
            profile_aliases: None,
            committed_gib: 1,
            capability_refs: Vec::new(),
        }],
        lane_commitments: Vec::new(),
        pricing: None,
        valid_from: now / 1_000,
        valid_until: now / 1_000 + 600,
        metadata: vec![
            CapacityMetadataEntry {
                key: OWNER_METADATA.into(),
                value: config.account.to_string(),
            },
            CapacityMetadataEntry {
                key: STORAGE_CLASS_METADATA.into(),
                value: "hot".into(),
            },
        ],
    };
    ProviderCapacityDeclarationRequest {
        selection: ProviderCapacityDeclarationSelection {
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            provider_id: credit.provider_id,
            provider_account: partition.terms.provider_account.clone(),
            declaration_hash: HashOf::try_new(&declaration).unwrap(),
            credit_hash: HashOf::try_new(&credit).unwrap(),
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
        credit,
        declaration,
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
fn exact_capacity_payload_public_report_and_owner_fee_only_principal() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("capacity");
    let report = service
        .prepare_provider_capacity_declaration(&request, &path)
        .unwrap();
    assert_eq!(report.status, OperationStatus::Prepared);
    assert_eq!(
        report.data["operation"].as_str(),
        Some("provider_capacity_declaration")
    );
    assert!(report.data.get("funded").is_none() && report.data.get("ready").is_none());
    let calls = transport.requests.load(Ordering::SeqCst);
    let signed = service
        .verify_provider_capacity_declaration_journal(&path, &request)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(
        signed.encode_versioned(),
        hex::decode(&record.signed_transaction_hex).unwrap()
    );
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("native declaration")
    };
    assert_eq!(instructions.len(), 1);
    let declaration = instructions[0]
        .as_any()
        .downcast_ref::<RegisterCapacityDeclaration>()
        .unwrap();
    assert_eq!(
        declaration.declaration,
        norito::encode_canonical(&request.declaration).unwrap()
    );
    assert_eq!(signed.authority(), &request.selection.provider_account);
    assert_ne!(signed.authority(), &request.policy.operations_authority);
    assert_ne!(signed.authority(), &request.policy.decision_authority);
    assert!(signed.attachments().is_none() && signed.multisig_signatures().is_none());
    assert!(
        record
            .operation
            .principal(&service.config.account)
            .unwrap()
            .is_empty()
    );
    assert!(record.deadline_ms <= request.deadline_unix_ms);
    assert!(
        service
            .submit(&path, NativeOperationKind::ProviderCapacityDeclaration)
            .is_err()
    );
    assert!(
        service
            .resume(&path, NativeOperationKind::ProviderCapacityDeclaration)
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn selected_network_owner_hash_policy_and_partition_mismatches_refuse_before_http() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    for field in 0..19 {
        let mut changed = request.clone();
        match field {
            0 => changed.selection.chain_id.push('x'),
            1 => {
                changed.selection.network_id = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"other")),
                )
            }
            2 => changed.selection.provider_account = account(99),
            3 => changed.selection.provider_id = ProviderId::new([99; 32]),
            4 => changed.partition.terms.provider_account = account(98),
            5 => changed.partition.terms.provider_id = ProviderId::new([98; 32]),
            6 => changed.selection.partition_revision += 1,
            7 => changed.selection.partition_policy_digest[0] ^= 1,
            8 => changed.selection.policy_digest[0] ^= 1,
            9 => changed.selection.asset_definition = different_asset(71),
            10 => changed.selection.custody_account = account(91),
            11 => changed.selection.treasury_account = account(92),
            12 => changed.selection.operations_authority = account(93),
            13 => changed.selection.decision_authority = account(94),
            14 => changed.credit.available_credit = Quantity::from(99u32),
            15 => changed.declaration.valid_until += 1,
            16 => changed.partition.revision = 0,
            17 => changed.deadline_unix_ms = 0,
            _ => changed.deadline_unix_ms = u64::MAX,
        }
        let path = root.path().join(field.to_string());
        assert!(
            service
                .prepare_provider_capacity_declaration(&changed, &path)
                .is_err(),
            "binding {field}"
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn canonical_manifest_metadata_and_claimed_backing_rules_refuse_before_http() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    for field in 0..21 {
        let mut changed = request.clone();
        match field {
            0 => changed.declaration.version += 1,
            1 => changed.declaration.provider_id = [0; 32],
            2 => changed.declaration.stake.pool_id = [0; 32],
            3 => changed.declaration.stake.stake_amount = XorQuantity::zero(),
            4 => changed.declaration.chunker_commitments.clear(),
            5 => changed.declaration.chunker_commitments[0].committed_gib += 1,
            6 => changed.declaration.chunker_commitments[0].profile_aliases = Some(Vec::new()),
            7 => changed.declaration.lane_commitments.push(LaneCommitmentV1 {
                lane_id: "Bad".into(),
                max_gib: 1,
            }),
            8 => changed
                .declaration
                .metadata
                .retain(|entry| entry.key != OWNER_METADATA),
            9 => changed.declaration.metadata[0].value = account(91).to_string(),
            10 => changed.declaration.metadata[1].value = "Hot".into(),
            11 => changed
                .declaration
                .metadata
                .push(changed.declaration.metadata[0].clone()),
            12 => {
                changed.declaration.valid_from = 1;
                changed.declaration.valid_until = 2;
            }
            13 => changed.declaration.valid_until = changed.declaration.valid_from,
            14 => {
                changed.declaration.committed_capacity_gib = 2;
                changed.declaration.chunker_commitments[0].committed_gib = 2;
            }
            15 => changed.credit.bonded = Quantity::zero(),
            16 => {
                changed.credit.bonded = Quantity::from(2u32);
                changed.credit.slashed = Quantity::from(8u32);
            }
            17 => changed.credit.required_bond = Quantity::from(11u32),
            18 => changed.partition.reserve_balance = XorQuantity::zero(),
            19 => changed.credit.provider_id = ProviderId::new([98; 32]),
            _ => {
                let _other_profile = ChainDiscriminantGuard::enter(
                    service.config.account_chain_discriminant.wrapping_add(1),
                );
                changed.declaration.metadata[0].value = service.config.account.to_string();
                assert_ne!(
                    changed.declaration.metadata[0].value,
                    request.declaration.metadata[0].value
                );
            }
        }
        changed.selection.credit_hash = HashOf::try_new(&changed.credit).unwrap();
        changed.selection.declaration_hash = HashOf::try_new(&changed.declaration).unwrap();
        let path = root.path().join(field.to_string());
        assert!(
            service
                .prepare_provider_capacity_declaration(&changed, &path)
                .is_err(),
            "rule {field}"
        );
        assert!(!path.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn pricing_future_window_and_lagging_claims_do_not_invent_native_preconditions() {
    let (service, transport) = service();
    let now = current_unix_ms().unwrap();
    let mut request = request(&service.config, now);
    assert!(request.credit.available_credit.is_zero());
    request.declaration.valid_from += 100;
    request.declaration.metadata[1].value = "cold".into();
    request.declaration.pricing = Some(PricingScheduleV1 {
        currency: "xor".into(),
        rate_per_gib_hour_milliu: 1,
        min_commitment_hours: Some(1),
        notes: Some("operator hint".into()),
    });
    request.selection.declaration_hash = HashOf::try_new(&request.declaration).unwrap();
    let original = Plan::new(&request, now).unwrap();
    let wire = original.instruction(&service.config).unwrap();
    request.policy.revision = 2;
    request.policy.predecessor_policy_digest = Some(request.selection.policy_digest);
    request.selection.policy_digest = request.policy.digest().unwrap();
    request.partition.revision += 1;
    request.selection.partition_revision += 1;
    request.credit.slashed = Quantity::from(2u32);
    request.credit.bonded = Quantity::from(8u32);
    request.credit.last_penalty_epoch = Some(1);
    request.selection.credit_hash = HashOf::try_new(&request.credit).unwrap();
    let other = Plan::new(&request, now).unwrap();
    assert_ne!(
        request.selection.policy_digest,
        request.selection.partition_policy_digest
    );
    assert_eq!(
        other.instruction(&service.config).unwrap(),
        wire,
        "supporting claims carry no native CAS"
    );
    assert_ne!(
        encode_bounded(&original, MAX_PLAN_BYTES).unwrap(),
        encode_bounded(&other, MAX_PLAN_BYTES).unwrap()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn large_canonical_declaration_retains_complete_typed_payload_beyond_four_kib() {
    let (service, _) = service();
    let now = current_unix_ms().unwrap();
    let mut request = request(&service.config, now);
    for field in 0..3 {
        request.declaration.metadata.push(CapacityMetadataEntry {
            key: format!("note{field}"),
            value: "x".repeat(3000),
        });
    }
    request.selection.declaration_hash = HashOf::try_new(&request.declaration).unwrap();
    let payload = encode_bounded(&request.declaration, MAX_DECLARATION_BYTES).unwrap();
    assert!(payload.len() > 4096);
    let plan = Plan::new(&request, now).unwrap();
    let encoded = encode_bounded(&plan, MAX_PLAN_BYTES).unwrap();
    let restored: Plan = decode_bounded(&encoded, MAX_PLAN_BYTES).unwrap();
    assert_eq!(restored.declaration, request.declaration);
    let instruction = instructions(&service.config, &encoded, request.deadline_unix_ms).unwrap();
    assert_eq!(
        instruction[0]
            .as_any()
            .downcast_ref::<RegisterCapacityDeclaration>()
            .unwrap()
            .declaration,
        payload
    );
}

#[test]
fn exact_full_intent_and_fees_are_immutable_across_once_only_503_and_reopen() {
    let (service, transport) = service();
    let mut request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("capacity");
    service
        .prepare_provider_capacity_declaration(&request, &path)
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.clone());
    let before = std::fs::read(path.join("operation.json")).unwrap();
    let wire = service
        .verify_provider_capacity_declaration_journal(&path, &request)
        .unwrap()
        .encode_versioned();
    let calls = transport.requests.load(Ordering::SeqCst);
    for field in 0..17 {
        let mut changed = request.clone();
        match field {
            0 => changed.deadline_unix_ms += 1,
            1 => {
                changed.policy.grace_period_days += 1;
                changed.selection.policy_digest = changed.policy.digest().unwrap();
            }
            2 => changed.partition.updated_at_unix += 1,
            3 => {
                changed.partition.revision += 1;
                changed.selection.partition_revision += 1;
            }
            4 => {
                changed.partition.policy_digest[0] ^= 1;
                changed.selection.partition_policy_digest = changed.partition.policy_digest;
            }
            5 => {
                changed.options.max_total_fees.insert(
                    changed.policy.asset_definition.clone(),
                    Quantity::from(1u32),
                );
            }
            6 => {
                changed.options.fee_payment =
                    FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(99))
            }
            7 => changed.credit.available_credit = Quantity::from(9u32),
            8 => changed.declaration.stake.pool_id = [91; 32],
            9 => changed.declaration.stake.stake_amount = "4".parse().unwrap(),
            10 => changed.declaration.valid_from += 1,
            11 => changed.declaration.valid_until += 1,
            12 => changed.declaration.metadata[1].value = "cold".into(),
            13 => changed.declaration.metadata.push(CapacityMetadataEntry {
                key: "note".into(),
                value: "exact retained bytes".into(),
            }),
            14 => changed.declaration.lane_commitments.push(LaneCommitmentV1 {
                lane_id: "hot".into(),
                max_gib: 1,
            }),
            15 => {
                changed.declaration.pricing = Some(PricingScheduleV1 {
                    currency: "xor".into(),
                    rate_per_gib_hour_milliu: 1,
                    min_commitment_hours: None,
                    notes: None,
                })
            }
            _ => changed.declaration.chunker_commitments[0]
                .capability_refs
                .push(sorafs_manifest::provider_advert::CapabilityType::ToriiGateway),
        }
        changed.selection.credit_hash = HashOf::try_new(&changed.credit).unwrap();
        changed.selection.declaration_hash = HashOf::try_new(&changed.declaration).unwrap();
        assert!(
            service
                .verify_provider_capacity_declaration_journal(&path, &changed)
                .is_err(),
            "verify {field}"
        );
        assert!(
            service
                .submit_provider_capacity_declaration(&path, &changed)
                .is_err(),
            "submit {field}"
        );
        assert!(
            service
                .resume_provider_capacity_declaration(&path, &changed)
                .is_err(),
            "resume {field}"
        );
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    assert_eq!(
        service
            .resume_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Absent
    );
    assert!(!path.join("submission.json").exists());
    assert_eq!(
        service
            .submit_provider_capacity_declaration(&path, &request)
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
            .submit_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        reopened
            .resume_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        reopened
            .verify_provider_capacity_declaration_journal(&path, &request)
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
    let operation = NativeOperation::ProviderCapacityDeclaration {
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
            .verify_provider_capacity_declaration_journal(&path, &request)
            .unwrap()
            .encode_versioned(),
        signed.encode_versioned()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .resume_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_provider_capacity_declaration(&path, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert!(
        service
            .prepare_provider_capacity_declaration(&request, &root.path().join("fresh"))
            .is_err()
    );
    assert!(!root.path().join("fresh").exists());
    assert!(!path.join("submission.json").exists());
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn component_fee_and_canonical_bounds_preserve_actual_resource_refusal() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    for field in 0..8 {
        let mut changed = request.clone();
        match field {
            0 => changed.selection.chain_id = "x".repeat(MAX_SELECTION_BYTES),
            1 => {
                changed.policy.economics.rent_rates =
                    vec![changed.policy.economics.rent_rates[0].clone(); MAX_POLICY_BYTES]
            }
            2 => {
                changed.credit.metadata.insert(
                    "large".parse().unwrap(),
                    iroha_primitives::json::Json::new("x".repeat(MAX_CREDIT_BYTES)),
                );
            }
            3 => changed.declaration.metadata.push(CapacityMetadataEntry {
                key: "large".into(),
                value: "x".repeat(MAX_DECLARATION_BYTES),
            }),
            4 => changed.options.deadline = Instant::now() - Duration::from_secs(1),
            5 => {
                changed
                    .options
                    .max_total_fees
                    .insert(changed.policy.asset_definition.clone(), Quantity::zero());
            }
            6 => {
                for byte in 1..=17 {
                    changed
                        .options
                        .max_total_fees
                        .insert(different_asset(byte), Quantity::from(1u32));
                }
            }
            _ => {
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
                )
            }
        }
        let path = root.path().join(field.to_string());
        assert!(
            service
                .prepare_provider_capacity_declaration(&changed, &path)
                .is_err(),
            "bound {field}"
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
        "preserve decoder refusal: {error:?}"
    );
    assert!(instructions(&service.config, &bytes, request.deadline_unix_ms).is_ok());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn signed_capacity_journal_rejects_instruction_payload_metadata_and_purpose_substitution() {
    let (service, _) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("capacity");
    service
        .prepare_provider_capacity_declaration(&request, &path)
        .unwrap();
    let record: TransactionJournal = Journal::open(&path).unwrap().read_operation().unwrap();
    let original = record.verify(&service.config).unwrap();
    let mut changed = record.clone();
    let NativeOperation::ProviderCapacityDeclaration { plan, .. } = &mut changed.operation else {
        panic!("capacity purpose")
    };
    plan.push(0);
    assert!(changed.verify(&service.config).is_err());
    assert!(
        ProviderCapacityExpectation(&request)
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
                let mut bytes = norito::encode_canonical(&request.declaration).unwrap();
                bytes.push(0);
                payload.instructions = vec![InstructionBox::from(
                    RegisterCapacityDeclaration::new(bytes),
                )]
                .into();
            }
            2 => {
                let mut declaration = request.declaration.clone();
                declaration.valid_until += 1;
                payload.instructions =
                    vec![InstructionBox::from(RegisterCapacityDeclaration::new(
                        norito::encode_canonical(&declaration).unwrap(),
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
        changed.transaction_hash = signed.hash().to_string();
        changed.signed_transaction_hex = hex::encode(signed.encode_versioned());
        assert!(
            changed.verify(&service.config).is_err(),
            "envelope {variant}"
        );
    }
    let mut changed = record;
    changed.operation = NativeOperation::InitialReservePolicy {
        plan: Vec::new(),
        terms: BoundedTerms::new(&request.options).unwrap(),
    };
    assert!(
        ProviderCapacityExpectation(&request)
            .verify(&preparation::Selection {
                operation: &changed.operation,
                requested_fee: &changed.requested_fee,
                deadline_ms: changed.deadline_ms
            })
            .is_err()
    );
}

#[test]
fn missing_original_capacity_recovery_never_creates_or_dispatches() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("absent");
    assert!(
        service
            .verify_provider_capacity_declaration_journal(&path, &request)
            .is_err()
    );
    assert!(
        service
            .resume_provider_capacity_declaration(&path, &request)
            .is_err()
    );
    assert!(
        service
            .submit_provider_capacity_declaration(&path, &request)
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 0);
    assert!(transport.submitted.lock().unwrap().is_empty());
}

#[test]
fn retain_provider_capacity_declaration_request_is_a_real_unsigned_zero_http_boundary() {
    let (service, transport) = service();
    let request = request(&service.config, current_unix_ms().unwrap());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request-only-boundary");
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let first = service
        .retain_provider_capacity_declaration_request(&request, &path)
        .unwrap();
    assert_eq!(first.phase(), NativePreparationPhase::RequestOnly);
    let commitment = first.request_sha256().unwrap().to_owned();
    let original = std::fs::read(path.join("preparation.json")).unwrap();
    assert!(!path.join("payload.json").exists());
    assert!(!path.join("operation.json").exists());
    assert!(!path.join("submission.json").exists());
    let repeated = service
        .retain_provider_capacity_declaration_request(&request, &path)
        .unwrap();
    assert_eq!(repeated.request_sha256(), Some(commitment.as_str()));
    let mut changed = request.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        service
            .retain_provider_capacity_declaration_request(&changed, &path)
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
        .prepare_provider_capacity_declaration(&request, &path)
        .unwrap();
    let before = transport.requests.load(std::sync::atomic::Ordering::SeqCst);
    let signed = service
        .retain_provider_capacity_declaration_request(&request, &path)
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
        .retain_provider_capacity_declaration_request(&request, &path)
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
            .inspect_provider_capacity_declaration_preparation_in_parent(&parent, name, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert!(!path.exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);

    assert_eq!(
        service
            .prepare_provider_capacity_declaration(&request, &path)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let calls = transport.requests.load(Ordering::SeqCst);
    let before = ["preparation.json", "payload.json", "operation.json"]
        .map(|record| std::fs::read(path.join(record)).unwrap());
    let absolute = service
        .inspect_provider_capacity_declaration_preparation(&path, &request)
        .unwrap();
    let retained = service
        .inspect_provider_capacity_declaration_preparation_in_parent(&parent, name, &request)
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
            .inspect_provider_capacity_declaration_preparation_in_parent(&parent, name, &changed)
            .is_err()
    );
    assert_eq!(
        service
            .inspect_provider_capacity_declaration_preparation_in_parent(&parent, name, &request)
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
