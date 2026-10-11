//! Migrated native envelope, independent trust and exact recovery tests.
use super::*;
use iroha::account_bootstrap::validate_endpoint;
use iroha::data_model::prelude::TransactionEntrypoint;
use iroha_crypto::{Hash, KeyPair};
use iroha_torii_shared::PipelineTransactionStatusResponse;
#[cfg(unix)]
use std::fs;
use url::Url;
fn vector(name: &str) -> Value {
    let fixture: Value = json::from_str(include_str!(
        "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
    ))
    .unwrap();
    fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"].as_str() == Some(name))
        .unwrap()
        .clone()
}

fn onboarding_fixture(proof_required: bool) -> (Config, OperationJournalV1) {
    let fixture = vector("onboarding_prepared");
    let prepared: AccountOnboardingPreparedTransactionV1 =
        json::from_value(fixture["response"].clone()).unwrap();
    let mut config = crate::operations::tests::fixture_config();
    config.network_id = json::from_value(fixture["network_id"].clone()).unwrap();
    config.account_chain_discriminant = 0x02f1;
    config.account = AccountId::parse_encoded(&prepared.account_id).unwrap();
    // Public target signer from the canonical data-model onboarding fixture.
    config.key_pair = KeyPair::from_seed(vec![0x22; 32], iroha_crypto::Algorithm::Ed25519);
    assert_eq!(
        config.account,
        AccountId::new(config.key_pair.public_key().clone())
    );
    let mut binding = prepared.binding.clone();
    let fee = prepared.fee_payment.clone();
    let issuer = prepared.receipt.body.authority.clone();
    let request = prepared.receipt.body.request.clone();
    let receipt = prepared.receipt.clone();
    let response = if proof_required {
        let proof: AccountOnboardingProofRequiredPrepareResponseV1 =
            json::from_value(vector("onboarding_proof_required")["response"].clone()).unwrap();
        binding = proof.binding.clone();
        OnboardingResponseV1::ProofRequired(Box::new(proof))
    } else {
        OnboardingResponseV1::Prepared(Box::new(prepared))
    };
    let operation = new_operation(
        &config,
        binding,
        fee,
        OperationV1::Onboarding(Box::new(OnboardingV1 {
            issuer,
            request,
            receipt,
            response,
        })),
    );
    (config, operation)
}

fn faucet_fixture() -> (Config, OperationJournalV1) {
    let fixture = vector("faucet_prepared");
    let prepared: AccountFaucetPreparedTransactionV1 =
        json::from_value(fixture["response"].clone()).unwrap();
    let mut config = crate::operations::tests::fixture_config();
    config.network_id = json::from_value(fixture["network_id"].clone()).unwrap();
    config.account_chain_discriminant = 0x02f1;
    config.account = AccountId::parse_encoded(&prepared.account_id).unwrap();
    // Faucet and onboarding fixtures share the same published recipient identity.
    config.key_pair = KeyPair::from_seed(vec![0x22; 32], iroha_crypto::Algorithm::Ed25519);
    assert_eq!(
        config.account,
        AccountId::new(config.key_pair.public_key().clone())
    );
    let operation = new_operation(
        &config,
        prepared.binding.clone(),
        prepared.fee_payment.clone(),
        OperationV1::Faucet(Box::new(FaucetV1 {
            requested_fee: prepared.fee_payment.clone(),
            issuer: AccountId::parse_encoded(fixture["signer_account_id"].as_str().unwrap())
                .unwrap(),
            asset_definition: prepared.asset_definition_id.parse().unwrap(),
            amount: prepared.amount.clone(),
            claim: prepared.claim.clone(),
            prepared,
        })),
    );
    (config, operation)
}

#[test]
fn request_identity_is_fresh_bounded_and_canonical() {
    let mut args = PreparationOptions {
        timeout_secs: 30,
        request_id: None,
        expires_in_secs: 120,
    };
    let (first, deadline) = args.identity(1_000).unwrap();
    assert_eq!(deadline, 121_000);
    assert_eq!(validate_request_id(&first).unwrap(), first);
    assert_ne!(args.identity(1_000).unwrap().0, first);
    args.request_id = Some("ab".repeat(32));
    assert_eq!(args.identity(1_000).unwrap().0, "ab".repeat(32));
    args.request_id = Some("AB".repeat(32));
    assert!(args.identity(1_000).is_err());
    args.request_id = None;
    assert!(args.identity(u64::MAX).is_err());
    args.expires_in_secs = 0;
    assert!(args.identity(1_000).is_err());
}

#[test]
fn onboarding_verifies_real_sdk_fixture_and_rejects_substitution() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = onboarding_fixture(false);
    assert!(operation.verify(&config, "onboarding").unwrap().is_some());
    assert!(operation.verify(&config, "faucet").is_err());
    let mut wrong_context = config.clone();
    wrong_context.account_chain_discriminant = 369;
    assert!(operation.verify(&wrong_context, "onboarding").is_err());
    wrong_context = config.clone();
    wrong_context.torii_api_url = Url::parse("https://other.invalid").unwrap();
    assert!(operation.verify(&wrong_context, "onboarding").is_err());
    let mut changed = operation.clone();
    changed.binding.request_id = "dd".repeat(32);
    assert!(changed.verify(&config, "onboarding").is_err());
    let mut changed = operation.clone();
    let OperationV1::Onboarding(onboarding) = &mut changed.operation else {
        unreachable!()
    };
    onboarding.issuer = AccountId::new(KeyPair::random().public_key().clone());
    assert!(changed.verify(&config, "onboarding").is_err());
    let mut changed = operation.clone();
    let OperationV1::Onboarding(onboarding) = &mut changed.operation else {
        unreachable!()
    };
    onboarding
        .request
        .permissions
        .push("CanManageSmartContractCode".to_owned());
    assert!(changed.verify(&config, "onboarding").is_err());
    let mut changed = operation.clone();
    let OperationV1::Onboarding(onboarding) = &mut changed.operation else {
        unreachable!()
    };
    let OnboardingResponseV1::Prepared(prepared) = &mut onboarding.response else {
        unreachable!()
    };
    prepared.signed_transaction_wire_hex.push_str("00");
    assert!(changed.verify(&config, "onboarding").is_err());
}

#[test]
fn proof_required_retains_authenticated_result_without_inventing_a_transaction() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = onboarding_fixture(true);
    assert!(operation.verify(&config, "onboarding").unwrap().is_none());
    let OperationV1::Onboarding(onboarding) = &operation.operation else {
        unreachable!()
    };
    assert!(verify_trusted_issuer(&onboarding.receipt, &onboarding.issuer).is_ok());
    assert_eq!(
        canonical_issuer(&onboarding.issuer.to_string()).unwrap(),
        onboarding.issuer
    );
    assert!(canonical_issuer("not-an-account").is_err());
}

#[test]
fn faucet_requires_exact_independent_policy_and_signed_target() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = faucet_fixture();
    assert!(operation.verify(&config, "faucet").unwrap().is_some());
    let mut changed = operation.clone();
    let OperationV1::Faucet(faucet) = &mut changed.operation else {
        unreachable!()
    };
    faucet.amount = 6_u64.into();
    assert!(changed.verify(&config, "faucet").is_err());
    let mut changed = operation.clone();
    let OperationV1::Faucet(faucet) = &mut changed.operation else {
        unreachable!()
    };
    faucet.issuer = AccountId::new(KeyPair::random().public_key().clone());
    assert!(changed.verify(&config, "faucet").is_err());
    let mut changed = operation.clone();
    let OperationV1::Faucet(faucet) = &mut changed.operation else {
        unreachable!()
    };
    faucet.claim.account_id = faucet.issuer.to_string();
    assert!(changed.verify(&config, "faucet").is_err());
}

#[test]
#[cfg(unix)]
fn immutable_journal_roundtrips_public_evidence_and_reuses_one_submission_marker() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = onboarding_fixture(false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("onboarding");
    let journal = Journal::create(&path).unwrap();
    journal.write_operation(&operation).unwrap();
    assert!(journal.write_operation(&operation).is_err());
    assert!(journal.record_submission(&operation).unwrap());
    let marker = fs::read(path.join("submission.json")).unwrap();
    assert!(!journal.record_submission(&operation).unwrap());
    assert_eq!(fs::read(path.join("submission.json")).unwrap(), marker);
    let mut changed = operation.clone();
    changed.binding.request_id = "ed".repeat(32);
    assert!(journal.record_submission(&changed).is_err());
    drop(journal);
    let loaded: OperationJournalV1 = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(loaded, operation);
    assert!(loaded.verify(&config, "onboarding").unwrap().is_some());
    let text = fs::read_to_string(path.join("operation.json")).unwrap();
    for secret_field in ["private_key", "token_file", "token_fd", "onboarding_token"] {
        assert!(!text.contains(secret_field));
    }
}

#[derive(Debug)]
struct RecoveryTransport {
    expected: SignedTransaction,
    returned: SignedTransaction,
    status: &'static str,
    source: &'static str,
    calls: std::sync::atomic::AtomicUsize,
}

impl iroha::http::HttpTransport for RecoveryTransport {
    fn send_blocking(
        &self,
        request: iroha::http::TransportRequest,
    ) -> Result<iroha::http::Response<Vec<u8>>> {
        use iroha::data_model::{
            query::CommittedTransaction,
            transaction::{DataTriggerSequence, TransactionResult},
        };
        if request.url.path() == "/v1/pipeline/transactions/details" {
            assert_eq!(request.method, iroha::http::Method::POST);
            assert!(
                !request.body.is_empty(),
                "exact details use the SDK's signed canonical query"
            );
        } else {
            assert_eq!(request.method, iroha::http::Method::GET);
            assert!(request.body.is_empty());
        }
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (content_type, body) = match request.url.path() {
            "/v1/pipeline/transactions/status" => {
                assert!(
                    request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "hash"
                            && value == self.expected.hash().to_string())
                );
                if self.status == "Absent" {
                    let absence = iroha_torii_shared::ErrorEnvelope::new(
                        iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                        "Missing exact saved transaction.",
                    )
                    .with_details(iroha_torii_shared::ErrorDetails {
                        pipeline_transaction_status_not_found: Some(
                            iroha_torii_shared::PipelineTransactionStatusNotFoundV1::new(
                                &self.expected.hash(),
                                "global",
                            ),
                        ),
                        ..iroha_torii_shared::ErrorDetails::default()
                    });
                    return Ok(iroha::http::Response::builder()
                        .status(404)
                        .header("Content-Type", "application/json")
                        .body(json::to_vec(&absence)?)?);
                }
                let response = PipelineTransactionStatusResponse::new(
                    hex::encode(self.expected.hash().as_ref()),
                    iroha_torii_shared::PipelineTransactionStatus {
                        kind: self.status.to_owned(),
                        block_height: (self.status == "Applied").then_some(2),
                    },
                    "global".to_owned(),
                    self.source.to_owned(),
                );
                ("application/json", json::to_vec(&response)?)
            }
            "/v1/node/capabilities" => (
                "application/json",
                json::to_vec(
                    &norito::json!({"data_model_version": (iroha::data_model::DATA_MODEL_VERSION)}),
                )?,
            ),
            "/v1/pipeline/transactions/details" => {
                let result = TransactionResult::new(Ok(DataTriggerSequence::default()));
                let output = iroha::data_model::block::execution_output::ExecutionOutputV1::Network(
                    iroha::data_model::block::execution_output::NetworkExecutionOutputV1 {
                        input_index: 0,
                        result,
                        completions: Vec::new(),
                    },
                );
                let details = iroha_torii_shared::PipelineTransactionDetailsResponse {
                    hash: self.expected.hash_as_entrypoint().to_string(),
                    transaction: CommittedTransaction {
                        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                            b"bootstrap recovery test block",
                        )),
                        entrypoint_hash: self.returned.hash_as_entrypoint(),
                        entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                        entrypoint: TransactionEntrypoint::External(self.returned.clone()),
                        output_hash: iroha_crypto::HashOf::new(&output),
                        output_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                        output,
                    },
                };
                ("application/x-norito", norito::to_bytes(&details)?)
            }
            path => panic!("unexpected recovery endpoint: {path}"),
        };
        Ok(iroha::http::Response::builder()
            .status(200)
            .header("Content-Type", content_type)
            .body(body)?)
    }

    fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

#[test]
fn recovery_is_read_only_and_requires_state_resolved_exact_committed_wire() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = onboarding_fixture(false);
    let transaction = operation.verify(&config, "onboarding").unwrap().unwrap();
    let (other_config, other) = faucet_fixture();
    let other_transaction = other.verify(&other_config, "faucet").unwrap().unwrap();
    for (status, source, wrong_wire, expected) in [
        ("Queued", "state", false, Some("Pending")),
        ("Applied", "cache", false, Some("Pending")),
        ("Applied", "state", false, Some("Applied")),
        ("Applied", "state", true, None),
        ("Rejected", "state", false, Some("Rejected")),
        ("Expired", "state", false, Some("Expired")),
        ("FutureState", "state", false, None),
    ] {
        let transport = Arc::new(RecoveryTransport {
            expected: transaction.clone(),
            returned: if wrong_wire {
                other_transaction.clone()
            } else {
                transaction.clone()
            },
            status,
            source,
            calls: AtomicUsize::new(0),
        });
        let mut client_config = crate::operations::tests::fixture_config();
        client_config.network_id = config.network_id;
        client_config.torii_api_url = Url::parse("http://127.0.0.1:1").unwrap();
        let client = IrohaClient::builder(client_config)
            .http_transport(transport.clone())
            .build()
            .unwrap();
        let result = observe(&client, &operation, Some(&transaction));
        match expected {
            Some(expected) => assert_eq!(result.unwrap().status, expected),
            None => assert!(result.is_err()),
        }
        assert!(transport.calls.load(Ordering::SeqCst) >= 1);
    }
}

#[test]
fn public_endpoint_projection_cannot_persist_embedded_credentials() {
    validate_endpoint(&Url::parse("https://taira.sora.org/").unwrap()).unwrap();
    for url in [
        "https://user:secret@example.invalid/",
        "https://example.invalid/?token=secret",
        "https://example.invalid/#secret",
        "file:///runtime/secret",
    ] {
        assert!(validate_endpoint(&Url::parse(url).unwrap()).is_err());
    }
}

#[test]
#[cfg(unix)]
fn preparation_report_exposes_exact_review_inputs_without_runtime_secrets() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (_, operation) = onboarding_fixture(false);
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::create(&root.path().join("operation")).unwrap();
    let report = report(&journal, &operation, "Prepared", None).unwrap();
    let documents = [report.data.clone()];
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["status"].as_str(), Some("Prepared"));
    assert!(documents[0]["issuer"].as_str().is_some());
    assert_eq!(
        documents[0]["network_id"].as_str(),
        Some(operation.network_id.to_string().as_str())
    );
    assert_eq!(
        documents[0]["chain_discriminant"].as_u64(),
        Some(u64::from(operation.chain_discriminant))
    );
    assert_eq!(
        documents[0]["expires_at_unix_ms"].as_u64(),
        Some(operation.binding.execution_expires_at_unix_ms)
    );
    assert_eq!(
        documents[0]["fee_payment"],
        json::to_value(&operation.fee_payment).unwrap()
    );
    assert!(documents[0]["permissions_requested"].as_array().is_some());
    for forbidden in [
        "private_key",
        "onboarding_token",
        "signed_transaction_wire_hex",
    ] {
        assert!(!json::to_string(&documents[0]).unwrap().contains(forbidden));
    }
}

#[test]
fn timeout_bounds_precede_network_access() {
    let config = crate::operations::tests::fixture_config();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert!(operation_client(&config, 0, deadline).is_err());
    assert!(operation_client(&config, 301, deadline).is_err());
    assert!(operation_client(&config, 2, Instant::now()).is_err());
    assert!(operation_client(&config, 2, deadline).is_ok());
    assert_eq!(operation_deadline(10, Some(deadline)).unwrap(), deadline);
    assert!(operation_deadline(0, None).is_err());
    let service = OnboardingService::new(config)
        .unwrap()
        .with_deadline(deadline)
        .unwrap()
        .with_deadline(deadline + Duration::from_secs(10))
        .unwrap();
    assert_eq!(service.deadline, Some(deadline));
    assert!(service.with_deadline(Instant::now()).is_err());
}

#[test]
fn faucet_recovery_binds_original_trusted_request_before_network_or_submission() {
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = faucet_fixture();
    let OperationV1::Faucet(faucet) = &operation.operation else {
        unreachable!()
    };
    let request = FaucetRequest {
        issuer: faucet.issuer.clone(),
        asset_definition: faucet.asset_definition.clone(),
        amount: faucet.amount.clone(),
        fee_payment: faucet.requested_fee.clone(),
    };
    operation.verify_faucet_request(&request).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("faucet");
    {
        let journal = Journal::create(&path).unwrap();
        journal.write_operation(&operation).unwrap();
    }
    let service = OnboardingService::new(config.clone()).unwrap();
    service.verify_faucet_journal(&path, &request).unwrap();
    let mut changed = request.clone();
    changed.amount = 999_u64.into();
    assert!(service.verify_faucet_journal(&path, &changed).is_err());
    for submit in [false, true] {
        let result = if submit {
            service.submit_faucet_with_request(&path, &changed, 1)
        } else {
            service.resume_faucet_with_request(&path, &changed, 1)
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exact trusted request")
        );
    }
    assert!(!path.join("submission.json").exists());
    let held: OperationJournalV1 = Journal::open(&path).unwrap().read_operation().unwrap();
    assert_eq!(held, operation);
    let expired = OnboardingService {
        config,
        deadline: Some(Instant::now()),
        cancellation: None,
    };
    let fresh = temporary.path().join("not-created");
    assert!(
        expired
            .prepare_faucet(&request, &PreparationOptions::default(), &fresh)
            .is_err()
    );
    assert!(
        expired
            .resume_faucet_with_request(&path, &request, 1)
            .is_err()
    );
    assert!(!fresh.exists());
}
#[test]
fn saved_operation_success_requires_verified_completion() {
    for status in [OperationStatus::Applied, OperationStatus::AlreadyPresent] {
        assert!(
            OperationReport {
                status,
                data: Value::Null
            }
            .require_complete()
            .is_ok()
        );
    }
    for status in [
        OperationStatus::Absent,
        OperationStatus::Pending,
        OperationStatus::ProofRequired,
        OperationStatus::Rejected,
        OperationStatus::AliasConflict,
        OperationStatus::Expired,
    ] {
        assert!(
            OperationReport {
                status,
                data: Value::Null
            }
            .require_complete()
            .is_err()
        );
    }
}

#[derive(Debug)]
struct PollingRecoveryTransport {
    inner: RecoveryTransport,
    status_reads: std::sync::atomic::AtomicUsize,
    becomes_applied: bool,
}

fn expired_signed_bootstrap_fixture(
    (config, mut operation): (Config, OperationJournalV1),
) -> (Config, OperationJournalV1) {
    use iroha::data_model::{alias_setup::AliasPlanDispositionV1, prelude::TransactionBuilder};
    use iroha_crypto::Signature;
    use iroha_torii_shared::prepared_transaction::{
        FaucetPreparedSignatureFieldsV1, OnboardingPreparedSignatureFieldsV1,
        PreparedOperationBindingRefV1, faucet_prepared_signature_transcript_v1,
        onboarding_prepared_signature_transcript_v1, prepared_signature_digest_v1,
    };
    use sha2::{Digest as _, Sha256};

    let original = operation
        .verify(&config, operation.kind())
        .unwrap()
        .unwrap();
    let creation = Duration::from_millis(1);
    let ttl = original
        .time_to_live()
        .expect("verified positive fixture TTL");
    let expiry = u64::try_from((creation + ttl).as_millis()).unwrap();
    assert!(
        expiry <= current_unix_ms().unwrap(),
        "real signed lifetime is expired"
    );
    operation.binding.execution_expires_at_unix_ms = expiry;
    let mut metadata = original.metadata().clone();
    metadata.insert(
        "prepared_operation_binding".parse().unwrap(),
        iroha_primitives::json::Json::from_norito_value_ref(
            &json::to_value(&operation.binding).unwrap(),
        )
        .unwrap(),
    );
    // These are the published deterministic issuer seeds of the canonical vectors.
    let seed = match &operation.operation {
        OperationV1::Onboarding(onboarding) => {
            assert!(expiry <= onboarding.receipt.body.valid_until_ms);
            0x51
        }
        OperationV1::Faucet(_) => 0x61,
    };
    let signer = KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519);
    assert_eq!(
        original.authority(),
        &AccountId::new(signer.public_key().clone())
    );
    let mut builder = TransactionBuilder::from_payload(original.payload().clone())
        .unwrap()
        .with_metadata(metadata);
    builder.set_creation_time(creation);
    let transaction = builder.sign(signer.private_key());
    let wire = transaction.encode_wire_v1().unwrap();
    let wire_hex = hex::encode(&wire);
    let wire_sha256 = hex::encode(Sha256::digest(&wire));
    let transaction_hash = hex::encode(transaction.hash().as_ref());
    let binding = PreparedOperationBindingRefV1 {
        schema: &operation.binding.schema,
        semantic_hash_hex: &operation.binding.semantic_hash_hex,
        kind: &operation.binding.kind,
        request_id: &operation.binding.request_id,
        execution_expires_at_unix_ms: expiry,
    };
    match &mut operation.operation {
        OperationV1::Onboarding(onboarding) => {
            let OnboardingResponseV1::Prepared(prepared) = &mut onboarding.response else {
                panic!("expired fixture requires a signed onboarding transaction");
            };
            prepared.binding = operation.binding.clone();
            prepared.transaction_hash_hex = transaction_hash;
            prepared.signed_transaction_wire_hex = wire_hex;
            prepared.signed_transaction_wire_sha256 = wire_sha256;
            let disposition = match prepared.disposition {
                AliasPlanDispositionV1::Create => "create",
                AliasPlanDispositionV1::Repair => "repair",
                AliasPlanDispositionV1::NoOp => "no_op",
                AliasPlanDispositionV1::Conflict => "conflict",
            };
            let transcript =
                onboarding_prepared_signature_transcript_v1(OnboardingPreparedSignatureFieldsV1 {
                    envelope_schema: &prepared.schema,
                    binding,
                    semantic_hash_hex: &prepared.semantic_hash_hex,
                    account_id: &prepared.account_id,
                    alias: &prepared.alias,
                    disposition,
                    transaction_hash_hex: &prepared.transaction_hash_hex,
                    signed_transaction_wire_sha256: &prepared.signed_transaction_wire_sha256,
                    signed_transaction_wire: &wire,
                });
            prepared.server_signature = Signature::try_new(
                signer.private_key(),
                prepared_signature_digest_v1(&transcript).as_ref(),
            )
            .unwrap();
        }
        OperationV1::Faucet(faucet) => {
            let prepared = &mut faucet.prepared;
            prepared.binding = operation.binding.clone();
            prepared.transaction_hash_hex = transaction_hash;
            prepared.signed_transaction_wire_hex = wire_hex;
            prepared.signed_transaction_wire_sha256 = wire_sha256;
            let amount = prepared.amount.to_string();
            let transcript =
                faucet_prepared_signature_transcript_v1(FaucetPreparedSignatureFieldsV1 {
                    envelope_schema: &prepared.schema,
                    binding,
                    claim_account_id: &prepared.claim.account_id,
                    claim_pow_anchor_height: prepared.claim.pow_anchor_height,
                    claim_pow_nonce_hex: &prepared.claim.pow_nonce_hex,
                    semantic_hash_hex: &prepared.semantic_hash_hex,
                    account_id: &prepared.account_id,
                    asset_definition_id: &prepared.asset_definition_id,
                    asset_id: &prepared.asset_id,
                    amount: &amount,
                    transaction_hash_hex: &prepared.transaction_hash_hex,
                    signed_transaction_wire_sha256: &prepared.signed_transaction_wire_sha256,
                    signed_transaction_wire: &wire,
                });
            prepared.server_signature = Signature::try_new(
                signer.private_key(),
                prepared_signature_digest_v1(&transcript).as_ref(),
            )
            .unwrap();
        }
    }
    let verified = operation
        .verify(&config, operation.kind())
        .unwrap()
        .unwrap();
    assert_eq!(verified.encode_wire_v1().unwrap(), wire);
    assert_eq!(verified.creation_time(), creation);
    assert_eq!(verified.time_to_live(), Some(ttl));
    assert_eq!(
        u64::try_from((verified.creation_time() + ttl).as_millis()).unwrap(),
        operation.binding.execution_expires_at_unix_ms,
    );
    (config, operation)
}

#[test]
#[cfg(unix)]
fn expired_saved_bootstrap_is_terminal_only_without_a_dispatch_marker() {
    use std::sync::{Arc, atomic::AtomicUsize};
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    for (config, operation) in [
        expired_signed_bootstrap_fixture(onboarding_fixture(false)),
        expired_signed_bootstrap_fixture(faucet_fixture()),
    ] {
        let transaction = operation
            .verify(&config, operation.kind())
            .unwrap()
            .unwrap();
        assert!(current_unix_ms().unwrap() >= operation.binding.execution_expires_at_unix_ms);
        for (remote, dispatched, expected) in [
            ("Absent", false, OperationStatus::Expired),
            ("Absent", true, OperationStatus::Pending),
            ("Queued", false, OperationStatus::Pending),
            ("Applied", false, OperationStatus::Applied),
            ("Rejected", false, OperationStatus::Rejected),
        ] {
            for submit in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("saved-bootstrap");
                let journal = Journal::create(&path).unwrap();
                journal.write_operation(&operation).unwrap();
                if dispatched {
                    assert!(journal.record_submission(&operation).unwrap());
                }
                drop(journal);
                let original = fs::read(path.join("operation.json")).unwrap();
                let marker = dispatched.then(|| fs::read(path.join("submission.json")).unwrap());
                let transport = Arc::new(RecoveryTransport {
                    expected: transaction.clone(),
                    returned: transaction.clone(),
                    status: remote,
                    source: "state",
                    calls: AtomicUsize::new(0),
                });
                let client = IrohaClient::builder(config.clone())
                    .http_transport(transport.clone())
                    .build()
                    .unwrap();
                let result = run_saved_operation_with_client(
                    &config,
                    &path,
                    1,
                    Instant::now() + Duration::from_secs(1),
                    SavedAction {
                        kind: operation.kind(),
                        submit,
                        token: None,
                        expected_faucet: None,
                        cancellation: None,
                    },
                    || Ok(client),
                )
                .unwrap();
                assert_eq!(result.status, expected);
                assert_eq!(fs::read(path.join("operation.json")).unwrap(), original);
                assert_eq!(
                    fs::read(path.join("submission.json")).ok(),
                    marker,
                    "read-only recovery never creates or changes a dispatch marker",
                );
                // The transport accepts only exact status/details/capability reads.
                assert!(transport.calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
            }
        }
    }
}
impl iroha::http::HttpTransport for PollingRecoveryTransport {
    fn send_blocking(
        &self,
        request: iroha::http::TransportRequest,
    ) -> Result<iroha::http::Response<Vec<u8>>> {
        if request.url.path() == "/v1/pipeline/transactions/status" {
            let read = self
                .status_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let kind = if self.becomes_applied && read > 0 {
                "Applied"
            } else {
                "Queued"
            };
            let response = PipelineTransactionStatusResponse::new(
                hex::encode(self.inner.expected.hash().as_ref()),
                iroha_torii_shared::PipelineTransactionStatus {
                    kind: kind.to_owned(),
                    block_height: (kind == "Applied").then_some(2),
                },
                "global".to_owned(),
                "state".to_owned(),
            );
            return Ok(iroha::http::Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(json::to_vec(&response)?)?);
        }
        iroha::http::HttpTransport::send_blocking(&self.inner, request)
    }
    fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}
#[test]
fn submitted_envelope_waits_read_only_for_applied_and_timeout_stays_pending() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let _profile = ChainDiscriminantGuard::enter(0x02f1);
    let (config, operation) = onboarding_fixture(false);
    let transaction = operation.verify(&config, "onboarding").unwrap().unwrap();
    for applied in [true, false] {
        let transport = Arc::new(PollingRecoveryTransport {
            inner: RecoveryTransport {
                expected: transaction.clone(),
                returned: transaction.clone(),
                status: "Applied",
                source: "state",
                calls: AtomicUsize::new(0),
            },
            status_reads: AtomicUsize::new(0),
            becomes_applied: applied,
        });
        let client = IrohaClient::builder(crate::operations::tests::fixture_config())
            .http_transport(transport.clone())
            .build()
            .unwrap();
        let outcome = observe_after_submission(
            &client,
            &operation,
            Some(&transaction),
            iroha::client::TransactionWaitOptions {
                timeout: Duration::from_millis(if applied { 100 } else { 3 }),
                poll_interval: Duration::from_millis(1),
            },
        )
        .unwrap();
        assert_eq!(outcome.status, if applied { "Applied" } else { "Pending" });
        assert_eq!(outcome.evidence.is_some(), applied);
        assert!(transport.status_reads.load(Ordering::SeqCst) >= if applied { 2 } else { 1 });
        // The closed mock rejects every non-read route, including any second submit.
    }
}

#[path = "onboarding_cancellation_tests.rs"]
mod cancellation_tests;
