//! Exact native plan authentication and ambiguous submission recovery.
use super::*;
use iroha::data_model::{nexus::FeeDebitSource, transaction::Executable};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias,
};
use std::{
    cell::{Cell, RefCell},
    num::NonZeroU64,
};

/// Load the deterministic client configuration shared by deployment fixtures.
fn fixture_config() -> Result<Config> {
    fixture_config_at("http://127.0.0.1:8080/")
}

/// Load the deterministic fixture configuration bound to one Torii URL.
fn fixture_config_at(torii_url: &str) -> Result<Config> {
    // Public deterministic SDK test identity; never a runtime deployment account.
    let source = format!(
        r#"
chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "{torii_url}"
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
[transaction]
time_to_live_ms = 100000
status_timeout_ms = 100000
nonce = false
"#
    );
    let (config, _) = Config::load_bytes_with_musubi_publication(
        Path::new("deployment-test.toml"),
        source.as_bytes(),
    )
    .map_err(|error| eyre!(format!("{error:?}")))?;
    Ok(config)
}

/// Accepted fee quote for one exact signed fixture transaction.
fn accepted_quote(fee: &FeePaymentIntent, transaction: &SignedTransaction) -> FeeQuoteResponse {
    FeeQuoteResponse {
        intent: fee.clone(),
        observation: iroha_torii_shared::FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 2,
            route_dataspace_id: DataSpaceId::UNIVERSAL,
        },
        components: vec![],
        capacities: vec![],
        decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
            debit_source: FeeDebitSource::Account(transaction.authority().clone()),
            program_revision: None,
        },
    }
}

pub fn fixture() -> Result<(Config, PlanRecord)> {
    fixture_with_source(
        "seiyaku Coffee { view fn points(int cups) authorize(anyone) -> int { return cups * 10; } }",
    )
}

fn fixture_with_source(source: &str) -> Result<(Config, PlanRecord)> {
    let config = fixture_config()?;
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .map_err(|error| eyre!(error))?;
    let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
    let fee = FeePaymentIntent::authority(Vec::new(), Some(NonZeroU64::new(1_000_000).unwrap()));
    let address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        7,
        DataSpaceId::UNIVERSAL,
    )?;
    let alias: ContractAlias = "coffee::universal".parse()?;
    let metadata = deployment_transaction_metadata(&address, &[])?;
    let signing = TransactionSigningContext {
        network_id: config.network_id,
        authority: &config.account,
        private_key: config.key_pair.private_key(),
        transaction_ttl: Some(config.transaction_ttl),
        fee_payment: &fee,
        metadata: &metadata,
    };
    let upload = build_native_upload_transaction_plan(
        &signing,
        ContractArtifactId::new(DataSpaceId::UNIVERSAL, verified.code_hash),
        &artifact,
    )?;
    let mut uploads = upload.pre_stage;
    uploads.push(upload.finalize);
    let mut manifest_budget = ManifestEncodingBudget::new()?;
    let signer_backing = manifest_budget.reserve_signer(config.key_pair.public_key())?;
    let signing_frame = manifest_budget.reserve_frame(&verified.manifest)?;
    let manifest = verified.manifest.try_signed(
        manifest_budget.context(),
        signing_frame.remaining_bytes(),
        &config.key_pair,
    )?;
    drop(signing_frame);
    let register = signing.sign([InstructionBox::from(RegisterSmartContractCode {
        artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, verified.code_hash),
        manifest,
    })])?;
    let commit = build_commit_deployment_transaction(
        &signing,
        7,
        address.clone(),
        verified.code_hash,
        alias.clone(),
        None,
    )?;
    let sequence = deployment_transaction_sequence(false, uploads, register, commit);
    let quotes = sequence
        .iter()
        .map(|(_, _, transaction)| accepted_quote(&fee, transaction))
        .collect();
    let transactions: Vec<_> = sequence
        .into_iter()
        .map(|(name, _, tx)| TransactionRecord {
            name,
            hash: tx.hash().to_string(),
            norito_hex: hex::encode(tx.encode_versioned()),
        })
        .collect();
    drop(signer_backing); // Every native graph has been consumed into encoded records.
    let preflight = DeploymentPreflight {
        network_id: config.network_id,
        chain_id: config.chain.to_string(),
        authority: config.account.clone(),
        authorization: DeploymentAuthorization {
            account_exists: true,
            manage_alias_permission: CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            }
            .into(),
        },
        chain_discriminant: config.account_chain_discriminant,
        contract_alias: alias,
        contract_address: address,
        dataspace_id: DataSpaceId::UNIVERSAL,
        code_hash: verified.code_hash,
        abi_hash: verified.abi_hash,
        deploy_nonce: 7,
        previous_contract_address: None,
        observed_block_height: 1,
        observed_block_hash: Hash::new(b"test-block").to_string(),
        fee_quotes: quotes,
        transaction_hashes: transactions.iter().map(|tx| tx.hash.clone()).collect(),
    };
    Ok((
        config,
        PlanRecord {
            version: 1,
            preflight,
            artifact_hex: hex::encode(artifact),
            requested_fee: fee,
            transactions,
        },
    ))
}

#[test]
fn signed_plan_roundtrip_rejects_context_artifact_fee_and_instruction_substitution() -> Result<()> {
    let (config, record) = fixture()?;
    validate_plan(&record, &config)?;
    let encoded = norito::json::to_vec(&record)?;
    let decoded: PlanRecord = norito::json::from_slice(&encoded)?;
    validate_plan(&decoded, &config)?;
    let mut changed = record.clone();
    changed.preflight.fee_quotes[0]
        .observation
        .route_dataspace_id = DataSpaceId::new(u64::MAX);
    assert!(validate_plan(&changed, &config).is_err());
    changed = record.clone();
    changed.preflight.deploy_nonce += 1;
    assert!(validate_plan(&changed, &config).is_err());
    changed = record.clone();
    changed.artifact_hex.replace_range(0..2, "00");
    assert!(validate_plan(&changed, &config).is_err());
    changed = record.clone();
    changed.preflight.chain_discriminant ^= 1;
    assert!(validate_plan(&changed, &config).is_err());
    changed = record.clone();
    changed.transactions.swap(0, 1);
    assert!(validate_plan(&changed, &config).is_err());
    changed = record.clone();
    changed.requested_fee =
        FeePaymentIntent::authority(Vec::new(), Some(NonZeroU64::new(2_000_000).unwrap()));
    assert!(validate_plan(&changed, &config).is_err());
    // A valid signature is insufficient: native commit contents must still match the retained CAS.
    changed = record.clone();
    let index = changed.transactions.len() - 1;
    let old = decode_transaction(&changed.transactions[index])?;
    let malicious = TransactionBuilder::new(
        config.network_id,
        config.account.clone(),
        old.payload().fee_payment.clone(),
    )
    .with_metadata(old.metadata().clone())
    .with_instructions(Vec::<InstructionBox>::new())
    .try_sign(config.key_pair.private_key())?;
    changed.transactions[index].norito_hex = hex::encode(malicious.encode_versioned());
    changed.transactions[index].hash = malicious.hash().to_string();
    changed.preflight.transaction_hashes[index] = malicious.hash().to_string();
    assert!(validate_plan(&changed, &config).is_err());
    assert!(matches!(old.instructions(), Executable::Instructions(_)));
    Ok(())
}

struct MockTransport {
    submitted: RefCell<Vec<String>>,
    waited: RefCell<Vec<String>>,
    ambiguous_once: Cell<bool>,
    wrong_hash: Cell<bool>,
    failure_kind: Cell<Option<&'static str>>,
    pending: Cell<bool>,
}
impl MockTransport {
    fn new(ambiguous: bool) -> Self {
        Self {
            submitted: RefCell::new(vec![]),
            waited: RefCell::new(vec![]),
            ambiguous_once: Cell::new(ambiguous),
            wrong_hash: Cell::new(false),
            failure_kind: Cell::new(None),
            pending: Cell::new(false),
        }
    }
}
impl DeploymentTransport for MockTransport {
    fn submit(&self, tx: &SignedTransaction) -> Result<()> {
        self.submitted.borrow_mut().push(tx.hash().to_string());
        if self.ambiguous_once.replace(false) {
            return Err(eyre!("connection closed after request write"));
        }
        Ok(())
    }
    fn wait(&self, hash: HashOf<SignedTransaction>) -> Result<AppliedEvidence> {
        self.waited.borrow_mut().push(hash.to_string());
        if self.pending.get() {
            return Err(eyre!("exact transaction status remains unresolved"));
        }
        if let Some(kind) = self.failure_kind.get() {
            let response = norito::json::from_value(norito::json!({
                "hash": (hash.to_string()), "scope": "global", "resolved_from": "state", "status": { "kind": kind }
            }))?;
            let proof = TransactionFinalityFailure::from_response(hash, response)?
                .ok_or_else(|| eyre!("fixture must produce canonical fixed failure"))?;
            return Err(eyre::Report::new(proof).wrap_err("fixture SDK error context"));
        }

        Ok(AppliedEvidence {
            hash: if self.wrong_hash.get() {
                "wrong".to_owned()
            } else {
                hash.to_string()
            },
            terminal_kind: "Applied".to_owned(),
            block_height: 2,
            scope: "global".to_owned(),
            resolved_from: "state".to_owned(),
            charge: None,
        })
    }
}

#[test]
fn ambiguous_submit_recovers_exact_hash_and_never_replays() -> Result<()> {
    let (config, record) = fixture()?;
    validate_plan(&record, &config)?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("journal"), true)?;
    journal.put_exact("plan.json", &record)?;
    let transport = MockTransport::new(true);
    let error = execute_transactions(&record, &journal, &transport, &mut |_| Ok(())).unwrap_err();
    assert!(
        matches!(error, DeploymentError::Pending { hash, .. } if hash == record.transactions[0].hash)
    );
    assert!(journal.exists("attempt-0000.json")?);
    assert_eq!(transport.submitted.borrow().len(), 1);
    let evidence = execute_transactions(&record, &journal, &transport, &mut |_| Ok(()))?;
    assert_eq!(evidence.len(), record.transactions.len());
    assert_eq!(
        transport.submitted.borrow().len(),
        record.transactions.len()
    );
    assert_eq!(transport.submitted.borrow()[0], record.transactions[0].hash);
    execute_transactions(&record, &journal, &transport, &mut |_| Ok(()))?;
    assert_eq!(
        transport.submitted.borrow().len(),
        record.transactions.len()
    );
    assert_eq!(transport.waited.borrow()[0], record.transactions[0].hash);
    Ok(())
}

#[test]
fn crash_before_dispatch_and_wrong_finality_never_create_another_attempt() -> Result<()> {
    let (_, record) = fixture()?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("journal"), true)?;
    journal.put_exact(
        "attempt-0000.json",
        &TransactionAttempt {
            name: record.transactions[0].name.clone(),
            hash: record.transactions[0].hash.clone(),
        },
    )?;
    let transport = MockTransport::new(false);
    transport.wrong_hash.set(true);
    assert!(matches!(
        execute_transactions(&record, &journal, &transport, &mut |_| Ok(())),
        Err(DeploymentError::Pending { .. })
    ));
    assert!(transport.submitted.borrow().is_empty());
    assert!(!journal.exists("attempt-0001.json")?);
    let hash = decode_transaction(&record.transactions[0])?.hash();
    let mut evidence = transport.wait(hash)?;
    evidence.hash = hash.to_string();
    evidence.scope = "local".to_owned();
    assert!(validate_applied(hash, &evidence).is_err());
    evidence.scope = "global".to_owned();
    evidence.resolved_from = "pipeline".to_owned();
    assert!(validate_applied(hash, &evidence).is_err());
    Ok(())
}

#[test]
fn prepared_persistence_and_completion_require_authenticated_plan_and_receipt() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config.clone())?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    let prepared = PreparedDeployment {
        record: record.clone(),
    };
    assert_eq!(prepared.preflight().code_hash, record.preflight.code_hash);
    service.persist(&prepared, &path)?;
    assert!(
        service
            .completed_receipt(&path, &prepared.record.preflight)?
            .is_none()
    );
    assert_eq!(receipt_path(&path), path.join(RECEIPT_FILE_NAME));
    let mut wrong_config = config;
    wrong_config.account_chain_discriminant ^= 1;
    assert!(
        DeploymentService::new(wrong_config)?
            .resume(&path, &mut |_| Ok(()))
            .is_err()
    );
    let journal = Journal::open(&path, false)?;
    let stages = execute_transactions(&record, &journal, &MockTransport::new(false), &mut |_| {
        Ok(())
    })?;
    let context = &record.preflight;
    let mut receipt = completed_receipt_fixture(&record, stages);
    journal.put_exact(RECEIPT_FILE_NAME, &receipt)?;
    assert!(retained_receipt(&record, &journal)?.is_some());
    // Historical recovery requires only the exact immutable commit status. Its transport has no
    // alias-read method, so a later alias update cannot invalidate this finalized receipt.
    let historical = MockTransport::new(false);
    let recovered =
        verify_completed_record(&record, &journal, &historical)?.expect("historical completion");
    assert_eq!(recovered.contract_address, receipt.contract_address);
    assert!(historical.submitted.borrow().is_empty());
    assert_eq!(
        historical.waited.borrow().as_slice(),
        &[receipt.commit.hash.clone()]
    );

    receipt.code_hash = Hash::new(b"different-artifact");
    std::fs::write(receipt_path(&path), norito::json::to_vec(&receipt)?)?;
    assert!(retained_receipt(&record, &journal).is_err());
    receipt.code_hash = context.code_hash;
    std::fs::write(receipt_path(&path), norito::json::to_vec(&receipt)?)?;
    journal.put_exact(
        "cancelled.json",
        &DeploymentCancellation {
            transaction_hashes: record.preflight.transaction_hashes.clone(),
        },
    )?;
    assert!(retained_receipt(&record, &journal).is_err());
    std::fs::remove_file(path.join("cancelled.json"))?;
    assert!(retained_receipt(&record, &journal)?.is_some());
    let first = &record.transactions[0];
    let hash = decode_transaction(first)?.hash();
    let response = norito::json::from_value(norito::json!({
        "hash": (hash.to_string()), "scope": "global", "resolved_from": "state", "status": { "kind": "Rejected" }
    }))?;
    journal.put_exact(
        "failed-0000.json",
        &DeploymentFailure {
            step: first.name.clone(),
            hash: first.hash.clone(),
            proof: TransactionFinalityFailure::from_response(hash, response)?
                .expect("canonical contradictory failure fixture"),
        },
    )?;
    assert!(retained_receipt(&record, &journal).is_err());
    let rejected_history = MockTransport::new(false);
    assert!(verify_completed_record(&record, &journal, &rejected_history).is_err());
    assert!(rejected_history.waited.borrow().is_empty());
    assert!(rejected_history.submitted.borrow().is_empty());
    Ok(())
}

#[test]
fn retained_preflight_and_current_completion_require_original_authenticated_plan() -> Result<()> {
    let (config, record) = fixture()?;
    let expected_code_hash = record.preflight.code_hash;
    let service = DeploymentService::new(config.clone())?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    service.persist(
        &PreparedDeployment {
            record: record.clone(),
        },
        &path,
    )?;
    let retained = service.retained_preflight(&path)?;
    assert_eq!(retained.code_hash, record.preflight.code_hash);
    assert_eq!(retained.contract_alias, record.preflight.contract_alias);
    assert_eq!(
        retained.transaction_hashes,
        record.preflight.transaction_hashes
    );
    assert!(
        service
            .current_completed_receipt(&path, &retained)?
            .is_none()
    );
    assert!(
        service
            .retained_lifecycle_hook(&path, expected_code_hash)?
            .is_none()
    );

    let mut other = config;
    other.key_pair = KeyPair::try_from_seed(vec![0x78; 32], iroha_crypto::Algorithm::Ed25519)?;
    other.account = AccountId::of(other.key_pair.public_key().clone());
    let other = DeploymentService::new(other)?;
    assert!(other.retained_preflight(&path).is_err());
    assert!(
        other
            .retained_lifecycle_hook(&path, expected_code_hash)
            .is_err()
    );
    assert!(other.current_completed_receipt(&path, &retained).is_err());

    let mut substituted = record;
    substituted.preflight.code_hash = Hash::new(b"substituted artifact");
    std::fs::write(path.join("plan.json"), norito::json::to_vec(&substituted)?)?;
    assert!(service.retained_preflight(&path).is_err());
    assert!(
        service
            .retained_lifecycle_hook(&path, expected_code_hash)
            .is_err()
    );
    assert!(service.current_completed_receipt(&path, &retained).is_err());
    Ok(())
}

#[test]
fn retained_lifecycle_guidance_rejects_a_valid_alternate_plan_for_the_same_authority() -> Result<()>
{
    let (config, original) = fixture()?;
    let (_, alternate) = fixture_with_source(
        "seiyaku Coffee { state int value; hajimari(int start) { value = start; } view fn points(int cups) authorize(anyone) -> int { return cups + value; } }",
    )?;
    validate_plan(&original, &config)?;
    validate_plan(&alternate, &config)?;
    assert_eq!(original.preflight.authority, alternate.preflight.authority);
    assert_ne!(original.preflight.code_hash, alternate.preflight.code_hash);
    let expected_code_hash = original.preflight.code_hash;
    let alternate_code_hash = alternate.preflight.code_hash;
    let service = DeploymentService::new(config)?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("original");
    let other = temporary.path().join("alternate");
    service.persist(&PreparedDeployment { record: original }, &path)?;
    service.persist(&PreparedDeployment { record: alternate }, &other)?;
    assert!(
        service
            .retained_lifecycle_hook(&path, expected_code_hash)?
            .is_none()
    );
    std::fs::write(
        path.join("plan.json"),
        std::fs::read(other.join("plan.json"))?,
    )?;
    assert_eq!(
        service.retained_preflight(&path)?.code_hash,
        alternate_code_hash,
        "the replacement is independently authenticated, not malformed fixture data"
    );
    let advisory = service.retained_lifecycle_hook(&path, expected_code_hash);
    assert!(
        matches!(&advisory, Err(DeploymentError::InvalidRequest(reason))
        if reason == "retained initialization artifact differs from completed deployment")
    );
    assert!(
        advisory.ok().flatten().is_none(),
        "optional presentation omits the mismatch"
    );
    let hook = service
        .retained_lifecycle_hook(&path, alternate_code_hash)?
        .unwrap();
    assert_eq!(hook.name, "hajimari");
    assert_eq!(
        hook.params,
        [LifecycleParameter {
            name: "start".into(),
            type_name: "int".into()
        }]
    );
    Ok(())
}

#[test]
fn invalid_artifact_and_unauthenticated_governance_fail_before_network_access() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config.clone())?;
    let mut request = DeploymentRequest {
        artifact: vec![],
        alias: record.preflight.contract_alias,
        fee_payment: record.requested_fee,
        governance_approvers: vec![],
    };
    assert!(matches!(
        service.prepare(&request),
        Err(DeploymentError::Artifact(_))
    ));
    request.artifact = hex::decode(&record.artifact_hex)?;
    request.governance_approvers.push(config.account.clone());
    assert!(matches!(
        service.preflight(&request),
        Err(DeploymentError::InvalidRequest(_))
    ));
    let mut zero_timeout = config;
    zero_timeout.transaction_status_timeout = Duration::ZERO;
    assert!(DeploymentService::new(zero_timeout).is_err());
    Ok(())
}

#[test]
fn native_sequence_signing_matches_the_retained_plan_layout() -> Result<()> {
    let (config, record) = fixture()?;
    let context = &record.preflight;
    let service = DeploymentService::new(config.clone())?;
    let artifact = hex::decode(&record.artifact_hex)?;
    let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
    let request = DeploymentRequest {
        artifact,
        alias: context.contract_alias.clone(),
        fee_payment: record.requested_fee.clone(),
        governance_approvers: vec![],
    };
    // Signing reads only the nonce and the CAS address; the observed snapshot is inert here.
    let state = ValidatedContractDeploymentState {
        snapshot: norito::json::from_value(norito::json!({
            "authority": (context.authority.to_string()),
            "contract_alias": (context.contract_alias.to_string()),
            "deploy_nonce": (context.deploy_nonce.to_string()),
            "dataspace_alias": "universal",
            "dataspace_id": "0",
            "previous_contract_address": null,
            "observed_block_height": "1",
            "observed_block_hash": (context.observed_block_hash.clone()),
            "ledger_time_ms": "1",
            "chain_discriminant": (context.chain_discriminant.to_string()),
        }))?,
        deploy_nonce: context.deploy_nonce,
        dataspace_id: context.dataspace_id,
        previous_contract_address: context.previous_contract_address.clone(),
    };
    let mut manifest_budget = ManifestEncodingBudget::new()?;
    let signer_backing = manifest_budget.reserve_signer(config.key_pair.public_key())?;
    let signing_frame = manifest_budget.reserve_frame(&verified.manifest)?;
    let manifest = verified.manifest.try_signed(
        manifest_budget.context(),
        signing_frame.remaining_bytes(),
        &config.key_pair,
    )?;
    drop(signing_frame);
    let sequence = service.sign_native_sequence(
        &request,
        manifest,
        verified.code_hash,
        &state,
        &context.contract_address,
    )?;
    assert_eq!(sequence.len(), record.transactions.len());
    for ((name, _, signed), retained) in sequence.iter().zip(&record.transactions) {
        let expected = decode_transaction(retained)?;
        assert_eq!(name, &retained.name);
        assert_eq!(signed.authority(), expected.authority());
        assert_eq!(signed.metadata(), expected.metadata());
        assert_eq!(signed.instructions(), expected.instructions());
    }
    drop(sequence);
    drop(signer_backing);
    Ok(())
}

#[test]
fn confirmed_rejection_or_expiry_is_durable_and_allows_only_explicit_new_work() -> Result<()> {
    for kind in ["Rejected", "Expired"] {
        let (_, record) = fixture()?;
        let temporary = tempfile::tempdir()?;
        let journal = Journal::open(&temporary.path().join("journal"), true)?;
        journal.put_exact("plan.json", &record)?;
        let transport = MockTransport::new(false);
        transport.failure_kind.set(Some(kind));
        let failure = match execute_transactions(&record, &journal, &transport, &mut |_| Ok(())) {
            Err(DeploymentError::Failed(failure)) => failure,
            result => panic!("expected typed fixed failure, got {result:?}"),
        };
        assert_eq!(failure.hash, record.transactions[0].hash);
        assert_eq!(failure.proof.response().status.kind, kind);
        assert!(journal.exists("failed-0000.json")?);
        assert!(!journal.exists("attempt-0001.json")?);
        let retained: DeploymentFailure = journal.read("failed-0000.json")?;
        assert_eq!(retained.proof, failure.proof);
        // Boxed error evidence renders exactly like its durable failure record.
        assert_eq!(
            norito::json::to_vec(&failure)?,
            norito::json::to_vec(&retained)?
        );
        let JournalDisposition::Failed(inspected) =
            inspect_transactions(&record, &journal, &transport)?
        else {
            panic!("exact fixed failure must be inspectable");
        };
        assert_eq!(inspected.proof, failure.proof);
        assert_eq!(transport.submitted.borrow().len(), 1);
        // A cached/ambiguous current observation cannot release the gate merely because a file exists.
        transport.failure_kind.set(None);
        transport.wrong_hash.set(true);
        assert!(inspect_transactions(&record, &journal, &transport).is_err());
        assert_eq!(transport.submitted.borrow().len(), 1);
    }
    Ok(())
}

#[test]
fn service_journal_and_review_use_configured_discriminant_without_ambient_state() -> Result<()> {
    let (mut config, mut record) = fixture()?;
    config.account_chain_discriminant = 42;
    record.preflight.chain_discriminant = 42;
    let expected_authority = config.account.to_i105_for_discriminant(42)?;
    let service = DeploymentService::new(config)?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    let _caller_profile = ChainDiscriminantGuard::enter(73);
    let review = record.preflight.to_json()?;
    assert_eq!(
        review
            .get("authority")
            .and_then(norito::json::Value::as_str),
        Some(expected_authority.as_str())
    );
    let expected = record.preflight.clone();
    service.persist(&PreparedDeployment { record }, &path)?;
    assert!(service.completed_receipt(&path, &expected)?.is_none());
    assert_eq!(
        iroha::data_model::account::address::chain_discriminant(),
        73
    );
    Ok(())
}

fn completed_receipt_fixture(
    record: &PlanRecord,
    stages: Vec<AppliedEvidence>,
) -> DeploymentReceipt {
    let context = &record.preflight;
    DeploymentReceipt {
        version: 1,
        network_id: context.network_id,
        chain_id: context.chain_id.clone(),
        chain_discriminant: context.chain_discriminant,
        authority: context.authority.clone(),
        contract_alias: context.contract_alias.clone(),
        contract_address: context.contract_address.clone(),
        contract_subject_account: context.contract_address.subject_id(),
        dataspace_id: context.dataspace_id,
        code_hash: context.code_hash,
        abi_hash: context.abi_hash,
        commit: stages.last().unwrap().clone(),
        stages,
        readback_block_height: 3,
        readback_block_hash: Hash::new(b"readback-block").to_string(),
        stored_artifact_matches: true,
    }
}

#[test]
fn historical_inspection_accepts_a_new_reader_but_never_a_new_deployment_signer() -> Result<()> {
    for disposition in ["Completed", "Rejected", "Pending"] {
        let (mut reader_config, record) = fixture()?;
        reader_config.key_pair =
            KeyPair::try_from_seed(vec![0x77; 32], iroha_crypto::Algorithm::Ed25519)?;
        reader_config.account = AccountId::of(reader_config.key_pair.public_key().clone());
        assert_ne!(reader_config.account, record.preflight.authority);
        let read_context = DeploymentReadContext::from(&reader_config);
        validate_read_plan(&record, &read_context)?;
        assert!(validate_plan(&record, &reader_config).is_err());
        let mut substituted = record.clone();
        substituted.preflight.authority = reader_config.account.clone();
        assert!(validate_read_plan(&substituted, &read_context).is_err());
        let mut wrong_profile = reader_config.clone();
        wrong_profile.account_chain_discriminant ^= 1;
        assert!(validate_read_plan(&record, &DeploymentReadContext::from(&wrong_profile)).is_err());

        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("journal");
        let journal = Journal::open(&path, true)?;
        journal.put_exact("plan.json", &record)?;
        let writer = MockTransport::new(disposition == "Pending");
        let reader = MockTransport::new(false);
        match disposition {
            "Completed" => {
                let stages = execute_transactions(&record, &journal, &writer, &mut |_| Ok(()))?;
                journal.put_exact(
                    RECEIPT_FILE_NAME,
                    &completed_receipt_fixture(&record, stages),
                )?;
            }
            "Rejected" => {
                writer.failure_kind.set(Some("Rejected"));
                assert!(matches!(
                    execute_transactions(&record, &journal, &writer, &mut |_| Ok(())),
                    Err(DeploymentError::Failed(_))
                ));
                reader.failure_kind.set(Some("Rejected"));
            }
            "Pending" => {
                assert!(matches!(
                    execute_transactions(&record, &journal, &writer, &mut |_| Ok(())),
                    Err(DeploymentError::Pending { .. })
                ));
                reader.pending.set(true);
            }
            _ => unreachable!(),
        }
        let observed = inspect_read_record(&record, &journal, &read_context, &reader)?;
        match (disposition, observed) {
            ("Completed", JournalDisposition::Completed(receipt)) => {
                assert_eq!(receipt.authority, record.preflight.authority);
                assert_eq!(reader.waited.borrow().as_slice(), &[receipt.commit.hash]);
            }
            ("Rejected", JournalDisposition::Failed(failure)) => {
                assert_eq!(failure.hash, record.transactions[0].hash);
            }
            ("Pending", JournalDisposition::Pending { hash, .. }) => {
                assert_eq!(hash.as_ref(), Some(&record.transactions[0].hash));
            }
            (_, observed) => panic!("wrong rotated-reader disposition: {observed:?}"),
        }
        assert!(reader.submitted.borrow().is_empty());
        drop(journal);
        let reader_service = DeploymentService::new(reader_config)?;
        let prepared = PreparedDeployment { record };
        assert!(reader_service.persist(&prepared, &path).is_err());
        assert!(
            reader_service
                .execute(&prepared, &path, &mut |_| Ok(()))
                .is_err()
        );
        assert!(reader_service.resume(&path, &mut |_| Ok(())).is_err());
    }
    Ok(())
}

#[test]
fn only_unattempted_plans_can_be_cancelled_and_cancelled_plans_cannot_resume() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config)?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("cancelled");
    let prepared = PreparedDeployment {
        record: record.clone(),
    };
    service.persist(&prepared, &path)?;
    let cancelled = service.cancel(&path, &record.preflight)?;
    assert_eq!(
        cancelled.transaction_hashes,
        record.preflight.transaction_hashes
    );
    assert_eq!(service.cancel(&path, &record.preflight)?, cancelled);
    assert!(
        service
            .resume(&path, &mut |_| panic!(
                "cancelled plan cannot reach progress"
            ))
            .is_err()
    );
    assert!(
        service
            .execute(&prepared, &path, &mut |_| panic!(
                "cancelled plan cannot reach progress"
            ))
            .is_err()
    );
    let journal = Journal::open(&path, false)?;
    let reader = MockTransport::new(false);
    assert!(matches!(
        inspect_read_record(&record, &journal, &DeploymentReadContext::from(&service.config), &reader)?,
        JournalDisposition::Cancelled(observed) if observed == cancelled
    ));
    assert!(reader.waited.borrow().is_empty());
    assert!(reader.submitted.borrow().is_empty());
    assert!(execute_transactions(&record, &journal, &reader, &mut |_| Ok(())).is_err());
    assert!(reader.submitted.borrow().is_empty());

    for marker in [
        "attempt-0000.json",
        "applied-0000.json",
        "failed-0000.json",
        RECEIPT_FILE_NAME,
        "attempt-9999.json",
    ] {
        let path = temporary.path().join(marker);
        service.persist(&prepared, &path)?;
        let journal = Journal::open(&path, false)?;
        journal.put_exact(marker, &norito::json!({ "unexpected": true }))?;
        drop(journal);
        assert!(
            service.cancel(&path, &record.preflight).is_err(),
            "execution evidence must prevent cancellation: {marker}"
        );
        assert!(!Journal::open(&path, false)?.exists("cancelled.json")?);
    }
    Ok(())
}

#[test]
fn deployment_progress_follows_durable_attempt_and_applied_records_in_exact_order() -> Result<()> {
    let (_, record) = fixture()?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("journal"), true)?;
    journal.put_exact("plan.json", &record)?;
    let transport = MockTransport::new(false);
    let mut events = Vec::new();
    execute_transactions(&record, &journal, &transport, &mut |event| {
        match &event {
            DeploymentProgress::Submitting(stage) => {
                assert!(
                    journal
                        .exists(&format!("attempt-{:04}.json", stage.number - 1))
                        .unwrap()
                );
                assert!(
                    !journal
                        .exists(&format!("applied-{:04}.json", stage.number - 1))
                        .unwrap()
                );
            }
            DeploymentProgress::Applied { stage, evidence } => {
                let durable: AppliedEvidence = journal
                    .read(&format!("applied-{:04}.json", stage.number - 1))
                    .unwrap();
                assert_eq!(&durable, evidence);
            }
            other => panic!("unexpected initial transaction progress: {other:?}"),
        }
        events.push(event);
        Ok(())
    })?;
    assert_eq!(events.len(), record.transactions.len() * 2);
    for (index, pair) in events.chunks_exact(2).enumerate() {
        let expected = progress::stage(&record, index);
        assert!(matches!(&pair[0], DeploymentProgress::Submitting(stage) if stage == &expected));
        assert!(
            matches!(&pair[1], DeploymentProgress::Applied { stage, evidence } if stage == &expected && evidence.hash == expected.hash)
        );
    }
    Ok(())
}

#[test]
fn ambiguous_or_rejected_progress_never_claims_applied_and_recovery_never_resubmits() -> Result<()>
{
    for failure in ["ambiguous", "rejected", "wrong-finality"] {
        let (_, record) = fixture()?;
        let temporary = tempfile::tempdir()?;
        let journal = Journal::open(&temporary.path().join("journal"), true)?;
        let transport = MockTransport::new(failure == "ambiguous");
        transport.wrong_hash.set(failure == "wrong-finality");
        if failure == "rejected" {
            transport.failure_kind.set(Some("Rejected"));
        }
        let mut events = Vec::new();
        assert!(
            execute_transactions(&record, &journal, &transport, &mut |event| {
                events.push(event);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], DeploymentProgress::Submitting(stage) if stage.hash == record.transactions[0].hash)
        );
        assert!(!journal.exists("applied-0000.json")?);
        if failure == "ambiguous" {
            events.clear();
            execute_transactions(&record, &journal, &transport, &mut |event| {
                events.push(event);
                Ok(())
            })?;
            assert!(
                matches!(&events[0], DeploymentProgress::Recovering(stage) if stage.hash == record.transactions[0].hash)
            );
            assert!(
                matches!(&events[1], DeploymentProgress::Applied { stage, .. } if stage.hash == record.transactions[0].hash)
            );
            assert_eq!(
                transport
                    .submitted
                    .borrow()
                    .iter()
                    .filter(|hash| **hash == record.transactions[0].hash)
                    .count(),
                1
            );
        }
    }
    Ok(())
}

#[test]
fn fee_quote_route_requires_the_exact_full_width_deployment_dataspace() -> Result<()> {
    let (_, record) = fixture()?;
    let mut quote = record.preflight.fee_quotes[0].clone();
    let dataspace = DataSpaceId::new(u64::MAX);
    quote.observation.route_dataspace_id = dataspace;
    native::validate_quote_route(&quote, dataspace)?;
    assert!(native::validate_quote_route(&quote, DataSpaceId::UNIVERSAL).is_err());
    assert!(native::validate_quote_route(&quote, DataSpaceId::new(u64::MAX - 1)).is_err());
    Ok(())
}

#[test]
fn persist_and_execute_refuse_incomplete_plan_publication_before_progress() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config)?;
    let prepared = PreparedDeployment { record };
    let temporary = tempfile::tempdir()?;
    for state in ["empty", "lock-only", "partial-plan"] {
        let path = temporary.path().join(state);
        let directory = iroha_fs::PrivateDirectory::open_or_create(&path)?;
        if state != "empty" {
            directory.open_lock("lock")?;
        }
        if state == "partial-plan" {
            directory.write_atomic(
                "plan.json",
                b"partial original",
                iroha_fs::PublishMode::CreateNew,
            )?;
        }
        let before = directory.entries(4)?;
        assert!(matches!(
            service.persist(&prepared, &path),
            Err(DeploymentError::Journal(_))
        ));
        assert!(matches!(
            service.execute(&prepared, &path, &mut |_| panic!(
                "incomplete persistence cannot dispatch"
            )),
            Err(DeploymentError::Journal(_)),
        ));
        assert_eq!(directory.entries(4)?, before);
        if state == "partial-plan" {
            assert_eq!(
                directory.read("plan.json", 64)?.as_slice(),
                b"partial original"
            );
        }
    }
    Ok(())
}

#[test]
fn service_persistence_reopens_the_same_complete_original_plan() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config)?;
    let prepared = PreparedDeployment { record };
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    service.persist(&prepared, &path)?;
    let original = std::fs::read(path.join("plan.json"))?;
    let lock = std::fs::File::open(path.join("lock"))?;
    let identity = iroha_fs::FileIdentity::of(&lock)?;
    service.persist(&prepared, &path)?;
    assert_eq!(std::fs::read(path.join("plan.json"))?, original);
    assert_eq!(
        iroha_fs::FileIdentity::of(&std::fs::File::open(path.join("lock"))?)?,
        identity
    );
    assert_eq!(
        service.retained_preflight(&path)?.transaction_hashes,
        prepared.preflight().transaction_hashes
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn submitting_callback_lock_replacement_retains_attempt_without_dispatch_or_replay() -> Result<()> {
    let (config, record) = fixture()?;
    validate_plan(&record, &config)?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    let journal = Journal::persist_plan(&path, &record)?;
    let original_plan = std::fs::read(path.join("plan.json"))?;
    let transport = MockTransport::new(false);
    let mut submitting = 0;
    let error = execute_transactions(&record, &journal, &transport, &mut |event| {
        if matches!(event, DeploymentProgress::Submitting(_)) {
            submitting += 1;
            assert_eq!(submitting, 1);
            assert!(path.join("attempt-0000.json").is_file());
            std::fs::rename(path.join("lock"), path.join("retired-lock")).unwrap();
            iroha_fs::PrivateDirectory::open(&path)
                .unwrap()
                .open_lock("lock")
                .unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(error, DeploymentError::Journal(_)));
    assert_eq!(submitting, 1);
    assert!(transport.submitted.borrow().is_empty());
    assert!(transport.waited.borrow().is_empty());
    let original_attempt = std::fs::read(path.join("attempt-0000.json"))?;
    let attempt: TransactionAttempt = norito::json::from_slice(&original_attempt)?;
    assert_eq!(attempt.hash, record.transactions[0].hash);
    assert_eq!(attempt.name, record.transactions[0].name);
    drop(journal);

    // A later owner must honor the retained attempt as uncertain even though this caller
    // observed refusal before submit. Recovery cannot re-sign or dispatch the exact step.
    let reopened = Journal::open(&path, false)?;
    let recovery = MockTransport::new(false);
    recovery.pending.set(true);
    let mut recovering = 0;
    let error = execute_transactions(&record, &reopened, &recovery, &mut |event| {
        assert!(!matches!(event, DeploymentProgress::Submitting(_)));
        if matches!(event, DeploymentProgress::Recovering(_)) {
            recovering += 1;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        matches!(error, DeploymentError::Pending { hash, .. } if hash == record.transactions[0].hash)
    );
    assert_eq!(recovering, 1);
    assert!(recovery.submitted.borrow().is_empty());
    assert_eq!(
        &*recovery.waited.borrow(),
        &[record.transactions[0].hash.clone()]
    );
    assert_eq!(std::fs::read(path.join("plan.json"))?, original_plan);
    assert_eq!(
        std::fs::read(path.join("attempt-0000.json"))?,
        original_attempt
    );
    assert!(!reopened.exists("applied-0000.json")?);
    assert!(!reopened.exists("attempt-0001.json")?);
    Ok(())
}

#[test]
fn fallible_progress_stops_native_work_without_erasing_original_evidence() -> Result<()> {
    let (config, record) = fixture()?;
    let service = DeploymentService::new(config)?;
    let prepared = PreparedDeployment {
        record: record.clone(),
    };
    let temporary = tempfile::tempdir()?;
    for refused in ["prepared", "submitting", "recovering", "applied"] {
        let path = temporary.path().join(refused);
        service.persist(&prepared, &path)?;
        let original_plan = std::fs::read(path.join("plan.json"))?;
        let transport = MockTransport::new(false);
        let mut calls = 0;
        let mut observer = |event: DeploymentProgress| -> DeploymentResult<()> {
            let stop = matches!(
                (refused, event),
                ("prepared", DeploymentProgress::Prepared(_))
                    | ("submitting", DeploymentProgress::Submitting(_))
                    | ("recovering", DeploymentProgress::Recovering(_))
                    | ("applied", DeploymentProgress::Applied { .. })
            );
            if stop {
                calls += 1;
                Err(DeploymentError::Journal(eyre!(
                    "observer refused continued custody"
                )))
            } else {
                Ok(())
            }
        };
        let error = if refused == "prepared" {
            let error = service
                .execute(&prepared, &path, &mut observer)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("observer refused continued custody")
            );
            // The same fallible boundary also applies to the public exact resume API.
            service.resume(&path, &mut observer).unwrap_err()
        } else {
            let journal = Journal::open(&path, false)?;
            if refused == "recovering" {
                journal.put_exact(
                    "attempt-0000.json",
                    &TransactionAttempt {
                        name: record.transactions[0].name.clone(),
                        hash: record.transactions[0].hash.clone(),
                    },
                )?;
            }
            execute_transactions(&record, &journal, &transport, &mut observer).unwrap_err()
        };
        assert!(
            error
                .to_string()
                .contains("observer refused continued custody")
        );
        assert_eq!(calls, if refused == "prepared" { 2 } else { 1 });
        let journal = Journal::open(&path, false)?;
        assert_eq!(std::fs::read(path.join("plan.json"))?, original_plan);
        assert_eq!(journal.exists("attempt-0000.json")?, refused != "prepared");
        assert_eq!(journal.exists("applied-0000.json")?, refused == "applied");
        assert!(!journal.exists("attempt-0001.json")?);
        let expected_dispatches = usize::from(refused == "applied");
        assert_eq!(transport.submitted.borrow().len(), expected_dispatches);
        assert_eq!(transport.waited.borrow().len(), expected_dispatches);
    }
    Ok(())
}
#[test]
fn applied_charge_reporting_never_fails_an_applied_transaction() -> Result<()> {
    // A port with no listener: the transaction-details read fails and reports no charge.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let config = fixture_config_at(&format!("http://127.0.0.1:{port}/"))?;
    let client = Client::new(config)?;
    let hash = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed([7; 32]));
    assert_eq!(read_applied_charge(&client, hash), None);
    Ok(())
}
#[test]
fn applied_evidence_reconciles_by_finality_and_keeps_the_first_charge() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("journal"), true)?;
    let unreported = AppliedEvidence {
        hash: "a".repeat(64),
        terminal_kind: "Applied".to_owned(),
        block_height: 9,
        scope: "global".to_owned(),
        resolved_from: "state".to_owned(),
        charge: None,
    };
    let charged = AppliedEvidence {
        charge: Some(AppliedCharge {
            gas_used: 4_321,
            fee_asset: AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::parse_fully_qualified("wonderland.universal")?,
                "xor".parse()?,
            ),
            fee_amount: iroha_primitives::numeric::Quantity::from(3_u32),
        }),
        ..unreported.clone()
    };
    assert!(charged.same_finality(&unreported));
    assert_ne!(charged, unreported);
    let later_height = AppliedEvidence {
        block_height: 10,
        ..unreported.clone()
    };
    assert!(!later_height.same_finality(&unreported));
    // Nothing retained yet: the read-only reconciliation returns the current observation.
    assert_eq!(
        retained_applied_evidence(&journal, 0, unreported.clone())?,
        unreported
    );
    assert!(!journal.exists("applied-0000.json")?);
    // The first observation is retained; a later one without its charge still recovers it.
    assert_eq!(
        retain_applied_evidence(&journal, 0, charged.clone())?,
        charged
    );
    assert_eq!(
        retain_applied_evidence(&journal, 0, unreported.clone())?,
        charged
    );
    assert_eq!(retained_applied_evidence(&journal, 0, unreported)?, charged);
    assert!(retain_applied_evidence(&journal, 0, later_height).is_err());
    Ok(())
}

#[test]
fn original_review_equality_preserves_quotes_context_and_ordered_signed_hashes() -> Result<()> {
    let (config, original) = fixture()?;
    let (_, alternate) = fixture_with_source(
        "seiyaku Coffee { view fn points(int cups) authorize(anyone) -> int { return cups + 1; } }",
    )?;
    validate_plan(&original, &config)?;
    validate_plan(&alternate, &config)?;
    original
        .preflight
        .require_same_plan(&original.preflight.clone())?;
    assert!(
        alternate
            .preflight
            .require_same_plan(&original.preflight)
            .is_err()
    );
    for field in 0..4 {
        let mut changed = original.preflight.clone();
        match field {
            0 => changed.transaction_hashes.swap(0, 1),
            1 => changed.observed_block_height += 1,
            2 => changed.fee_quotes[0].observation.ledger_time_ms += 1,
            3 => changed.authorization.account_exists = false,
            _ => unreachable!(),
        }
        assert!(matches!(changed.require_same_plan(&original.preflight),
            Err(DeploymentError::InvalidRequest(reason))
            if reason == "retained deployment differs from the original reviewed plan"));
    }
    Ok(())
}

#[test]
fn cancellation_refuses_a_valid_replacement_before_publishing_another_plans_hashes() -> Result<()> {
    let (config, original) = fixture()?;
    let (_, alternate) = fixture_with_source(
        "seiyaku Coffee { view fn points(int cups) authorize(anyone) -> int { return cups + 1; } }",
    )?;
    validate_plan(&original, &config)?;
    validate_plan(&alternate, &config)?;
    assert_eq!(original.preflight.authority, alternate.preflight.authority);
    assert_eq!(
        original.preflight.contract_alias,
        alternate.preflight.contract_alias
    );
    assert_ne!(
        original.preflight.transaction_hashes,
        alternate.preflight.transaction_hashes
    );
    let service = DeploymentService::new(config)?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("original");
    let other = temporary.path().join("alternate");
    service.persist(
        &PreparedDeployment {
            record: original.clone(),
        },
        &path,
    )?;
    service.persist(
        &PreparedDeployment {
            record: alternate.clone(),
        },
        &other,
    )?;
    let expected = service.retained_preflight(&path)?;
    let replacement = std::fs::read(other.join("plan.json"))?;
    std::fs::write(path.join("plan.json"), &replacement)?;
    assert_eq!(
        service.retained_preflight(&path)?.to_json()?,
        alternate.preflight.to_json()?,
        "the substituted plan remains independently authenticated for the same authority"
    );
    assert!(
        matches!(service.cancel(&path, &expected), Err(DeploymentError::InvalidRequest(reason))
        if reason == "retained deployment differs from the original reviewed plan")
    );
    assert!(!path.join("cancelled.json").exists());
    assert_eq!(std::fs::read(path.join("plan.json"))?, replacement);
    assert_eq!(
        std::fs::read_dir(&path)?.count(),
        2,
        "only original lock and replaced plan remain"
    );
    let cancelled = service.cancel(&other, &alternate.preflight)?;
    assert_eq!(
        cancelled.transaction_hashes,
        alternate.preflight.transaction_hashes
    );
    assert_eq!(service.cancel(&other, &alternate.preflight)?, cancelled);
    assert!(!other.join("attempt-0000.json").exists());
    Ok(())
}
