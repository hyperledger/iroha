//! Real runtime recovery over authenticated native signed plans and bounded loopback HTTP.
//! Scripted state responses exercise journal recovery, not live-network qualification.

use super::slot::Publication;
use super::*;
use iroha::{
    crypto::Hash,
    executor_data_model::permission::account::{
        AccountAliasPermissionScope, CanManageAccountAlias,
    },
};
use iroha_contract_deploy::{AppliedEvidence, DeploymentAuthorization};
use iroha_data_model::{
    isi::{
        InstructionBox,
        smart_contract_code::{
            CommitContractDeployment, FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
            SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
        },
    },
    smart_contract::{ContractAddress, ContractArtifactId},
    transaction::{SignedTransaction, TransactionBuilder},
};
use iroha_model_base::{metadata::Metadata, topology::DataSpaceId};
use iroha_primitives::json::Json;
use norito::json::Value;
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Plan {
    journal: PathBuf,
    preflight: DeploymentPreflight,
    transactions: Vec<(String, SignedTransaction)>,
    bytes: Vec<u8>,
    artifact: Vec<u8>,
}

fn plan(runtime: &DeploymentRuntime, nonce: u64) -> Result<Plan> {
    plan_for_alias(runtime, nonce, "ResumeFixture::universal")
}

fn plan_for_alias(runtime: &DeploymentRuntime, nonce: u64, alias: &str) -> Result<Plan> {
    plan_for_source(
        runtime,
        nonce,
        alias,
        "seiyaku ResumeFixture { view fn value() authorize(anyone) -> int { return 1; } }",
    )
}

fn plan_for_source(
    runtime: &DeploymentRuntime,
    nonce: u64,
    alias: &str,
    source: &str,
) -> Result<Plan> {
    let config = &runtime.config;
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .map_err(|error| eyre!(error))?;
    let verified = ivm::verify_contract_artifact(&artifact).map_err(|error| eyre!(error))?;
    let alias: ContractAlias = alias.parse()?;
    let address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        nonce,
        DataSpaceId::UNIVERSAL,
    )?;
    let artifact_id = ContractArtifactId::new(DataSpaceId::UNIVERSAL, verified.code_hash);
    let fee = FeePaymentIntent::authority(Vec::new(), None);
    let mut metadata = Metadata::default();
    for name in ["gov_contract_address", "contract_address"] {
        metadata.insert(name.parse()?, Json::new(address.to_string()));
    }
    let sign = |instructions: Vec<InstructionBox>| -> Result<SignedTransaction> {
        Ok(
            TransactionBuilder::new(config.network_id, config.account.clone(), fee.clone())
                .with_metadata(metadata.clone())
                .with_instructions(instructions)
                .try_sign(config.key_pair.private_key())?,
        )
    };
    let count = artifact.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES);
    let mut transactions = Vec::new();
    for (index, chunk) in artifact.chunks(SMART_CONTRACT_CODE_CHUNK_BYTES).enumerate() {
        let mut instructions = vec![
            UploadSmartContractCodeChunk {
                artifact_id,
                total_size: artifact.len() as u64,
                chunk_index: index as u32,
                chunk_count: count as u32,
                chunk: chunk.to_vec(),
            }
            .into(),
        ];
        let name = if index + 1 == count {
            instructions.push(
                FinalizeSmartContractCodeUpload {
                    artifact_id,
                    total_size: artifact.len() as u64,
                    chunk_count: count as u32,
                }
                .into(),
            );
            "register_bytes_finalize".to_owned()
        } else {
            format!("register_bytes_chunk_{:04}_of_{count:04}", index + 1)
        };
        transactions.push((name, sign(instructions)?));
    }
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        256,
    ));
    let manifest = verified
        .manifest
        .try_signed(&context, 1024 * 1024, &config.key_pair)?;
    transactions.push((
        "register_manifest".to_owned(),
        sign(vec![
            RegisterSmartContractCode {
                artifact_id,
                manifest,
            }
            .into(),
        ])?,
    ));
    transactions.push((
        "commit_deployment".to_owned(),
        sign(vec![
            CommitContractDeployment {
                expected_deploy_nonce: nonce,
                contract_address: address.clone(),
                code_hash: verified.code_hash,
                contract_alias: alias.clone(),
                lease_expiry_ms: None,
                expected_previous_contract_address: None,
            }
            .into(),
        ])?,
    ));
    let quote = norito::json!({
        "intent": fee,
        "observation": {"ledger_time_ms": 1_u64, "next_block_height": 2_u64, "route_dataspace_id": 0_u64},
        "components": [], "capacities": [],
        "decision": {"status": "accepted", "value": {"debit_source": (iroha_data_model::nexus::FeeDebitSource::Account(config.account.clone())), "program_revision": null}}
    });
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
        deploy_nonce: nonce,
        previous_contract_address: None,
        observed_block_height: 1,
        observed_block_hash: Hash::new(b"resume fixture observed block").to_string(),
        fee_quotes: transactions
            .iter()
            .map(|_| norito::json::from_value(quote.clone()))
            .collect::<std::result::Result<_, _>>()?,
        transaction_hashes: transactions
            .iter()
            .map(|(_, tx)| tx.hash().to_string())
            .collect(),
    };
    let records = transactions.iter().map(|(name, tx)| Ok(norito::json!({
        "name": name, "hash": (tx.hash().to_string()), "norito_hex": (hex::encode(tx.encode_wire_v1()?))
    }))).collect::<Result<Vec<_>>>()?;
    let bytes = norito::json::to_vec(&norito::json!({
        "version": 1_u8, "preflight": preflight, "artifact_hex": (hex::encode(&artifact)),
        "requested_fee": fee, "transactions": records,
    }))?;
    let slot = deployment_slot(config, &runtime.journal_root, &preflight.contract_alias);
    let session = DeploymentSlot::open(&slot)?;
    let directory = session.writer.create_child(&plan_journal_id(&preflight)?)?;
    drop(directory.open_lock("lock")?);
    directory.write_atomic("plan.json", &bytes, PublishMode::CreateNew)?;
    let journal = directory.path().to_owned();
    // This is the genuine native authentication boundary, not a mocked preflight.
    let retained = DeploymentService::new(config.clone())?.retained_preflight(&journal)?;
    assert_eq!(retained.transaction_hashes, preflight.transaction_hashes);
    Ok(Plan {
        journal,
        preflight,
        transactions,
        bytes,
        artifact,
    })
}

fn complete(plan: &Plan) -> Result<DeploymentReceipt> {
    let _profile = ChainDiscriminantGuard::enter(plan.preflight.chain_discriminant);
    let directory = PrivateDirectory::open(&plan.journal)?;
    let stages: Vec<_> = plan
        .transactions
        .iter()
        .map(|(_, tx)| AppliedEvidence {
            hash: tx.hash().to_string(),
            terminal_kind: "Applied".into(),
            block_height: 2,
            scope: "global".into(),
            resolved_from: "state".into(),
            charge: None,
        })
        .collect();
    for (index, ((name, tx), evidence)) in plan.transactions.iter().zip(&stages).enumerate() {
        directory.write_atomic(
            &format!("attempt-{index:04}.json"),
            &norito::json::to_vec(&norito::json!({"name": name, "hash": (tx.hash().to_string())}))?,
            PublishMode::CreateNew,
        )?;
        directory.write_atomic(
            &format!("applied-{index:04}.json"),
            &norito::json::to_vec(evidence)?,
            PublishMode::CreateNew,
        )?;
    }
    let p = &plan.preflight;
    let receipt = DeploymentReceipt {
        version: 1,
        network_id: p.network_id,
        chain_id: p.chain_id.clone(),
        chain_discriminant: p.chain_discriminant,
        authority: p.authority.clone(),
        contract_alias: p.contract_alias.clone(),
        contract_address: p.contract_address.clone(),
        contract_subject_account: p.contract_address.subject_id(),
        dataspace_id: p.dataspace_id,
        code_hash: p.code_hash,
        abi_hash: p.abi_hash,
        commit: stages.last().unwrap().clone(),
        stages,
        readback_block_height: 2,
        readback_block_hash: Hash::new(b"resume fixture readback block").to_string(),
        stored_artifact_matches: true,
    };
    directory.write_atomic(
        iroha_contract_deploy::RECEIPT_FILE_NAME,
        &norito::json::to_vec(&receipt)?,
        PublishMode::CreateNew,
    )?;
    Ok(receipt)
}

fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        eyre::ensure!(headers.len() <= 64 * 1024, "bounded fixture headers");
    }
    let headers = String::from_utf8(headers)?;
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()?
        .unwrap_or(0);
    eyre::ensure!(length <= 2 * 1024 * 1024, "bounded fixture body");
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok((headers.lines().next().unwrap().to_owned(), body))
}

struct Http {
    origin: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    handle: Option<thread::JoinHandle<Result<()>>>,
}
impl Http {
    fn new(applied: Option<AppliedEvidence>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}/", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::clone(&stop);
        let observed = Arc::clone(&requests);
        let handle = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !stopped.load(Ordering::Acquire) {
                eyre::ensure!(Instant::now() < deadline, "fixture lifetime deadline");
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                let (head, body) = read_request(&mut stream)?;
                let response = if head.starts_with("GET /v1/node/capabilities ") {
                    Some(
                        norito::json!({"data_model_version": (iroha_data_model::DATA_MODEL_VERSION), "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))}),
                    )
                } else if head.starts_with("GET /v1/pipeline/transactions/status?") {
                    applied.as_ref().map(|evidence| {
                        norito::json!({
                            "hash": (evidence.hash), "scope": "global", "resolved_from": "state",
                            "status": {"kind": "Applied", "block_height": 2_u64}
                        })
                    })
                } else {
                    None
                };
                observed.lock().unwrap().push((head, body));
                let status = if response.is_some() {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                let response = norito::json::to_vec(&response.unwrap_or(Value::Null))?;
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )?;
                stream.write_all(&response)?;
            }
            Ok(())
        });
        Ok(Self {
            origin,
            stop,
            requests,
            handle: Some(handle),
        })
    }
    fn finish(mut self) -> Result<Vec<(String, Vec<u8>)>> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .unwrap()
            .join()
            .map_err(|_| eyre!("fixture panicked"))??;
        Ok(self.requests.lock().unwrap().clone())
    }
}
impl Drop for Http {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn runtime(root: &Path, origin: &str) -> DeploymentRuntime {
    let mut config = super::tests::config();
    config.torii_api_url = origin.parse().unwrap();
    // The serial loopback fixture always answers; a generous per-request bound keeps the
    // capability probe and read-only evidence queries from timing out under parallel test load.
    // Status polling keeps its short bound so non-Applied fixtures finish quickly.
    config.torii_request_timeout = Duration::from_secs(5);
    config.transaction_status_timeout = Duration::from_millis(500);
    DeploymentRuntime::new(config, root.join("journals"), root.join("cache"))
}
fn active(runtime: &DeploymentRuntime, plan: &Plan) -> Result<DeploymentSlot> {
    DeploymentSlot::open(&deployment_slot(
        &runtime.config,
        &runtime.journal_root,
        &plan.preflight.contract_alias,
    ))
}

#[test]
fn resume_completes_preparing_before_original_dispatch_and_retry_never_resubmits() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let plan = plan(&runtime, 7)?;
    let slot = active(&runtime, &plan)?;
    assert!(slot.current_journal()?.is_none());
    slot.write_state(&Publication::Preparing {
        candidate: plan_journal_id(&plan.preflight)?,
        previous: None,
    })?;
    drop(slot);
    let mut submitting = 0;
    let error = runtime
        .resume(&plan.journal, &mut |_| Ok(()), &mut |event| {
            let state: Publication = norito::json::from_slice(
                &PrivateDirectory::open(plan.journal.parent().unwrap())
                    .unwrap()
                    .read("publication.json", 1024)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                state,
                Publication::Active {
                    journal: plan_journal_id(&plan.preflight).unwrap()
                }
            );
            assert!(
                active(&runtime, &plan).is_err(),
                "original alias slot remains locked"
            );
            if matches!(event, DeploymentProgress::Submitting(_)) {
                submitting += 1;
            }
        })
        .err()
        .expect("scripted submission stays unresolved");
    assert!(
        matches!(
            error.downcast_ref::<DeploymentError>(),
            Some(DeploymentError::Pending { .. })
        ),
        "{error:#}"
    );
    assert_eq!(submitting, 1);
    assert!(plan.journal.join("attempt-0000.json").is_file());
    let mut recovering = 0;
    let error = runtime
        .resume(&plan.journal, &mut |_| Ok(()), &mut |event| {
            assert!(
                !matches!(event, DeploymentProgress::Submitting(_)),
                "attempted original must not be replayed"
            );
            if matches!(event, DeploymentProgress::Recovering(_)) {
                recovering += 1;
            }
        })
        .err()
        .expect("exact original hash remains unresolved");
    assert!(
        matches!(
            error.downcast_ref::<DeploymentError>(),
            Some(DeploymentError::Pending { .. })
        ),
        "{error:#}"
    );
    assert_eq!(recovering, 1);
    assert_eq!(
        active(&runtime, &plan)?.current_journal()?,
        Some(plan.journal.clone())
    );
    assert_eq!(std::fs::read(plan.journal.join("plan.json"))?, plan.bytes);
    let requests = http.finish()?;
    let wire = plan.transactions[0].1.encode_wire_v1()?;
    assert_eq!(
        requests.iter().filter(|(_, body)| body == &wire).count(),
        1,
        "exact original signed bytes dispatched once"
    );
    assert!(
        requests
            .iter()
            .any(|(head, _)| head.starts_with("GET /v1/pipeline/transactions/status?"))
    );
    Ok(())
}

#[test]
fn resume_refuses_conflicting_active_pending_or_terminal_journal_before_dispatch() -> Result<()> {
    for completed in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let requested = plan(&runtime, 7)?;
        let successor = plan(&runtime, 8)?;
        if completed {
            complete(&successor)?;
        }
        let slot = active(&runtime, &successor)?;
        slot.write_state(&Publication::Active {
            journal: plan_journal_id(&successor.preflight)?,
        })?;
        drop(slot);
        let error = runtime
            .resume(&requested.journal, &mut |_| Ok(()), &mut |_| {
                panic!("conflicting unfinished plan reached execution")
            })
            .err()
            .expect("different active plan must block old unfinished recovery");
        assert!(
            error.to_string().contains("another deployment is active"),
            "{error:#}"
        );
        assert_eq!(
            active(&runtime, &successor)?.current_journal()?,
            Some(successor.journal)
        );
        assert!(!requested.journal.join("attempt-0000.json").exists());
        assert!(http.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn completed_historical_resume_keeps_newer_active_pointer_and_never_dispatches() -> Result<()> {
    for preparing in [false, true] {
        let temporary = tempfile::tempdir()?;
        let offline = runtime(temporary.path(), "http://127.0.0.1:9/");
        let original = plan_for_source(
            &offline,
            7,
            "ResumeFixture::universal",
            "seiyaku ResumeFixture { state int stored; 始まり(int start) { stored = start; } view fn value() authorize(anyone) -> int { return stored; } }",
        )?;
        let receipt = complete(&original)?;
        let successor = plan(&offline, 8)?;
        complete(&successor)?;
        let slot = active(&offline, &successor)?;
        let publication = if preparing {
            Publication::Preparing {
                candidate: plan_journal_id(&successor.preflight)?,
                previous: Some(plan_journal_id(&original.preflight)?),
            }
        } else {
            Publication::Active {
                journal: plan_journal_id(&successor.preflight)?,
            }
        };
        slot.write_state(&publication)?;
        drop(slot);
        let http = Http::new(Some(receipt.commit.clone()))?;
        let runtime = runtime(temporary.path(), &http.origin);
        let recovered = runtime.resume(&original.journal, &mut |_| Ok(()), &mut |_| {
            panic!("historical completion entered mutable service")
        })?;
        assert_eq!(recovered.receipt.to_json()?, receipt.to_json()?);
        assert_eq!(
            recovered.lifecycle,
            Some(
                LifecycleHook {
                    name: "hajimari".into(),
                    params: vec![iroha_contract_deploy::LifecycleParameter {
                        name: "start".into(),
                        type_name: "int".into()
                    }],
                }
                .guidance(true)
            )
        );
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            original.bytes
        );
        assert_eq!(recovered.receipt.commit, receipt.commit);
        assert_eq!(recovered.journal, original.journal);
        assert_eq!(active(&runtime, &successor)?.read_state()?, publication);
        let requests = http.finish()?;
        assert!(
            requests
                .iter()
                .any(|(head, _)| head.starts_with("GET /v1/pipeline/transactions/status?"))
        );
        // Only reads: status polls and the signed, read-only transaction-details query that
        // reports the settled gas and fee. Nothing is submitted.
        assert!(requests.iter().all(|(head, _)| {
            head.starts_with("GET ") || head.starts_with("POST /v1/pipeline/transactions/details ")
        }));
    }
    Ok(())
}

#[test]
fn resume_review_refusal_leaves_active_original_plan_untouched() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let plan = plan(&runtime, 7)?;
    active(&runtime, &plan)?.write_state(&Publication::Active {
        journal: plan_journal_id(&plan.preflight)?,
    })?;
    let error = runtime
        .resume(
            &plan.journal,
            &mut |_| bail!("fee review refused"),
            &mut |_| panic!("refused review entered execution"),
        )
        .err()
        .expect("review must refuse");
    assert!(error.to_string().contains("fee review refused"));
    assert_eq!(
        active(&runtime, &plan)?.current_journal()?,
        Some(plan.journal.clone())
    );
    assert!(!plan.journal.join("attempt-0000.json").exists());
    assert_eq!(std::fs::read(plan.journal.join("plan.json"))?, plan.bytes);
    assert!(http.finish()?.is_empty());
    Ok(())
}

#[test]
fn ordinary_deploy_reconciles_saved_replacement_instead_of_preparing_another_paid_plan()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let previous = plan(&runtime, 6)?;
    complete(&previous)?;
    let candidate = plan(&runtime, 7)?;
    let slot = active(&runtime, &candidate)?;
    slot.write_state(&Publication::Preparing {
        candidate: plan_journal_id(&candidate.preflight)?,
        previous: Some(plan_journal_id(&previous.preflight)?),
    })?;
    drop(slot);
    let mut original_reviewed = false;
    let error = runtime
        .deploy_artifact(
            BuiltArtifact::from_bytes(candidate.artifact.clone())?,
            &AliasSelection::Exact(candidate.preflight.contract_alias.clone()),
            FeePaymentIntent::authority(Vec::new(), None),
            &mut |retained| {
                assert_eq!(
                    retained.transaction_hashes,
                    candidate.preflight.transaction_hashes
                );
                original_reviewed = true;
                Ok(())
            },
            &mut |_| {},
        )
        .err()
        .expect("original candidate remains pending after the scripted unavailable response");
    assert!(
        matches!(
            error.downcast_ref::<DeploymentError>(),
            Some(DeploymentError::Pending { .. })
        ),
        "{error:#}"
    );
    assert!(original_reviewed);
    assert_eq!(
        active(&runtime, &candidate)?.current_journal()?,
        Some(candidate.journal.clone())
    );
    assert_eq!(
        std::fs::read(candidate.journal.join("plan.json"))?,
        candidate.bytes
    );
    assert_eq!(
        std::fs::read(previous.journal.join("plan.json"))?,
        previous.bytes
    );
    let requests = http.finish()?;
    let wire = candidate.transactions[0].1.encode_wire_v1()?;
    assert_eq!(requests.iter().filter(|(_, body)| body == &wire).count(), 1);
    assert!(
        requests
            .iter()
            .all(|(head, body)| head.starts_with("GET /v1/node/capabilities ") || body == &wire),
        "no replacement preflight, quotes, or other signed transaction"
    );
    Ok(())
}

#[test]
fn absent_preparing_candidate_restores_exact_predecessor_without_creating_a_journal() -> Result<()>
{
    for with_previous in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let previous = plan(&runtime, 6)?;
        let slot = active(&runtime, &previous)?;
        let missing = hex::encode(Hash::new(b"never published candidate").as_ref());
        let missing_path = slot.writer.path().join(&missing);
        slot.write_state(&Publication::Preparing {
            candidate: missing,
            previous: with_previous.then(|| plan_journal_id(&previous.preflight).unwrap()),
        })?;
        drop(slot);
        let error = runtime
            .resume(
                &missing_path,
                &mut |_| panic!("absent candidate cannot reach review"),
                &mut |_| panic!("absent candidate cannot dispatch"),
            )
            .err()
            .expect("no original signed plan exists to resume");
        assert!(error.to_string().contains("never published"), "{error:#}");
        assert_eq!(
            active(&runtime, &previous)?.current_journal()?,
            with_previous.then(|| previous.journal.clone())
        );
        assert!(!missing_path.exists());
        assert_eq!(
            std::fs::read(previous.journal.join("plan.json"))?,
            previous.bytes
        );
        assert!(http.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn partial_or_malformed_preparing_candidate_refuses_resume_and_fresh_deploy_without_erasing_evidence()
-> Result<()> {
    for malformed in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let original = plan(&runtime, 6)?;
        let slot = active(&runtime, &original)?;
        let candidate = hex::encode(Hash::new(b"partial original candidate").as_ref());
        let partial = slot.writer.create_child(&candidate)?;
        if malformed {
            drop(partial.open_lock("lock")?);
            partial.write_atomic("plan.json", b"{truncated", PublishMode::CreateNew)?;
        } else {
            partial.write_atomic("sentinel", b"unclassified original", PublishMode::CreateNew)?;
        }
        let state = Publication::Preparing {
            candidate,
            previous: Some(plan_journal_id(&original.preflight)?),
        };
        slot.write_state(&state)?;
        drop(slot);
        assert!(
            runtime
                .resume(
                    partial.path(),
                    &mut |_| panic!("partial plan reached review"),
                    &mut |_| panic!("partial plan reached execution")
                )
                .is_err()
        );
        assert!(
            runtime
                .deploy_artifact(
                    BuiltArtifact::from_bytes(original.artifact.clone())?,
                    &AliasSelection::Exact(original.preflight.contract_alias.clone()),
                    FeePaymentIntent::authority(Vec::new(), None),
                    &mut |_| panic!("partial candidate was skipped for fresh review"),
                    &mut |_| panic!("partial candidate was skipped for fresh dispatch"),
                )
                .is_err()
        );
        assert_eq!(active(&runtime, &original)?.read_state()?, state);
        assert!(!partial.path().join("attempt-0000.json").exists());
        if malformed {
            assert_eq!(partial.read("plan.json", 64)?.as_slice(), b"{truncated");
        } else {
            assert_eq!(
                partial.read("sentinel", 64)?.as_slice(),
                b"unclassified original"
            );
        }
        assert!(http.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn missing_or_retired_slot_state_is_never_recreated() -> Result<()> {
    for legacy in [false, true] {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("private/slot");
        let directory = PrivateDirectory::open_or_create(&path)?;
        drop(directory.open_lock("deployment.lock")?);
        if legacy {
            directory.write_atomic(
                "active-journal",
                hex::encode(Hash::new(b"retired pointer").as_ref()).as_bytes(),
                PublishMode::CreateNew,
            )?;
        }
        let error = DeploymentSlot::open(&path)
            .err()
            .expect("incomplete or retired publication must be refused");
        if legacy {
            assert!(
                error
                    .to_string()
                    .contains("retired deployment active-journal")
            );
        } else {
            assert!(matches!(
                error.downcast_ref::<std::io::Error>(),
                Some(error) if error.kind() == std::io::ErrorKind::NotFound
            ));
        }
        assert!(!path.join("publication.json").exists());
        assert_eq!(directory.entries(4)?.len(), if legacy { 2 } else { 1 });
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn replaced_slot_lock_refuses_original_owner_reads_writes_and_dispatch() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let original = plan(&runtime, 7)?;
    let slot = active(&runtime, &original)?;
    let state = Publication::Active {
        journal: plan_journal_id(&original.preflight)?,
    };
    slot.write_state(&state)?;
    let path = slot.writer.path();
    std::fs::rename(path.join("deployment.lock"), path.join("original.lock"))?;
    drop(slot.writer.open_lock("deployment.lock")?);
    assert!(slot.current_journal().is_err());
    assert!(slot.write_state(&Publication::Empty).is_err());
    assert!(
        slot.resume(
            &DeploymentService::new(runtime.config.clone())?,
            &original.journal,
            &original.preflight,
            &mut |_| panic!("replaced lock admitted dispatch")
        )
        .is_err()
    );
    let bytes = slot.writer.read("publication.json", 1024)?;
    assert_eq!(norito::json::from_slice::<Publication>(&bytes)?, state);
    assert!(http.finish()?.is_empty());
    Ok(())
}

#[test]
fn genuine_same_authority_plan_in_wrong_alias_slot_cannot_promote_preparing() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let original = plan(&runtime, 6)?;
    let foreign = plan_for_alias(&runtime, 7, "OtherAlias::universal")?;
    let slot = active(&runtime, &original)?;
    let id = plan_journal_id(&foreign.preflight)?;
    let copied = slot
        .writer
        .publish_private_child(&id, &[("lock", b""), ("plan.json", &foreign.bytes)])?;
    let missing = hex::encode(Hash::new(b"absent replacement candidate").as_ref());
    let states = [
        Publication::Preparing {
            candidate: id.clone(),
            previous: Some(plan_journal_id(&original.preflight)?),
        },
        Publication::Preparing {
            candidate: missing.clone(),
            previous: Some(id.clone()),
        },
        Publication::Active { journal: id },
    ];
    drop(slot);
    // This signed plan is valid for this network and account; exact alias-slot custody must
    // still refuse candidate promotion, predecessor restoration, and existing Active reads.
    DeploymentService::new(runtime.config.clone())?.retained_preflight(copied.path())?;
    for state in states {
        active(&runtime, &original)?.write_state(&state)?;
        let requested = match &state {
            Publication::Preparing { candidate, .. } => {
                original.journal.parent().unwrap().join(candidate)
            }
            _ => copied.path().to_owned(),
        };
        assert!(
            runtime
                .resume(
                    &requested,
                    &mut |_| panic!("foreign alias reached review"),
                    &mut |_| panic!("foreign alias reached dispatch")
                )
                .is_err()
        );
        assert_eq!(active(&runtime, &original)?.read_state()?, state);
        assert!(
            runtime
                .deploy_artifact(
                    BuiltArtifact::from_bytes(original.artifact.clone())?,
                    &AliasSelection::Exact(original.preflight.contract_alias.clone()),
                    FeePaymentIntent::authority(Vec::new(), None),
                    &mut |_| panic!("foreign alias reached fresh review"),
                    &mut |_| panic!("foreign alias reached fresh dispatch"),
                )
                .is_err()
        );
        assert_eq!(active(&runtime, &original)?.read_state()?, state);
    }
    assert!(!copied.path().join("attempt-0000.json").exists());
    assert!(http.finish()?.is_empty());
    Ok(())
}

#[test]
fn cancellation_requires_exact_active_admission_and_preserves_other_publication_states()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let http = Http::new(None)?;
    let runtime = runtime(temporary.path(), &http.origin);
    let requested = plan(&runtime, 7)?;
    let candidate = plan(&runtime, 8)?;
    let requested_id = plan_journal_id(&requested.preflight)?;
    let candidate_id = plan_journal_id(&candidate.preflight)?;
    let service = DeploymentService::new(runtime.config.clone())?;
    let slot = active(&runtime, &requested)?;
    for state in [
        Publication::Empty,
        Publication::Active {
            journal: candidate_id.clone(),
        },
        Publication::Preparing {
            candidate: candidate_id,
            previous: Some(requested_id.clone()),
        },
    ] {
        slot.write_state(&state)?;
        assert!(slot.cancel(&service, &requested.journal).is_err());
        assert_eq!(slot.read_state()?, state);
        assert!(!requested.journal.join("cancelled.json").exists());
    }
    slot.write_state(&Publication::Active {
        journal: requested_id,
    })?;
    let cancellation = slot.cancel(&service, &requested.journal)?;
    assert_eq!(
        cancellation.transaction_hashes,
        requested.preflight.transaction_hashes
    );
    assert_eq!(slot.current_journal()?, Some(requested.journal));
    assert!(http.finish()?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn same_inode_lock_mutation_refuses_original_slot_owner() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let slot = DeploymentSlot::open(&temporary.path().join("private/slot"))?;
    slot.writer
        .open_existing_lock("deployment.lock")?
        .write_all(b"changed original lock")?;
    assert!(slot.current_journal().is_err());
    assert!(slot.write_state(&Publication::Empty).is_err());
    Ok(())
}

#[cfg(windows)]
#[test]
fn held_slot_lock_refuses_windows_rename() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let slot = DeploymentSlot::open(&temporary.path().join("private/slot"))?;
    assert!(
        std::fs::rename(
            slot.writer.path().join("deployment.lock"),
            slot.writer.path().join("retired-lock")
        )
        .is_err()
    );
    assert!(slot.current_journal()?.is_none());
    Ok(())
}

/// Exercise the package command's production fresh consumer with a real native saved plan.
pub(crate) fn assert_package_fresh_retry_preserves_original(
    run: impl Fn(
        &DeploymentService,
        &DeploymentSlot,
        DeploymentRequest,
        bool,
        &mut dyn FnMut(&str),
    ) -> Result<RetainedDeployment>,
) -> Result<()> {
    for preparing in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let mut original = plan(&runtime, 7)?;
        let package_slot = temporary
            .path()
            .join("target/deploy/test")
            .join(blake3::hash(b"demo/resume::resume").to_hex().as_str());
        let session =
            DeploymentSlot::open_package(&package_slot, original.preflight.contract_alias.clone())?;
        let id = plan_journal_id(&original.preflight)?;
        let directory = session
            .writer
            .publish_private_child(&id, &[("lock", b""), ("plan.json", &original.bytes)])?;
        original.journal = directory.path().to_owned();
        session.write_state(&if preparing {
            Publication::Preparing {
                candidate: id.clone(),
                previous: None,
            }
        } else {
            Publication::Active {
                journal: id.clone(),
            }
        })?;
        drop(session);
        let service = DeploymentService::new(runtime.config.clone())?;
        let request = || DeploymentRequest {
            artifact: original.artifact.clone(),
            alias: original.preflight.contract_alias.clone(),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            governance_approvers: Vec::new(),
        };
        let session = DeploymentSlot::open_package_read(
            &package_slot,
            original.preflight.contract_alias.clone(),
        )?;
        let prepared = run(&service, &session, request(), true, &mut |_| {
            panic!("prepare-only retry dispatched")
        })?;
        assert!(prepared.receipt.is_none());
        assert!(!prepared.completed_earlier);
        assert_eq!(prepared.journal, original.journal);
        assert_eq!(
            prepared.preflight.transaction_hashes,
            original.preflight.transaction_hashes
        );
        assert_eq!(
            session.read_state()?,
            Publication::Active {
                journal: id.clone()
            }
        );
        assert!(!original.journal.join("attempt-0000.json").exists());
        assert!(
            http.requests
                .lock()
                .unwrap()
                .iter()
                .all(|(head, _)| head.starts_with("GET /v1/node/capabilities ")),
            "prepare-only retry must not quote, sign, or submit another plan"
        );
        drop(session);
        let session = DeploymentSlot::open_package_read(
            &package_slot,
            original.preflight.contract_alias.clone(),
        )?;
        let mut submitting = 0;
        let error = run(&service, &session, request(), false, &mut |event| {
            assert!(
                DeploymentSlot::open_package_read(
                    &package_slot,
                    original.preflight.contract_alias.clone()
                )
                .is_err(),
                "fresh retry retains the original slot lock"
            );
            if event.contains("submitting") {
                submitting += 1;
            }
        })
        .err()
        .expect("scripted submission remains pending");
        assert!(
            matches!(
                error.downcast_ref::<DeploymentError>(),
                Some(DeploymentError::Pending { .. })
            ),
            "{error:#}"
        );
        assert_eq!(submitting, 1);
        drop(session);
        let session = DeploymentSlot::open_package_read(
            &package_slot,
            original.preflight.contract_alias.clone(),
        )?;
        let mut recovering = 0;
        let error = run(&service, &session, request(), false, &mut |event| {
            assert!(
                !event.contains("submitting"),
                "attempted original must not be replayed"
            );
            if event.contains("recovering") {
                recovering += 1;
            }
        })
        .err()
        .expect("original exact hash remains pending");
        assert!(
            matches!(
                error.downcast_ref::<DeploymentError>(),
                Some(DeploymentError::Pending { .. })
            ),
            "{error:#}"
        );
        assert_eq!(recovering, 1);
        assert_eq!(session.current_journal()?, Some(original.journal.clone()));
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            original.bytes
        );
        assert_eq!(
            std::fs::read_dir(&package_slot)?.count(),
            3,
            "no replacement plan may be prepared"
        );
        let requests = http.finish()?;
        let wire = original.transactions[0].1.encode_wire_v1()?;
        assert_eq!(requests.iter().filter(|(_, body)| body == &wire).count(), 1);
        assert!(
            requests.iter().all(|(head, body)| {
                head.starts_with("GET /v1/node/capabilities ")
                    || head.starts_with("GET /v1/pipeline/transactions/status?")
                    || body == &wire
            }),
            "fresh retry must not issue new preflight, quote, or replacement submission requests"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn changed_slot_lock_during_submitting_refuses_http_dispatch() -> Result<()> {
    for replace_name in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let original = plan(&runtime, 7)?;
        active(&runtime, &original)?.write_state(&Publication::Active {
            journal: plan_journal_id(&original.preflight)?,
        })?;
        let slot_path = original.journal.parent().unwrap();
        let mut submitting = 0;
        let error = runtime
            .resume(&original.journal, &mut |_| Ok(()), &mut |event| {
                if matches!(event, DeploymentProgress::Submitting(_)) {
                    submitting += 1;
                    let directory = PrivateDirectory::open(slot_path).unwrap();
                    if replace_name {
                        std::fs::rename(
                            slot_path.join("deployment.lock"),
                            slot_path.join("retired-lock"),
                        )
                        .unwrap();
                        drop(directory.open_lock("deployment.lock").unwrap());
                    } else {
                        directory
                            .open_existing_lock("deployment.lock")
                            .unwrap()
                            .write_all(b"changed during progress")
                            .unwrap();
                    }
                }
            })
            .err()
            .expect("changed original slot lock must refuse dispatch");
        assert_eq!(submitting, 1);
        assert!(
            format!("{error:#}").contains("slot lock changed"),
            "{error:#}"
        );
        assert!(
            original.journal.join("attempt-0000.json").exists(),
            "retain conservative exact-hash recovery marker"
        );
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            original.bytes
        );
        let requests = http.finish()?;
        assert!(
            requests.iter().all(
                |(head, body)| head.starts_with("GET /v1/node/capabilities ") && body.is_empty()
            ),
            "ownership loss must prevent signed HTTP dispatch"
        );
    }
    Ok(())
}

/// Replace only retained content, preserving the genuine original directory and child lock.
fn replace_retained_plan(source: &Path, destination: &Path) -> Result<()> {
    let source = PrivateDirectory::open(source)?;
    let destination = PrivateDirectory::open(destination)?;
    for name in source.entries(64)? {
        if name == "lock" {
            continue;
        }
        let bytes = source.read(&name, 32 * 1024 * 1024)?;
        destination.write_atomic(&name, &bytes, PublishMode::Replace)?;
    }
    Ok(())
}

fn assert_review_binding_error<T>(result: iroha_contract_deploy::DeploymentResult<T>) {
    assert!(
        matches!(result, Err(DeploymentError::InvalidRequest(reason))
        if reason == "retained deployment differs from the original reviewed plan")
    );
}

#[test]
fn retry_review_rejects_valid_completed_replacement_without_inspection() -> Result<()> {
    for different_artifact in [false, true] {
        let temporary = tempfile::tempdir()?;
        let offline = runtime(temporary.path(), "http://127.0.0.1:9/");
        let original = plan_for_source(
            &offline,
            7,
            "ResumeFixture::universal",
            "seiyaku ResumeFixture { state int stored; hajimari(int start) { stored = start; } view fn value() authorize(anyone) -> int { return stored; } }",
        )?;
        let alternate = if different_artifact {
            plan(&offline, 8)?
        } else {
            plan_for_source(
                &offline,
                8,
                "ResumeFixture::universal",
                "seiyaku ResumeFixture { state int stored; hajimari(int start) { stored = start; } view fn value() authorize(anyone) -> int { return stored; } }",
            )?
        };
        let original_receipt = complete(&original)?;
        let alternate_receipt = complete(&alternate)?;
        assert_eq!(original.preflight.authority, alternate.preflight.authority);
        assert_eq!(
            original.preflight.contract_alias,
            alternate.preflight.contract_alias
        );
        assert_eq!(
            original.preflight.code_hash != alternate.preflight.code_hash,
            different_artifact
        );
        assert_ne!(original_receipt.commit.hash, alternate_receipt.commit.hash);
        let state = Publication::Active {
            journal: plan_journal_id(&original.preflight)?,
        };
        active(&offline, &original)?.write_state(&state)?;
        let http = Http::new(Some(alternate_receipt.commit.clone()))?;
        let runtime = runtime(temporary.path(), &http.origin);
        let service = DeploymentService::new(runtime.config.clone())?;
        assert_eq!(
            service
                .completed_receipt(&alternate.journal, &alternate.preflight)?
                .unwrap()
                .to_json()?,
            alternate_receipt.to_json()?,
            "alternate signed plan and complete retained evidence authenticate independently",
        );
        http.requests.lock().unwrap().clear();
        let mut reviews = 0;
        let error = runtime
            .deploy_artifact(
                BuiltArtifact::from_bytes(original.artifact.clone())?,
                &AliasSelection::Exact(original.preflight.contract_alias.clone()),
                FeePaymentIntent::authority(Vec::new(), None),
                &mut |reviewed| {
                    reviews += 1;
                    assert_eq!(reviewed.to_json()?, original.preflight.to_json()?);
                    assert!(
                        active(&runtime, &original).is_err(),
                        "original slot stays locked"
                    );
                    replace_retained_plan(&alternate.journal, &original.journal)
                },
                &mut |_| panic!("substituted retry reached progress"),
            )
            .err()
            .expect("valid replacement must not become the reviewed deployment");
        assert_eq!(reviews, 1);
        assert!(
            error
                .to_string()
                .contains("deployment journal differs from its authenticated slot and commit"),
            "{error:#}"
        );
        assert_eq!(active(&runtime, &original)?.read_state()?, state);
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            alternate.bytes
        );
        assert_eq!(
            std::fs::read(original.journal.join("receipt.json"))?,
            std::fs::read(alternate.journal.join("receipt.json"))?
        );
        assert_eq!(
            std::fs::read_dir(original.journal.parent().unwrap())?.count(),
            4,
            "two original journal directories and the unchanged slot files only"
        );
        assert!(
            http.finish()?.is_empty(),
            "refusal precedes status reads, signing and submission"
        );
    }
    Ok(())
}

#[test]
fn retry_prepare_only_rechecks_review_but_preserves_callback_refusal() -> Result<()> {
    for accept in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let original = plan(&runtime, 7)?;
        let alternate = plan(&runtime, 8)?;
        let slot = active(&runtime, &original)?;
        let state = Publication::Active {
            journal: plan_journal_id(&original.preflight)?,
        };
        slot.write_state(&state)?;
        let service = DeploymentService::new(runtime.config.clone())?;
        let fee = FeePaymentIntent::authority(Vec::new(), None);
        let mut reviews = 0;
        let error = slot
            .recover_matching(
                &service,
                slot::RetryRequest {
                    code_hash: original.preflight.code_hash,
                    alias: &original.preflight.contract_alias,
                    fee_payment: &fee,
                    prepare_only: true,
                },
                &mut |_| {
                    reviews += 1;
                    replace_retained_plan(&alternate.journal, &original.journal)?;
                    if accept {
                        Ok(())
                    } else {
                        bail!("original review refusal")
                    }
                },
                &mut |_| panic!("prepare-only retry reached progress"),
            )
            .err()
            .expect("prepare-only must not return a substituted plan");
        assert_eq!(reviews, 1);
        assert!(
            error.to_string().contains(if accept {
                "deployment journal differs from its authenticated slot and commit"
            } else {
                "original review refusal"
            }),
            "{error:#}"
        );
        assert_eq!(slot.read_state()?, state);
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            alternate.bytes
        );
        assert!(!original.journal.join("attempt-0000.json").exists());
        assert!(http.finish()?.is_empty());
    }
    Ok(())
}

#[test]
fn fresh_inspection_and_receipt_reads_reject_a_valid_replacement_before_effects() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let offline = runtime(temporary.path(), "http://127.0.0.1:9/");
    let original = plan(&offline, 7)?;
    let alternate = plan(&offline, 8)?;
    complete(&original)?;
    let alternate_receipt = complete(&alternate)?;
    let http = Http::new(Some(alternate_receipt.commit.clone()))?;
    let runtime = runtime(temporary.path(), &http.origin);
    let service = DeploymentService::new(runtime.config.clone())?;
    let expected = service.retained_preflight(&original.journal)?;
    assert_eq!(
        service
            .completed_receipt(&alternate.journal, &alternate.preflight)?
            .unwrap()
            .to_json()?,
        alternate_receipt.to_json()?
    );
    http.requests.lock().unwrap().clear();
    replace_retained_plan(&alternate.journal, &original.journal)?;
    assert_eq!(
        service.retained_preflight(&original.journal)?.to_json()?,
        alternate.preflight.to_json()?,
        "replacement remains fully authenticated for this same authority"
    );
    let before = std::fs::read(original.journal.join("receipt.json"))?;
    assert_review_binding_error(service.inspect_journal(&original.journal, &expected));
    assert_review_binding_error(service.completed_receipt(&original.journal, &expected));
    assert_review_binding_error(service.current_completed_receipt(&original.journal, &expected));
    assert_eq!(
        std::fs::read(original.journal.join("receipt.json"))?,
        before
    );
    assert_eq!(
        std::fs::read(original.journal.join("plan.json"))?,
        alternate.bytes
    );
    assert!(!original.journal.join("failed-0000.json").exists());
    assert!(
        http.finish()?.is_empty(),
        "mismatch is refused before capability/finality/readback I/O"
    );
    Ok(())
}

#[test]
fn resume_prepared_boundary_rejects_between_open_replacement_before_progress() -> Result<()> {
    for completed in [false, true] {
        let temporary = tempfile::tempdir()?;
        let http = Http::new(None)?;
        let runtime = runtime(temporary.path(), &http.origin);
        let original = plan(&runtime, 7)?;
        let alternate = plan(&runtime, 8)?;
        if completed {
            complete(&original)?;
            complete(&alternate)?;
        }
        let state = Publication::Active {
            journal: plan_journal_id(&original.preflight)?,
        };
        active(&runtime, &original)?.write_state(&state)?;
        let source = alternate.journal.clone();
        let destination = original.journal.clone();
        let invoked = Arc::new(AtomicBool::new(false));
        let hook_invoked = Arc::clone(&invoked);
        let mut reviews = 0;
        let error = slot::resume_open_test_support::with_before_open(
            move || {
                replace_retained_plan(&source, &destination).unwrap();
                hook_invoked.store(true, Ordering::Release);
            },
            || {
                runtime.resume(
                    &original.journal,
                    &mut |reviewed| {
                        reviews += 1;
                        assert_eq!(reviewed.to_json()?, original.preflight.to_json()?);
                        Ok(())
                    },
                    &mut |_| panic!("foreign Prepared reached the external progress observer"),
                )
            },
        )
        .err()
        .expect("opened record must match the original review before progress or dispatch");
        assert_eq!(reviews, 1);
        assert!(invoked.load(Ordering::Acquire));
        assert!(
            matches!(error.downcast_ref::<DeploymentError>(), Some(DeploymentError::InvalidRequest(reason))
            if reason == "retained deployment differs from the original reviewed plan"),
            "{error:#}"
        );
        assert_eq!(active(&runtime, &original)?.read_state()?, state);
        assert_eq!(
            std::fs::read(original.journal.join("plan.json"))?,
            alternate.bytes
        );
        assert_eq!(
            original.journal.join("attempt-0000.json").exists(),
            completed
        );
        assert!(http.finish()?.is_empty());
    }
    Ok(())
}
