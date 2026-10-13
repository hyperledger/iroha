//! Full journal restart with real signatures/QCs and synthetic execution over owned transports.

use super::*;
use crate::{
    http::{HttpTransport, Response, StatusCode, TransportFuture, TransportRequest},
    http_default::DefaultHttpTransport,
};
use iroha_data_model::{
    nexus::PrivateSettlementReceiptV1, sumeragi_finality::SumeragiFinalityProof,
};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};

struct World {
    native: NativeFinalityFixture,
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    carriers: BTreeMap<String, u64>,
    receipt: Option<PrivateSettlementReceiptV1>,
    submissions: usize,
    defer_registration_observation: bool,
}
struct Transport(Mutex<World>);
impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyntheticPrivateSettlementTransport")
    }
}
fn json<T: norito::json::JsonSerialize>(
    status: StatusCode,
    value: &T,
) -> eyre::Result<Response<Vec<u8>>> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(norito::json::to_vec(value)?)?)
}
impl Transport {
    fn respond(&self, request: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        let mut world = self.0.lock().unwrap();
        let path = request.url.path();
        if path.ends_with("/bundles") {
            let request: PrivateSettlementBundleSubmitRequestV1 =
                norito::json::from_slice(&request.body)
                    .expect("exact SDK carrier request must decode at the owned transport");
            let transaction = request.transaction;
            let manifest = exact_private_settlement_carrier_v1(&transaction)?.clone();
            world.submissions += 1;
            assert!(
                !world.carriers.contains_key(&transaction.hash().to_string()),
                "restart must preserve the original carrier instead of resubmitting it"
            );
            let header = world.native.next_header();
            let height = header.height().get();
            if let Executable::Instructions(instructions) = transaction.instructions() {
                if let Some(finalize) = instructions[0]
                    .as_any()
                    .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
                {
                    world.receipt = Some(finalize.commit_bundle.clone().into_receipt(height));
                }
            }
            let hash = transaction.hash();
            let mut builder = BlockBuilder::new(header);
            builder.push_transaction(transaction);
            let mut block = builder.build(BlockSignatures::default());
            block.set_execution_outputs(
                vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: TransactionResult::new(Ok(Vec::new())),
                    completions: Vec::new(),
                })],
                0,
                Default::default(),
                Vec::new(),
                AxtPolicySnapshot::default(),
                Default::default(),
                &ExecutionOutputLimits {
                    max_outputs: 16,
                    max_output_bytes: 16 * 1024 * 1024,
                    max_total_output_bytes: 32 * 1024 * 1024,
                    max_executed_wire_bytes: 32 * 1024 * 1024,
                },
            )?;
            let proof = world.native.certify(block);
            world.proofs.insert(height, proof);
            world.carriers.insert(hash.to_string(), height);
            // Both carriers commit even though the first response is lost. Recovery must
            // authenticate that exact input/output, never create another signed carrier.
            if world.submissions == 1 {
                return Err(eyre!("simulated lost Register response"));
            }
            return json(
                StatusCode::ACCEPTED,
                &PrivateSettlementBundleSubmitResponseV1 {
                    bundle_id: manifest.bundle_id,
                    accepted_at_height: height,
                    carrier_id: hash.into(),
                },
            );
        }
        if path.ends_with("/receipt") {
            let response = match &world.receipt {
                Some(receipt) => {
                    PrivateSettlementBundleReceiptResponseV1::Finalized(receipt.clone())
                }
                None => PrivateSettlementBundleReceiptResponseV1::Pending {
                    bundle_id: path.split('/').rev().nth(1).unwrap().parse()?,
                },
            };
            return json(StatusCode::OK, &response);
        }
        if path.ends_with("/transactions/status") {
            let hash = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "hash")
                .unwrap()
                .1
                .into_owned();
            let Some(height) = world.carriers.get(&hash) else {
                let signed_hash: HashOf<SignedTransaction> = hash.parse()?;
                let envelope = iroha_torii_shared::ErrorEnvelope::new(
                    iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                    "exact original carrier is absent",
                )
                .with_details(iroha_torii_shared::ErrorDetails {
                    pipeline_transaction_status_not_found: Some(
                        iroha_torii_shared::PipelineTransactionStatusNotFoundV1::new(
                            &signed_hash,
                            "global",
                        ),
                    ),
                    ..Default::default()
                });
                return json(StatusCode::NOT_FOUND, &envelope);
            };
            if world.defer_registration_observation {
                return Err(eyre!("simulated Register observation interruption"));
            }
            return json(
                StatusCode::OK,
                &norito::json!({ "hash": hash, "scope": "global", "resolved_from": "state", "status": { "kind": "Applied", "block_height": height } }),
            );
        }
        let height: u64 = path.rsplit('/').next().unwrap().parse()?;
        let proof = world
            .proofs
            .get(&height)
            .expect("no unrelated successor block exists");
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/x-norito")
            .body(norito::encode_canonical(proof)?)?)
    }
}
impl HttpTransport for Transport {
    fn send_blocking(&self, request: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        self.respond(request)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.respond(request) })
    }
}
struct Phases {
    request: PrivateSettlementRequest,
    certificates: Vec<PrivateSettlementSidecarAvailabilityV1>,
    availability_calls: AtomicUsize,
    promoted: AtomicBool,
    stop_before_promotion: AtomicBool,
}
impl SettlementPhases for Phases {
    fn run(
        &self,
        phase: usize,
        journal: WorkflowJournalV1,
        read_only: bool,
    ) -> WorkflowFuture<'_, std::result::Result<Option<Vec<u8>>, PrivateSettlementError>> {
        Box::pin(async move {
            if read_only {
                return Ok(None);
            }
            if phase == AVAILABILITY {
                self.availability_calls.fetch_add(1, Ordering::SeqCst);
                return Ok(Some(norito::encode_canonical(&self.certificates)?));
            }
            assert_eq!(
                transcript::<Vec<PrivateSettlementSidecarAvailabilityV1>>(&journal, AVAILABILITY)?,
                self.certificates,
                "the exact selected availability quorum must be durable before promotion"
            );
            if phase == PREPARE {
                if self.stop_before_promotion.swap(false, Ordering::SeqCst) {
                    return Err(PrivateSettlementError::Worker);
                }
                self.promoted.store(true, Ordering::SeqCst);
                let manifest = self.request.manifest_with(&self.certificates)?;
                return Ok(Some(norito::encode_canonical(&phase_certificates(
                    &self.request,
                    &manifest,
                    PrivateSettlementPhaseV1::Prepare,
                    private_settlement_reserved_prepared_digest_v1(),
                ))?));
            }
            assert_eq!(phase, COMMIT);
            assert!(journal.steps[REGISTER].is_done());
            let barrier = self.request.barrier(&journal)?;
            Ok(Some(norito::encode_canonical(&phase_certificates(
                &self.request,
                &barrier.manifest,
                PrivateSettlementPhaseV1::Commit,
                barrier.prepared_bundle_digest,
            ))?))
        })
    }
}

async fn restart_operation(defer_registration_observation: bool) {
    let native = NativeFinalityFixture::start("prepared-private-settlement-operation");
    let verifier = native.verifier();
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    client.chain = native.chain_id().parse().unwrap();
    let (request, certificates) = prepared(&client);
    let transport = Arc::new(Transport(Mutex::new(World {
        proofs: BTreeMap::from([(1, native.genesis_proof().clone())]),
        native,
        carriers: BTreeMap::new(),
        receipt: None,
        submissions: 0,
        defer_registration_observation,
    })));
    let client =
        client.with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
    crate::client::evidence_http_tests::mark_data_model_compatible(&client);
    let account = client.account_client().unwrap();
    let phases = Arc::new(Phases {
        request: request.clone(),
        certificates,
        availability_calls: AtomicUsize::new(0),
        promoted: AtomicBool::new(false),
        stop_before_promotion: AtomicBool::new(true),
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settlement");
    let open = || {
        let storage = Arc::new(FileWorkflowStorage::open_or_create(&path).unwrap());
        let mut operation = account
            .private_settlement(request.clone(), storage, verifier.clone())
            .unwrap();
        Arc::get_mut(&mut operation.driver).unwrap().phases = phases.clone();
        operation
    };
    let first = open();
    let id = first.id();
    assert!(
        first
            .run(&PrivateSettlementRunOptions::default())
            .await
            .is_err()
    );
    assert!(!phases.promoted.load(Ordering::SeqCst));
    assert_eq!(phases.availability_calls.load(Ordering::SeqCst), 1);
    drop(first);
    let resumed = open();
    assert_eq!(resumed.id(), id);
    let _ = resumed
        .recover(&PrivateSettlementRunOptions::default())
        .await;
    assert!(
        !phases.promoted.load(Ordering::SeqCst),
        "read-only recovery cannot upload"
    );
    let resumed = if defer_registration_observation {
        let mut options = PrivateSettlementRunOptions::default();
        options.workflow.observation_timeout = Duration::from_millis(100);
        options.workflow.poll_interval = Duration::from_millis(10);
        let interrupted = resumed.run(&options).await;
        assert!(interrupted.is_err());
        let journal = resumed
            .load()
            .expect("live context can read its exact journal")
            .unwrap();
        assert!(
            journal.steps[REGISTER]
                .transaction
                .as_ref()
                .unwrap()
                .signed_transaction
                .is_some()
        );
        let signed = journal.steps[REGISTER]
            .transaction
            .as_ref()
            .unwrap()
            .signed_transaction
            .as_ref()
            .unwrap();
        let transaction = crate::client::workflow_ledger::decode_signed(signed).unwrap();
        let body = norito::json::to_vec(&PrivateSettlementBundleSubmitRequestV1 { transaction })
            .expect("exact signed Register must serialize for the original submission endpoint");
        let _: PrivateSettlementBundleSubmitRequestV1 = norito::json::from_slice(&body).expect(
            "exact signed Register must roundtrip through the original submission endpoint",
        );
        if transport.0.lock().unwrap().submissions == 0 {
            let request = norito::json::from_slice(&body).unwrap();
            let direct = account
                .client()
                .submit_private_settlement_bundle_v1(&request);
            panic!(
                "Register never reached the owned transport; exact helper diagnosis: {direct:?}; operation: {interrupted:?}"
            );
        }
        assert_eq!(transport.0.lock().unwrap().submissions, 1);
        drop(resumed);
        transport.0.lock().unwrap().defer_registration_observation = false;
        let restarted = open();
        assert_eq!(restarted.id(), id);
        restarted
    } else {
        resumed
    };
    let settled = resumed
        .run(&PrivateSettlementRunOptions::default())
        .await
        .expect("file-backed unresolved signed Register must reopen before its certificate context is restored");
    assert_eq!(settled.receipt.receipt().finalized_height, 3);
    assert_eq!(transport.0.lock().unwrap().submissions, 2);
    assert_eq!(phases.availability_calls.load(Ordering::SeqCst), 1);
    let original_hash = settled.receipt.transaction_hash();
    drop(resumed);
    let restarted = open();
    let recovered = restarted
        .recover(&PrivateSettlementRunOptions::default())
        .await
        .unwrap();
    assert_eq!(recovered.receipt.unwrap().transaction_hash(), original_hash);
    assert_eq!(
        transport.0.lock().unwrap().submissions,
        2,
        "final-tip restart cannot create a third paid carrier"
    );
    assert_eq!(transport.0.lock().unwrap().native.latest().height(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_settlement_operation_restarts_exact_checkpoint_and_recovers_lost_response_at_final_tip()
 {
    restart_operation(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_settlement_unresolved_signed_register_reopens_from_original_file_journal() {
    restart_operation(true).await;
}
