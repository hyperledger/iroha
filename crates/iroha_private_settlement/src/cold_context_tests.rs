//! Real filesystem/journal reopen over genuine native QCs and synthetic public World values.
//! Deliberate wallet refusal stops before any plaintext witness or proof exists.
use super::*;
use crate::test_support::{client_with_base_url, compatible_capabilities_response};
use iroha::{
    client::Client,
    http::{HttpTransport, TransportFuture, TransportRequest},
    workflow::FileWorkflowStorage,
};
use iroha_data_model::{
    sumeragi_finality::{
        SumeragiFinalityProof, WorldStateElementKindV1, WorldStateSnapshotEntryV1,
        test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
    sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneState,
    },
};
use iroha_test_samples::private_settlement::{availability_material_fixture_v1, context_fixture};
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Debug)]
struct FinalityTransport(SumeragiFinalityProof);
impl HttpTransport for FinalityTransport {
    fn send_blocking(&self, _: TransportRequest) -> eyre::Result<http::Response<Vec<u8>>> {
        panic!("async original finality required")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            if request.url.path() == "/v1/node/capabilities" {
                assert_eq!(request.method, http::Method::GET);
                return compatible_capabilities_response();
            }
            assert_eq!(request.method, http::Method::GET);
            assert_eq!(request.url.path(), "/v1/bridge/finality/2");
            Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/x-norito")
                .body(norito::encode_canonical(&self.0)?)
                .unwrap())
        })
    }
}
struct Source {
    proof: Option<PrivateSettlementContextsProofV1>,
    reads: AtomicUsize,
}
impl PrivateSettlementContextSource for Source {
    fn fetch<'a>(
        &'a self,
        height: u64,
        selectors: PrivateSettlementContextRequestV1,
    ) -> WorkflowFuture<
        'a,
        std::result::Result<PrivateSettlementContextsProofV1, OneCallPrivateSettlementError>,
    > {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            assert_eq!(height, 2);
            let proof = self.proof.as_ref().ok_or_else(|| {
                OneCallPrivateSettlementError::Provider(eyre::eyre!("old cut no longer served"))
            })?;
            assert_eq!(
                selectors.pools,
                proof
                    .contexts
                    .iter()
                    .map(|p| PrivateSettlementPoolKeyV1 {
                        route: p.pool.pool.route,
                        pool_id: p.pool.pool.pool_id
                    })
                    .collect::<Vec<_>>()
            );
            Ok(proof.clone())
        })
    }
}
#[derive(Default)]
struct RefusingWallet {
    open: AtomicUsize,
    reserve: AtomicUsize,
}
impl PrivateSettlementWallet for RefusingWallet {
    fn open_policy(
        &self,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<PrivateSettlementRestrictedOpening, OneCallPrivateSettlementError>
    {
        self.open.fetch_add(1, Ordering::SeqCst);
        Err(OneCallPrivateSettlementError::Provider(eyre::eyre!(
            "caller opening temporarily unavailable"
        )))
    }
    fn reserve_or_reopen(
        &self,
        _: Digest32,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<
        AtomicPrivateSettlementAuthorizedWalletLegV1,
        OneCallPrivateSettlementError,
    > {
        self.reserve.fetch_add(1, Ordering::SeqCst);
        panic!("no wallet opening means no witness reservation")
    }
}
fn row<K: norito::codec::Encode, V: norito::codec::Encode>(
    field: &str,
    key: &K,
    value: &V,
) -> WorldStateSnapshotEntryV1 {
    WorldStateSnapshotEntryV1 {
        field_id: field.into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(key).unwrap()),
        value_hash: world_state_value_hash_v1(value).unwrap(),
    }
}
fn context(
    client: &Client,
) -> (
    PrivateSettlementContextsProofV1,
    PrivateSettlementProofIntentV1,
) {
    let template = context_fixture(client.network_id(), client.account());
    let (material, _) = availability_material_fixture_v1(client.network_id(), client.account());
    let mut contexts = Vec::new();
    let mut lanes = SumeragiLaneState::default();
    let mut entries = std::collections::BTreeMap::new();
    let mut add = |row: WorldStateSnapshotEntryV1| {
        entries.insert((row.field_id.clone(), row.kind, row.key_hash), row);
    };
    for leg in &material.manifest.legs {
        let mut proof = template.clone();
        let route = leg.route;
        proof.pool.pool.route = route;
        proof.pool.pool.pool_id = leg.pool_id;
        proof.pool.governance.route = route;
        proof.pool.governance.pool_id = leg.pool_id;
        proof.pool.governance.asset_binding_commitment = leg.asset_binding_commitment;
        proof.pool.governance.audit_policy_digest = leg.audit_policy_digest;
        let members = proof
            .committee_keys
            .iter()
            .map(|key| SumeragiLaneMember {
                peer: key.record.public_key.clone().into(),
                pop: key.record.pop.clone().unwrap(),
            })
            .collect();
        lanes.upsert(SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: route.lane_id,
            dataspace: route.dataspace_id,
            incarnation: *route.lane_incarnation.as_ref(),
            params: iroha_data_model::parameter::system::SumeragiParameters::default(),
            committee: members,
            created_at: 0,
            active_from: 2,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 2,
            rescued: 0,
        });
        let key = PrivateSettlementPoolKeyV1 {
            route,
            pool_id: leg.pool_id,
        };
        add(row(
            "world.private_settlement_governance",
            &key,
            &proof.pool.governance,
        ));
        add(row(
            "world.private_settlement_pools",
            &key,
            &proof.pool.pool,
        ));
        for original in &proof.committee_keys {
            add(row(
                "world.consensus_keys_by_pk",
                &original.record.public_key.to_string(),
                &original.index,
            ));
            add(row(
                "world.consensus_keys",
                &original.record.id,
                &original.record,
            ));
        }
        contexts.push(proof);
    }
    add(WorldStateSnapshotEntryV1 {
        field_id: "world.sumeragi_lanes".into(),
        kind: WorldStateElementKindV1::Cell,
        key_hash: None,
        value_hash: world_state_value_hash_v1(&lanes).unwrap(),
    });
    let entries = entries.into_values().collect::<Vec<_>>();
    for proof in &mut contexts {
        proof.lanes = lanes.clone();
        proof.pool.world.entries = entries.clone();
    }
    (
        PrivateSettlementContextsProofV1 { contexts },
        material.manifest.proof_intent(),
    )
}
fn request(
    client: &Client,
    proof: &PrivateSettlementContextsProofV1,
    original: &PrivateSettlementProofIntentV1,
) -> OneCallPrivateSettlementRequest {
    let intent = PrivateSettlementProofIntentV1::new(
        original.network_id,
        2,
        original.expiry_height,
        original.sponsor.clone(),
        original.public_fee_intent.clone(),
        original.reimbursement_terms_commitment,
        original.reimbursement_leg_ordinal,
        original.legs.clone(),
    )
    .unwrap();
    let terms = (0..2)
        .map(|index| PrivateSettlementBusinessTerms {
            asset: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
            payer: client.account().clone(),
            recipient: client.account().clone(),
            amount: 1,
            reimbursement: u128::from(index == usize::from(intent.reimbursement_leg_ordinal)),
            memo: b"cold context fixture".to_vec(),
        })
        .collect();
    OneCallPrivateSettlementRequest::new(
        intent,
        terms,
        proof.contexts[0].pool.world.schema_hash,
        0,
        vec![
            (0..4)
                .map(|index| format!("http://availability-{index}.mock/")
                    .parse()
                    .unwrap())
                .collect();
            2
        ],
        PrivateSettlementCapsulePaddingV1::KiB16,
        500,
        PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64,
        32 * 1024 * 1024,
        64 * 1024 * 1024,
    )
    .unwrap()
}
#[tokio::test(flavor = "current_thread")]
async fn private_onecall_cold_reopen_preserves_context_before_wallet_and_never_fetches_replacement()
{
    let mut native = NativeFinalityFixture::start("private-onecall-cold-context");
    let mut builder = client_with_base_url("http://context.invalid/".parse().unwrap()).to_builder();
    builder.network_id = native.network_id();
    builder.chain = native.chain_id().parse().unwrap();
    let client = builder.build().unwrap();
    let (proof, original_intent) = context(&client);
    let genesis_verifier = native.verifier();
    let block = native.block_with_submitted_work(native.next_header());
    let finality =
        native.certify_with_world_root(block, proof.contexts[0].pool.world.root().unwrap());
    let client = client
        .to_builder()
        .http_transport(Arc::new(FinalityTransport(finality)))
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let journals = root.path().join("journals");
    let artifacts = root.path().join("artifacts");
    let source = Arc::new(Source {
        proof: Some(proof.clone()),
        reads: AtomicUsize::new(0),
    });
    let wallet = Arc::new(RefusingWallet::default());
    let operation = OneCallPrivateSettlementOperation::with_source(
        client.account_client().unwrap(),
        request(&client, &proof, &original_intent),
        Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap()),
        Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[29; 32]).unwrap()),
        source.clone(),
        wallet.clone(),
        genesis_verifier,
    )
    .unwrap();
    let id = operation.id();
    let error = operation
        .run(&PrivateSettlementRunOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(error, OneCallPrivateSettlementError::Provider(_)),
        "original context must be durable before the deliberate wallet refusal: {error:?}"
    );
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.open.load(Ordering::SeqCst), 1);
    let journal = operation.handle.journal_snapshot().unwrap().unwrap();
    let round = journal.steps[0].round.as_ref().unwrap().round_id.unwrap();
    let original_path = artifacts.join(format!("{}.contexts", hex::encode(round)));
    let original_bytes = std::fs::read(&original_path).unwrap();
    let reopened = FilePrivateSettlementArtifacts::open(&artifacts, &[29; 32]).unwrap();
    let saved = reopened
        .read_context(
            ArtifactKey {
                request: request(&client, &proof, &original_intent).0.digest,
                round,
                ordinal: 0,
            },
            32 * 1024 * 1024,
        )
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        saved.contexts.len(),
        2,
        "every selected original must precede the first wallet call"
    );
    assert_eq!(saved, proof);
    drop(reopened);
    drop(operation);
    drop(journal);
    drop(source);
    let absent = Arc::new(Source {
        proof: None,
        reads: AtomicUsize::new(0),
    });
    let rebuilt = OneCallPrivateSettlementOperation::with_source(
        client.account_client().unwrap(),
        request(&client, &proof, &original_intent),
        Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap()),
        Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[29; 32]).unwrap()),
        absent.clone(),
        wallet.clone(),
        NativeFinalityFixture::start("private-onecall-cold-context").verifier(),
    )
    .unwrap();
    assert_eq!(rebuilt.id(), id);
    assert!(
        rebuilt
            .prepared_request(&PrivateSettlementRunOptions::default())
            .await
            .unwrap()
            .is_none(),
        "advanced read-only promotion cannot create missing artifacts"
    );
    assert_eq!(wallet.open.load(Ordering::SeqCst), 1);
    assert_eq!(wallet.reserve.load(Ordering::SeqCst), 0);
    assert_eq!(
        absent.reads.load(Ordering::SeqCst),
        0,
        "advanced promotion cannot replace the persisted original context"
    );
    let recovered = rebuilt
        .recover(&PrivateSettlementRunOptions::default())
        .await
        .unwrap();
    assert!(recovered.receipt.is_none());
    assert!(recovered.progress.is_some());
    assert_eq!(
        wallet.open.load(Ordering::SeqCst),
        1,
        "read-only recovery cannot invoke wallet"
    );
    assert_eq!(
        absent.reads.load(Ordering::SeqCst),
        0,
        "retained exact cut replaces no online source"
    );
    assert!(matches!(
        rebuilt.run(&PrivateSettlementRunOptions::default()).await,
        Err(OneCallPrivateSettlementError::Provider(_))
    ));
    assert_eq!(wallet.open.load(Ordering::SeqCst), 2);
    assert_eq!(wallet.reserve.load(Ordering::SeqCst), 0);
    assert_eq!(absent.reads.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(original_path).unwrap(), original_bytes);
    assert_eq!(
        rebuilt.handle.journal_snapshot().unwrap().unwrap().steps[0]
            .round
            .as_ref()
            .unwrap()
            .round_id,
        Some(round)
    );
}

struct HeldWallet {
    started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<std::sync::mpsc::Receiver<()>>,
    finished: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}
impl PrivateSettlementWallet for HeldWallet {
    fn open_policy(
        &self,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<PrivateSettlementRestrictedOpening, OneCallPrivateSettlementError>
    {
        self.started
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.released.lock().unwrap().recv().unwrap();
        let _ = self.finished.lock().unwrap().take().unwrap().send(());
        Err(OneCallPrivateSettlementError::Provider(eyre::eyre!(
            "deliberately held wallet opening"
        )))
    }
    fn reserve_or_reopen(
        &self,
        _: Digest32,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<
        AtomicPrivateSettlementAuthorizedWalletLegV1,
        OneCallPrivateSettlementError,
    > {
        panic!("held opening never grants witness reservation")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn private_onecall_cancelled_wallet_worker_keeps_original_round_lease_until_exit() {
    let mut native = NativeFinalityFixture::start("private-onecall-cancel-custody");
    let mut builder = client_with_base_url("http://context.invalid/".parse().unwrap()).to_builder();
    builder.network_id = native.network_id();
    builder.chain = native.chain_id().parse().unwrap();
    let client = builder.build().unwrap();
    let (proof, original_intent) = context(&client);
    let verifier = native.verifier();
    let block = native.block_with_submitted_work(native.next_header());
    let finality =
        native.certify_with_world_root(block, proof.contexts[0].pool.world.root().unwrap());
    let client = client
        .to_builder()
        .http_transport(Arc::new(FinalityTransport(finality)))
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let journals = root.path().join("journals");
    let artifacts = root.path().join("artifacts");
    let (started, started_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let (finished, finished_rx) = tokio::sync::oneshot::channel();
    let operation = Arc::new(
        OneCallPrivateSettlementOperation::with_source(
            client.account_client().unwrap(),
            request(&client, &proof, &original_intent),
            Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap()),
            Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[31; 32]).unwrap()),
            Arc::new(Source {
                proof: Some(proof.clone()),
                reads: AtomicUsize::new(0),
            }),
            Arc::new(HeldWallet {
                started: Mutex::new(Some(started)),
                released: Mutex::new(release_rx),
                finished: Mutex::new(Some(finished)),
            }),
            verifier.clone(),
        )
        .unwrap(),
    );
    let running = operation.clone();
    let task =
        tokio::spawn(async move { running.run(&PrivateSettlementRunOptions::default()).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let wallet = Arc::new(RefusingWallet::default());
    let source = Arc::new(Source {
        proof: None,
        reads: AtomicUsize::new(0),
    });
    let reopened = OneCallPrivateSettlementOperation::with_source(
        client.account_client().unwrap(),
        request(&client, &proof, &original_intent),
        Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap()),
        Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[31; 32]).unwrap()),
        source.clone(),
        wallet.clone(),
        verifier,
    )
    .unwrap();
    let error = reopened
        .run(&PrivateSettlementRunOptions::default())
        .await
        .unwrap_err();
    match error {
        OneCallPrivateSettlementError::Provider(cause) => {
            let storage = cause
                .downcast_ref::<iroha::workflow::WorkflowStorageError>()
                .expect("original durable runner refusal");
            assert_eq!(
                storage.kind,
                iroha::workflow::WorkflowStorageErrorKind::Busy
            );
        }
        other => {
            panic!("cancelled awaiter must leave the exact original proof lease held: {other:?}")
        }
    }
    assert_eq!(wallet.open.load(Ordering::SeqCst), 0);
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), finished_rx)
        .await
        .unwrap()
        .unwrap();
    // Native worker drops its original lease immediately after the wallet returns; retry is
    // allowed to observe RunnerBusy until that destructor has completed, never another wallet.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match reopened
            .recover(&PrivateSettlementRunOptions::default())
            .await
        {
            Ok(value) => {
                assert!(value.receipt.is_none());
                break;
            }
            Err(OneCallPrivateSettlementError::Provider(cause))
                if cause
                    .downcast_ref::<iroha::workflow::WorkflowStorageError>()
                    .is_some_and(|e| e.kind == iroha::workflow::WorkflowStorageErrorKind::Busy) =>
            {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "original proof lease never retired"
                );
                tokio::task::yield_now().await;
            }
            other => panic!("unexpected original lease recovery: {other:?}"),
        }
    }
    assert_eq!(wallet.open.load(Ordering::SeqCst), 0);
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn private_onecall_all_public_intent_bindings_precede_every_wallet_effect() {
    // A mismatch on the second leg must not reserve the first leg. Both mutations remain
    // internally valid public intents, so this tests the authenticated context join.
    for changed_policy in [false, true] {
        let mut native = NativeFinalityFixture::start("private-onecall-public-binding");
        let mut builder =
            client_with_base_url("http://context.invalid/".parse().unwrap()).to_builder();
        builder.network_id = native.network_id();
        builder.chain = native.chain_id().parse().unwrap();
        let client = builder.build().unwrap();
        let (proof, original_intent) = context(&client);
        let verifier = native.verifier();
        let block = native.block_with_submitted_work(native.next_header());
        let finality =
            native.certify_with_world_root(block, proof.contexts[0].pool.world.root().unwrap());
        let verified_block = verifier.clone().verify(&finality).unwrap();
        let client = client
            .to_builder()
            .http_transport(Arc::new(FinalityTransport(finality)))
            .build()
            .unwrap();
        let original = request(&client, &proof, &original_intent);
        let mut legs = original.intent().legs.clone();
        if changed_policy {
            legs[1].audit_policy_digest = Hash::new(b"different independently selected policy");
        } else {
            legs[1].asset_binding_commitment = Hash::new(b"different independently selected asset");
        }
        let intent = PrivateSettlementProofIntentV1::new(
            original.intent().network_id,
            original.intent().authority_context_height,
            original.intent().expiry_height,
            original.intent().sponsor.clone(),
            original.intent().public_fee_intent.clone(),
            original.intent().reimbursement_terms_commitment,
            original.intent().reimbursement_leg_ordinal,
            legs,
        )
        .unwrap();
        let changed = OneCallPrivateSettlementRequest::new(
            intent,
            original.0.terms.clone(),
            original.0.schema,
            original.0.minimum_context_time_ms,
            original.0.endpoints.clone(),
            original.0.padding,
            original.0.retention_height,
            original.0.max_carrier_bytes,
            original.0.max_artifact_bytes,
            original.0.max_total_artifact_bytes,
        )
        .unwrap();
        // Prove that this exact authenticated original accepts both initial legs and that
        // only the independently mutated second-leg binding rejects the changed intent.
        for (index, member) in proof.contexts.iter().enumerate() {
            let leg = &original.intent().legs[index];
            let selected = member
                .verify(
                    original.intent().network_id,
                    original.0.schema,
                    PrivateSettlementPoolKeyV1 {
                        route: leg.route,
                        pool_id: leg.pool_id,
                    },
                    &verified_block,
                )
                .unwrap();
            selected
                .verify_intent(original.intent(), leg.ordinal)
                .unwrap();
            assert_eq!(
                selected
                    .verify_intent(changed.intent(), leg.ordinal)
                    .is_err(),
                index == 1,
                "only the selected second-leg binding may differ, changed_policy={changed_policy}"
            );
        }
        let root = tempfile::tempdir().unwrap();
        let source = Arc::new(Source {
            proof: Some(proof),
            reads: AtomicUsize::new(0),
        });
        let wallet = Arc::new(RefusingWallet::default());
        let artifact_path = root.path().join("artifacts");
        let operation = OneCallPrivateSettlementOperation::with_source(
            client.account_client().unwrap(),
            changed,
            Arc::new(FileWorkflowStorage::open_or_create(root.path().join("journals")).unwrap()),
            Arc::new(FilePrivateSettlementArtifacts::open(&artifact_path, &[29; 32]).unwrap()),
            source.clone(),
            wallet.clone(),
            verifier,
        )
        .unwrap();
        let error = operation
            .run(&PrivateSettlementRunOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, OneCallPrivateSettlementError::Finality(_)),
            "valid public intent must fail at its exact authenticated context join: {error:?}"
        );
        assert_eq!(source.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            wallet.open.load(Ordering::SeqCst),
            0,
            "every public leg binding must precede the first wallet opening"
        );
        assert_eq!(
            wallet.reserve.load(Ordering::SeqCst),
            0,
            "a known public commitment mismatch must never reserve wallet notes"
        );
        assert!(
            !std::fs::read_dir(&artifact_path).unwrap().any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "contexts")),
            "a foreign intent cannot persist a usable original context checkpoint"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn private_onecall_fresh_readonly_recovery_has_no_journal_or_wallet_effects() {
    let native = NativeFinalityFixture::start("private-onecall-cold-context");
    let mut builder = client_with_base_url("http://context.invalid/".parse().unwrap()).to_builder();
    builder.network_id = native.network_id();
    builder.chain = native.chain_id().parse().unwrap();
    let client = builder.build().unwrap();
    let (proof, original_intent) = context(&client);
    let root = tempfile::tempdir().unwrap();
    let journals = root.path().join("journals");
    let artifacts = root.path().join("artifacts");
    let source = Arc::new(Source {
        proof: None,
        reads: AtomicUsize::new(0),
    });
    let wallet = Arc::new(RefusingWallet::default());
    let operation = OneCallPrivateSettlementOperation::with_source(
        client.account_client().unwrap(),
        request(&client, &proof, &original_intent),
        Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap()),
        Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[29; 32]).unwrap()),
        source.clone(),
        wallet.clone(),
        native.verifier(),
    )
    .unwrap();
    let options = PrivateSettlementRunOptions::default();
    assert!(
        operation
            .prepared_request(&options)
            .await
            .unwrap()
            .is_none()
    );
    let recovered = operation.recover(&options).await.unwrap();
    assert!(recovered.progress.is_none() && recovered.receipt.is_none());
    assert_eq!(wallet.open.load(Ordering::SeqCst), 0);
    assert_eq!(wallet.reserve.load(Ordering::SeqCst), 0);
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(journals).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(artifacts).unwrap().count(), 0);
}

#[derive(Clone, Copy, Debug)]
enum OperationalRefusal {
    Proof,
    Encoding,
    Binding,
    Signing,
    Permission,
    Unknown,
    RawCodecLimit,
    OriginalDecoderLimit,
    FixedProofLimit,
    Finality,
    Capacity,
}
impl OperationalRefusal {
    fn expected(self) -> WorkflowErrorCode {
        match self {
            Self::Proof | Self::Finality => WorkflowErrorCode::ProofInvalid,
            Self::Encoding => WorkflowErrorCode::NonCanonicalEncoding,
            Self::Binding => WorkflowErrorCode::BindingMismatch,
            Self::Signing | Self::Permission => WorkflowErrorCode::AuthorizationDenied,
            Self::Unknown | Self::RawCodecLimit => WorkflowErrorCode::EvidenceUnavailable,
            Self::OriginalDecoderLimit | Self::Capacity => {
                WorkflowErrorCode::LocalResourceUnavailable
            }
            Self::FixedProofLimit => WorkflowErrorCode::ResourceLimitExceeded,
        }
    }
    fn original(self) -> OneCallPrivateSettlementError {
        use iroha_core_privacy::privacy_engines::atomic_private_settlement::AtomicPrivateSettlementProofErrorV1;
        match self {
            Self::Proof => AtomicPrivateSettlementPreparationErrorV1::Proof(
                AtomicPrivateSettlementProofErrorV1::InvalidProof,
            )
            .into(),
            Self::Encoding => norito::Error::InvalidMagic.into(),
            Self::Binding => OneCallPrivateSettlementError::Binding,
            Self::Signing => OneCallPrivateSettlementError::Provider(eyre::Report::new(
                iroha::Error::RequestSigning {
                    operation: "private-preparation-classification-test",
                    details: "private-test-sentinel must never enter durable diagnostics".into(),
                },
            )),
            Self::Permission => {
                OneCallPrivateSettlementError::Provider(eyre::Report::new(iroha::Error::Http {
                    operation: "private-preparation-classification-test",
                    status: 403,
                    retry_after: None,
                    body: b"private-test-sentinel".to_vec(),
                }))
            }
            Self::Unknown => OneCallPrivateSettlementError::Provider(eyre::eyre!(
                "private-test-sentinel capacity exhausted forbidden proof invalid"
            )),
            Self::RawCodecLimit => norito::Error::TotalAllocationExceeded {
                attempted: 2,
                limit: 1,
            }
            .into(),
            Self::OriginalDecoderLimit => {
                let bytes = norito::encode_canonical(&vec![7_u8; 128]).unwrap();
                let source = norito::core::with_decode_limits_scope(
                    norito::DecodeLimits::new(1024, 1024, 1024, 1, 64),
                    || {
                        norito::core::classify_decode_attempt(|| {
                            norito::decode_canonical::<Vec<u8>>(&bytes)
                        })
                    },
                )
                .unwrap_err();
                assert_eq!(
                    source.kind(),
                    norito::core::DecodeAttemptErrorKind::EnclosingLimit
                );
                OneCallPrivateSettlementError::Provider(eyre::Report::new(
                    iroha::Error::CanonicalDecode(Box::new(iroha::CanonicalDecodeFailure {
                        operation: "private-preparation-classification-test",
                        source,
                    })),
                ))
            }
            Self::FixedProofLimit => AtomicPrivateSettlementPreparationErrorV1::Proof(
                AtomicPrivateSettlementProofErrorV1::ResourceLimit,
            )
            .into(),
            Self::Finality => FinalityReadError::Invalid(FinalityError(
                "private-test-sentinel completed certified root mismatch".into(),
            ))
            .into(),
            Self::Capacity => OneCallPrivateSettlementError::Capacity,
        }
    }
}
struct ClassifiedRefusingWallet {
    cause: OperationalRefusal,
    openings: AtomicUsize,
    reservations: AtomicUsize,
}
impl PrivateSettlementWallet for ClassifiedRefusingWallet {
    fn open_policy(
        &self,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<PrivateSettlementRestrictedOpening, OneCallPrivateSettlementError>
    {
        self.openings.fetch_add(1, Ordering::SeqCst);
        Err(self.cause.original())
    }
    fn reserve_or_reopen(
        &self,
        _: Digest32,
        _: &PrivateSettlementProofIntentV1,
        _: u8,
        _: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<
        AtomicPrivateSettlementAuthorizedWalletLegV1,
        OneCallPrivateSettlementError,
    > {
        self.reservations.fetch_add(1, Ordering::SeqCst);
        panic!("operational refusal cannot grant original secret reservation")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn private_onecall_original_failure_category_survives_store_reopen_without_terminal_verdict()
{
    for cause in [
        OperationalRefusal::Proof,
        OperationalRefusal::Encoding,
        OperationalRefusal::Binding,
        OperationalRefusal::Signing,
        OperationalRefusal::Permission,
        OperationalRefusal::Unknown,
        OperationalRefusal::RawCodecLimit,
        OperationalRefusal::OriginalDecoderLimit,
        OperationalRefusal::FixedProofLimit,
        OperationalRefusal::Finality,
        OperationalRefusal::Capacity,
    ] {
        let mut native = NativeFinalityFixture::start("private-preparation-classification");
        let mut builder =
            client_with_base_url("http://context.invalid/".parse().unwrap()).to_builder();
        builder.network_id = native.network_id();
        builder.chain = native.chain_id().parse().unwrap();
        let client = builder.build().unwrap();
        let (proof, original_intent) = context(&client);
        let original_verifier = native.verifier();
        let block = native.block_with_submitted_work(native.next_header());
        let finality =
            native.certify_with_world_root(block, proof.contexts[0].pool.world.root().unwrap());
        // The public compatibility handshake precedes finality reads; any monetary dispatch fails.
        let client = client
            .to_builder()
            .http_transport(Arc::new(FinalityTransport(finality)))
            .build()
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let journals = root.path().join("journals");
        let artifacts = root.path().join("artifacts");
        let mut original = None;
        for reopening in [false, true] {
            // Every pass creates fresh storage, wallet, request, artifact, verifier and driver owners.
            let storage = Arc::new(FileWorkflowStorage::open_or_create(&journals).unwrap());
            let source = Arc::new(Source {
                proof: (!reopening).then(|| proof.clone()),
                reads: AtomicUsize::new(0),
            });
            let wallet = Arc::new(ClassifiedRefusingWallet {
                cause,
                openings: AtomicUsize::new(0),
                reservations: AtomicUsize::new(0),
            });
            let operation = OneCallPrivateSettlementOperation::with_source(
                client.account_client().unwrap(),
                request(&client, &proof, &original_intent),
                storage.clone(),
                Arc::new(FilePrivateSettlementArtifacts::open(&artifacts, &[73; 32]).unwrap()),
                source.clone(),
                wallet.clone(),
                original_verifier.clone(),
            )
            .unwrap();
            let options = PrivateSettlementRunOptions::default();
            if reopening {
                assert!(operation.recover(&options).await.unwrap().receipt.is_none());
                assert_eq!(wallet.openings.load(Ordering::SeqCst), 0);
                assert_eq!(wallet.reservations.load(Ordering::SeqCst), 0);
                assert_eq!(source.reads.load(Ordering::SeqCst), 0);
            }
            operation
                .driver
                .begin_call(options.max_finality_proof_reads.get() as usize)
                .unwrap();
            // Exercise the actual canonical workflow owner before the public wrapper returns
            // the separately preserved original error. No replacement classifier is used.
            let failure = operation
                .handle
                .run(operation.driver.as_ref(), &options.workflow)
                .await
                .unwrap_err();
            assert_eq!(
                failure.code,
                cause.expected(),
                "{cause:?}, reopened={reopening}"
            );
            assert!(!failure.detail.contains("private-test-sentinel"));
            assert!(
                operation.driver.take_error().unwrap().is_some(),
                "public original remains available"
            );
            let journal = operation.handle.journal_snapshot().unwrap().unwrap();
            assert_eq!(
                journal.status,
                iroha::workflow::WorkflowStatusV1::InProgress
            );
            assert_eq!(
                journal.failure_code, None,
                "operational errors are not stored terminal outcomes"
            );
            assert_eq!(journal.failure_step, None);
            assert_eq!(journal.steps.len(), 1);
            assert!(journal.steps.iter().all(|step| step.transaction.is_none()));
            let round = journal.steps[0].round.as_ref().unwrap();
            let round_id = round.round_id.unwrap();
            let stored = storage.load(&operation.id()).unwrap().unwrap();
            assert!(
                !stored
                    .windows(b"private-test-sentinel".len())
                    .any(|window| window == b"private-test-sentinel")
            );
            let context =
                std::fs::read(artifacts.join(format!("{}.contexts", hex::encode(round_id))))
                    .unwrap();
            let identity = (operation.id(), round_id, round.start_ordinal, context);
            if let Some(original) = &original {
                assert_eq!(
                    &identity, original,
                    "restart must retain the original round and encrypted cut"
                );
            } else {
                original = Some(identity);
            }
            assert_eq!(wallet.openings.load(Ordering::SeqCst), 1);
            assert_eq!(wallet.reservations.load(Ordering::SeqCst), 0);
            assert_eq!(source.reads.load(Ordering::SeqCst), usize::from(!reopening));
            // End scope drops every operation/storage owner before the next pass reopens files.
        }
    }
}
