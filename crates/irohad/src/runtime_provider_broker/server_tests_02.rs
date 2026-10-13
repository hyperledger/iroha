#[derive(Debug)]
struct ServerTestReputationRetentionAuthority {
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
}
impl ServerTestReputationRetentionAuthority {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_REPUTATION_RETENTION_HANDLE.to_owned(),
            revision: 7,
            policy_digest: TEST_POLICY_DIGEST,
        }
    }
}
impl test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityV1
    for ServerTestReputationRetentionAuthority
{
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    > {
        Ok(
            test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityQualificationV1::new(
                self.revision,
                self.policy_digest,
            ),
        )
    }
    fn load_latest(
        &self,
        _network_id: &NetworkId,
    ) -> Result<
        Option<test_reputation_query::ReputationFinalizedArchiveRetentionApprovalRecordV1>,
        test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    > {
        Ok(None)
    }
    fn compare_and_swap_latest(
        &self,
        _network_id: &NetworkId,
        _expected_revision: Option<[u8; 32]>,
        _next: &test_reputation_query::ReputationFinalizedArchiveRetentionApprovalRecordV1,
    ) -> Result<
        (),
        test_reputation_query::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    > {
        Err(
            test_reputation_query::
                ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1::Rejected,
        )
    }
}
#[derive(Debug)]
struct LaxGovernanceCheckpointStore {
    handle: String,
    revision: AtomicU64,
    policy_digest: [u8; 32],
    records: Mutex<
        Vec<(
            node::GovernanceDagSealedStateSlot,
            node::GovernanceDagSealedStateRecord,
        )>,
    >,
    compare_and_swap_calls: AtomicU64,
    delete_calls: AtomicU64,
    drift_after_compare_and_swap: bool,
}
impl LaxGovernanceCheckpointStore {
    fn new(handle: impl Into<String>, revision: u64) -> Self {
        Self {
            handle: handle.into(),
            revision: AtomicU64::new(revision),
            policy_digest: TEST_POLICY_DIGEST,
            records: Mutex::new(Vec::new()),
            compare_and_swap_calls: AtomicU64::new(0),
            delete_calls: AtomicU64::new(0),
            drift_after_compare_and_swap: false,
        }
    }
    fn with_record(
        self,
        slot: node::GovernanceDagSealedStateSlot,
        record: node::GovernanceDagSealedStateRecord,
    ) -> Self {
        self.records
            .lock()
            .expect("lock lax checkpoint records")
            .push((slot, record));
        self
    }
    fn with_post_compare_and_swap_drift(mut self) -> Self {
        self.drift_after_compare_and_swap = true;
        self
    }
    fn with_policy_digest(mut self, policy_digest: [u8; 32]) -> Self {
        self.policy_digest = policy_digest;
        self
    }
}
impl node::GovernanceDagSealedCheckpointStore for LaxGovernanceCheckpointStore {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn qualification(&self) -> Result<node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(node::GovernanceDagRuntimeProviderQualificationV1::new(
            self.revision.load(Ordering::Acquire),
            self.policy_digest,
        ))
    }
    fn load(
        &self,
        slot: node::GovernanceDagSealedStateSlot,
    ) -> Result<Option<node::GovernanceDagSealedStateRecord>, String> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "lax checkpoint record lock poisoned".to_owned())?
            .iter()
            .find(|(candidate, _)| *candidate == slot)
            .map(|(_, record)| record.clone()))
    }
    fn compare_and_swap(
        &self,
        slot: node::GovernanceDagSealedStateSlot,
        _expected_revision: Option<[u8; 32]>,
        next: node::GovernanceDagSealedStateRecord,
    ) -> Result<(), String> {
        self.compare_and_swap_calls.fetch_add(1, Ordering::AcqRel);
        let mut records = self
            .records
            .lock()
            .map_err(|_| "lax checkpoint record lock poisoned".to_owned())?;
        if let Some((_, current)) = records.iter_mut().find(|(candidate, _)| *candidate == slot) {
            *current = next;
        } else {
            records.push((slot, next));
        }
        drop(records);
        if self.drift_after_compare_and_swap {
            self.revision.store(8, Ordering::Release);
        }
        Ok(())
    }
    fn delete(
        &self,
        slot: node::GovernanceDagSealedStateSlot,
        _expected_revision: [u8; 32],
    ) -> Result<(), String> {
        self.delete_calls.fetch_add(1, Ordering::AcqRel);
        self.records
            .lock()
            .map_err(|_| "lax checkpoint record lock poisoned".to_owned())?
            .retain(|(candidate, _)| *candidate != slot);
        Ok(())
    }
}
struct RevisionOnEofReader {
    inner: Cursor<Vec<u8>>,
    revision: Arc<AtomicU64>,
}
impl std::io::Read for RevisionOnEofReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = std::io::Read::read(&mut self.inner, output)?;
        if read == 0 {
            self.revision.store(6, Ordering::Release);
        }
        Ok(read)
    }
}
#[derive(Clone)]
struct ServerTestProviderSource {
    payload: Vec<u8>,
    manifest: sorafs_manifest::ManifestV1,
    plan: sorafs_car::CarBuildPlan,
    revision: Arc<AtomicU64>,
    fetch_delay: Duration,
    drift_on_eof: bool,
    observed_request: Option<Arc<Mutex<Option<node::ProviderIngestSourceRequestV1>>>>,
}
impl_broker_debug_fields!(ServerTestProviderSource as value {
    "payload_len" => value.payload.len(),
} => finish_non_exhaustive);
impl node::ProviderIngestAuthenticatedSourceFetchV1 for ServerTestProviderSource {
    type Fetched = crate::sorafs_provider_ingest_runtime::VerifiedProviderIngestPayloadV1;
    fn fetch(
        &self,
        request: node::ProviderIngestSourceRequestV1,
    ) -> node::ProviderIngestFutureV1<
        '_,
        Result<Self::Fetched, node::ProviderIngestSourceFetchErrorV1>,
    > {
        let payload = self.payload.clone();
        let manifest = self.manifest.clone();
        let plan = self.plan.clone();
        let revision = Arc::clone(&self.revision);
        let fetch_delay = self.fetch_delay;
        let drift_on_eof = self.drift_on_eof;
        let observed_request = self.observed_request.clone();
        Box::pin(async move {
            if let Some(observed_request) = observed_request {
                *observed_request.lock().expect("capture source request") = Some(request);
            }
            if !fetch_delay.is_zero() {
                tokio::time::sleep(fetch_delay).await;
            }
            let reader: Box<dyn std::io::Read + Send> = if drift_on_eof {
                Box::new(RevisionOnEofReader {
                    inner: Cursor::new(payload),
                    revision,
                })
            } else {
                Box::new(Cursor::new(payload))
            };
            Ok(
                crate::sorafs_provider_ingest_runtime::VerifiedProviderIngestPayloadV1::new(
                    manifest, plan, reader,
                ),
            )
        })
    }
}
impl crate::sorafs_provider_ingest_runtime::ProviderIngestAuthenticatedSourceRuntimeV1
    for ServerTestProviderSource
{
    fn runtime_handle(&self) -> &str {
        SERVER_TEST_SOURCE_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<
        node::ProviderIngestRuntimeProviderQualificationV1,
        node::ProviderIngestSourceFetchErrorV1,
    > {
        Ok(node::ProviderIngestRuntimeProviderQualificationV1::new(
            self.revision.load(Ordering::Acquire),
            [0xB1; 32],
        ))
    }
    fn source_provider_ids(&self) -> &[[u8; 32]] {
        &SERVER_TEST_SOURCE_PROVIDER_IDS
    }
    fn check_readiness(&self) -> Result<(), node::ProviderIngestSourceFetchErrorV1> {
        Ok(())
    }
}
fn test_source_material(
    payload: &[u8],
) -> (
    node::FinalizedProviderIngestAuthorizationV1,
    sorafs_manifest::ManifestV1,
    sorafs_car::CarBuildPlan,
) {
    let plan = sorafs_car::CarBuildPlan::single_file(payload).expect("build source plan");
    let car_stats = sorafs_car::CarWriter::new(&plan, payload)
        .expect("prepare source CAR")
        .write_to(std::io::sink())
        .expect("compute source CAR");
    let root_cid = car_stats
        .root_cids
        .first()
        .cloned()
        .expect("source CAR root");
    let manifest = sorafs_manifest::ManifestBuilder::new()
        .root_cid(root_cid.clone())
        .dag_codec(sorafs_manifest::DagCodecId(car_stats.dag_codec))
        .chunking_from_profile(
            sorafs_chunker::ChunkProfile::DEFAULT,
            sorafs_manifest::BLAKE3_256_MULTIHASH_CODE,
        )
        .chunk_digest_sha3_256(sorafs_car::compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(sorafs_car::compute_por_root(payload, &plan).expect("derive source PoR root"))
        .content_length(plan.content_length)
        .car_digest(*car_stats.car_archive_digest.as_bytes())
        .car_size(car_stats.car_size)
        .pin_policy(sorafs_manifest::PinPolicy::default())
        .build()
        .expect("build source manifest");
    let manifest_digest = *manifest
        .digest()
        .expect("digest source manifest")
        .as_bytes();
    let chunker_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    let authorization = node::FinalizedProviderIngestAuthorizationV1::from_finalized_state(
        7,
        [0x77; 32],
        [0x99; 32],
        [0x88; 32],
        manifest_digest,
        root_cid,
        chunker_handle,
        manifest.chunk_digest_sha3_256,
        manifest.por_root,
        manifest.content_length,
    )
    .expect("build source authorization");
    (authorization, manifest, plan)
}
fn test_source_musubi_fetch_binding(
    authorization: &node::FinalizedProviderIngestAuthorizationV1,
    manifest: &sorafs_manifest::ManifestV1,
    plan: &sorafs_car::CarBuildPlan,
    network_id: NetworkId,
) -> (
    node::FinalizedProviderIngestAuthorizationV1,
    node::ProviderIngestMusubiArchiveFetchBindingV1,
) {
    let commitment = iroha_data_model::musubi::MusubiArchiveCommitmentV1 {
        root_cid: test_pin_registry::ManifestRootCid::try_from_slice(&manifest.root_cid)
            .expect("canonical source root CID"),
        chunker: test_pin_registry::ChunkerProfileHandle {
            profile_id: manifest.chunking.profile_id.0,
            namespace: manifest.chunking.namespace.clone(),
            name: manifest.chunking.name.clone(),
            semver: manifest.chunking.semver.clone(),
            multihash_code: manifest.chunking.multihash_code,
        },
        chunk_plan_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(
            manifest.chunk_digest_sha3_256,
        ),
        por_root: iroha_data_model::musubi::MusubiContentDigestV1::new(manifest.por_root),
        content_length: manifest.content_length,
        car_digest: iroha_data_model::musubi::MusubiContentDigestV1::new(manifest.car_digest),
        car_size: manifest.car_size,
        bundle_digest: iroha_data_model::musubi::MusubiContentDigestV1::new([0xB1; 32]),
        source_tree_digest: iroha_data_model::musubi::MusubiContentDigestV1::new([0xB2; 32]),
        descriptor_digest: iroha_data_model::musubi::MusubiContentDigestV1::new([0xB3; 32]),
        file_count: u32::try_from(plan.files.len()).expect("source file count fits u32"),
        chunk_count: u32::try_from(plan.chunks.len()).expect("source chunk count fits u32"),
    };
    let archive_id = commitment.archive_id();
    let binding = iroha_data_model::musubi::MusubiReplicationOrderArchiveBindingV1::new(
        test_pin_registry::ReplicationOrderId::new(authorization.order_id()),
        archive_id,
        commitment,
    );
    let musubi_authorization =
        node::FinalizedProviderIngestAuthorizationV1::from_finalized_musubi_state(
            authorization.finalized_height(),
            authorization.finalized_block_hash(),
            authorization.provider_id(),
            authorization.order_id(),
            authorization.manifest_digest(),
            authorization.manifest_cid().to_vec(),
            authorization.chunker_handle().to_owned(),
            authorization.chunk_digest_sha3_256(),
            authorization.por_root(),
            authorization.content_length(),
            node::provider_ingest_outbox::FinalizedProviderIngestMusubiContextV1::new(
                network_id, archive_id,
            )
            .expect("construct source Musubi context"),
        )
        .expect("construct source Musubi authorization");
    let fetch_binding = node::ProviderIngestMusubiArchiveFetchBindingV1::new(
        network_id,
        authorization.provider_id(),
        authorization.admission_finalized_cursor(),
        binding,
    )
    .expect("construct Musubi source binding");
    (musubi_authorization, fetch_binding)
}
fn source_test_catalog(
    timeout: Duration,
    max_content_bytes: u64,
    max_concurrent_streams: u32,
) -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_provider_ingest_source_for_test(
        "server-test-chain",
        SERVER_TEST_SOURCE_HANDLE,
        5,
        [0xB1; 32],
        ProviderIngestSourceLimitsV1 {
            operation_timeout_ms: u64::try_from(timeout.as_millis())
                .expect("test timeout fits u64"),
            max_content_bytes,
            max_source_providers: 8,
            max_concurrent_streams,
        },
    )
}
fn server_test_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_governance_dag_signer_for_test(
        "server-test-chain",
        SERVER_TEST_SIGNER_HANDLE,
        7,
        TEST_POLICY_DIGEST,
        "12D3KooWRuntimeBrokerServerPrimary",
        "1509a611ad6d97b01d871e58ed00c8fd7c3917b6ca61a8c2833a19e000aac2e4",
    )
}
fn evidence_transparency_publisher_test_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_evidence_viewer_transparency_publisher_for_test(
        "server-test-chain",
        SERVER_TEST_EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE,
        7,
        TEST_POLICY_DIGEST,
        TEST_SIGNER_KEY,
    )
}
fn evidence_transparency_test_body()
-> test_evidence_transparency::EvidenceViewerTransparencyHeadBodyV1 {
    test_evidence_transparency::EvidenceViewerTransparencyHeadBodyV1 {
        version: test_evidence_transparency::EVIDENCE_VIEWER_TRANSPARENCY_HEAD_VERSION_V1,
        generation: 1,
        predecessor_head_digest: None,
        operation_id: [0x81; 32],
        source_checkpoint_anchor: node::evidence_viewer::EvidenceViewerSignedCheckpointAnchorV1 {
            version: node::evidence_viewer::EVIDENCE_VIEWER_CHECKPOINT_VERSION_V1,
            checkpoint_generation: 1,
            predecessor_checkpoint_revision: None,
            predecessor_checkpoint_digest: None,
            checkpoint_digest: [0x82; 32],
            receipt_count: 0,
            chain_head: None,
            compaction_archive_head_digest: None,
            checkpoint_store_handle: "sealed://sorafs/evidence-viewer/checkpoint-primary"
                .to_owned(),
            checkpoint_store_revision: 9,
            checkpoint_store_policy_digest: [0x83; 32],
            signer_handle: "software://sorafs/evidence-viewer/primary".to_owned(),
            signer_public_key: TEST_SIGNER_KEY,
            signature: [0x84; 64],
        },
        source_compaction_archive_head: None,
        source_predecessor: None,
        source_page_limit: 256,
        source_has_more: false,
        receipt_cursor: None,
        source_projection_digest: [0x85; 32],
        publisher_handle: SERVER_TEST_EVIDENCE_TRANSPARENCY_PUBLISHER_HANDLE.to_owned(),
        publisher_revision: 7,
        publisher_policy_digest: TEST_POLICY_DIGEST,
        publisher_public_key: TEST_SIGNER_KEY,
    }
}
fn request_auth_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_governance_request_auth_for_test(
        "server-test-chain",
        IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator,
        SERVER_TEST_IPFS_AUTH_HANDLE,
        7,
        TEST_POLICY_DIGEST,
        test_auth_public_key(),
        1024,
    )
}
fn native_signer_test_catalog() -> IrohaRuntimeProviderBindingsV1 {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    IrohaRuntimeProviderBindingsV1::qualified_native_transaction_signers_for_test(
        "server-test-chain",
        [
            (
                IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
                ServerTestNativeSigner::exact(Role::ProofOutcome).binding(),
            ),
            (
                IrohaRuntimeProviderSlotV1::RepairTransactionSigner,
                ServerTestNativeSigner::exact(Role::Repair).binding(),
            ),
            (
                IrohaRuntimeProviderSlotV1::ReserveTransactionSigner,
                ServerTestNativeSigner::exact(Role::Reserve).binding(),
            ),
            (
                IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner,
                ServerTestNativeSigner::exact(Role::Orderbook).binding(),
            ),
        ],
    )
    .with_network_id_for_test(network_id())
}
fn signer_catalog() -> IrohaRuntimeProviderBindingsV1 {
    let signer = ServerTestNativeSigner::exact(
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome,
    );
    IrohaRuntimeProviderBindingsV1::qualified_native_transaction_signers_for_test(
        "server-test-chain",
        [(
            IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner,
            signer.binding(),
        )],
    )
    .with_network_id_for_test(network_id())
}
fn native_signer_test_backends() -> RuntimeProviderBrokerBackendsV1 {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    RuntimeProviderBrokerBackendsV1::new()
        .with_proof_outcome_transaction_signer(Arc::new(ServerTestNativeSigner::exact(
            Role::ProofOutcome,
        )))
        .with_repair_transaction_signer(Arc::new(ServerTestNativeSigner::exact(Role::Repair)))
        .with_reserve_transaction_signer(Arc::new(ServerTestNativeSigner::exact(Role::Reserve)))
        .with_orderbook_transaction_signer(Arc::new(ServerTestNativeSigner::exact(Role::Orderbook)))
}
include!("native_signer_test_support.rs");
fn provider_ingest_completion_test_keypair() -> KeyPair {
    KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
        .expect("provider-ingest completion test key")
}
const fn ingest_completion_policy() -> test_pin_registry::ProviderIngestCompletionSignerPolicyV1 {
    test_pin_registry::ProviderIngestCompletionSignerPolicyV1 {
        policy_id: [0xA1; 32],
        revision: 1,
        predecessor_digest: None,
        policy_digest: [0xA2; 32],
    }
}
const fn ingest_completion_cursor() -> node::ProviderIngestFinalizedCursorV1 {
    node::ProviderIngestFinalizedCursorV1 {
        height: 17,
        block_hash: [0x17; 32],
    }
}
fn provider_ingest_completion_test_context(
    owner: AccountId,
) -> node::ProviderIngestCompletionSignerResolutionContextV1 {
    node::ProviderIngestCompletionSignerResolutionContextV1::new(
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1::new(
            (owner).clone(),
            owner,
            ingest_completion_policy(),
        ),
        3,
        ingest_completion_cursor(),
    )
}
fn provider_ingest_completion_test_instruction(
    owner: AccountId,
) -> iroha_data_model::isi::sorafs::CompleteReplicationOrder {
    iroha_data_model::isi::sorafs::CompleteReplicationOrder {
        order_id: test_pin_registry::ReplicationOrderId::new([0x11; 32]),
        provider_id: iroha_data_model::sorafs::capacity::ProviderId::new([0x22; 32]),
        completion_epoch: 9,
        expected_authority: test_pin_registry::ProviderIngestCompletionAuthorityV1::new(
            (owner).clone(),
            owner,
            ingest_completion_policy(),
        ),
        expected_assignment_revision: 3,
        finalized_anchor: test_pin_registry::ProviderIngestFinalizedAnchorV1 {
            height: ingest_completion_cursor().height,
            block_hash: ingest_completion_cursor().block_hash,
        },
    }
}
fn provider_ingest_completion_test_payload_with_executable(
    network_id: NetworkId,
    authority: AccountId,
    executable: Executable,
) -> TransactionPayload {
    TransactionBuilder::new(
        network_id,
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(executable)
    .into_payload()
    .expect("build provider-ingest completion payload")
}
fn provider_ingest_completion_test_payload(owner: AccountId) -> TransactionPayload {
    let completion = provider_ingest_completion_test_instruction(owner.clone());
    provider_ingest_completion_test_payload_with_executable(
        network_id(),
        owner,
        Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(completion)].into(),
        ),
    )
}
fn moderation_transaction_signer_test_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        IrohaRuntimeProviderSlotV1::ModerationTransactionSigner,
        SERVER_TEST_MODERATION_TRANSACTION_SIGNER_HANDLE,
        7,
        TEST_POLICY_DIGEST,
    )
    .with_network_id_for_test(network_id())
}
fn moderation_transaction_signer_test_payload() -> TransactionPayload {
    let public_key = ServerTestModerationTransactionSigner::keypair()
        .public_key()
        .clone();
    transaction_signer_test_payload_for_network(network_id(), AccountId::new(public_key))
}
fn moderation_transaction_signer_test_state(
    signer: Arc<dyn test_moderation_runtime::ModerationSignedTransactionSignerV1>,
) -> BrokerServerStateV1 {
    prepare_test_server_state(
        &moderation_transaction_signer_test_catalog(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_transaction_signer(signer),
    )
    .expect("prepare exact moderation transaction signer broker state")
}
fn moderation_delivery_test_handle(slot: IrohaRuntimeProviderSlotV1) -> &'static str {
    match slot {
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff => {
            SERVER_TEST_MODERATION_SETTLEMENT_HANDLE
        }
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff => {
            SERVER_TEST_MODERATION_PUBLICATION_HANDLE
        }
        IrohaRuntimeProviderSlotV1::ModerationPanelNotification => {
            SERVER_TEST_MODERATION_PANEL_HANDLE
        }
        _ => panic!("slot is not a moderation delivery boundary"),
    }
}
fn delivery_catalog(slot: IrohaRuntimeProviderSlotV1) -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        slot,
        moderation_delivery_test_handle(slot),
        7,
        TEST_POLICY_DIGEST,
    )
}
fn moderation_handoff_request(
    kind: test_moderation::ModerationTerminalHandoffKindV1,
) -> test_moderation_runtime::ModerationDurableHandoffRequestV1 {
    let actor_key = KeyPair::try_from_seed(vec![42; 32], Algorithm::Ed25519)
        .expect("derive moderation handoff actor");
    let mut handoff =
        test_moderation::ModerationTerminalHandoffV1 {
        handoff_id: [0; 32],
        network_id: network_id(),
        kind,
        case_id: "case-1".to_owned(),
        round_id: "round-1".to_owned(),
        outcome_digest: [0x32; 32],
        outcome_finalized_at_unix_ms: 7,
        finalized_cursor:
            test_moderation::ModerationFinalizedEventCursorV1 {
                sequence: 1,
                block_height: 7,
                block_hash: [0x44; 32],
                event_index: 0,
            },
        source_event_witness:
            test_moderation::ModerationFinalizedEventV1 {
                sequence: 1,
                block_height: 7,
                block_hash: [0x44; 32],
                event_index: 0,
                event: iroha_data_model::events::data::sorafs::
                    SorafsModerationLedgerEvent::new(
                        iroha_data_model::events::data::sorafs::
                            SorafsModerationLedgerEventKind::CaseFinalized,
                        Some("case-1".to_owned()),
                        Some("round-1".to_owned()),
                        AccountId::new(
                            actor_key.public_key().clone(),
                        ),
                        7,
                    ),
            },
    };
    handoff.handoff_id = handoff.canonical_id();
    let canonical_handoff =
        norito::to_bytes(&handoff).expect("encode canonical moderation handoff");
    test_moderation_runtime::ModerationDurableHandoffRequestV1 {
        handoff,
        canonical_handoff,
    }
}
fn moderation_panel_request() -> test_moderation_runtime::ModerationDurablePanelNotificationRequestV1
{
    let recipient_key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
        .expect("derive moderation panel recipient");
    let mut notification = test_moderation::ModerationPanelNotificationV1 {
        notification_id: [0; 32],
        network_id: network_id(),
        source_operation_id: [0x52; 32],
        scope_digest: [0x53; 32],
        kind: test_moderation::ModerationPanelNotificationKindV1::PrimaryAssignment,
        recipient: AccountId::new(recipient_key.public_key().clone()),
        finalized_event_cursor: test_moderation::ModerationFinalizedEventCursorV1 {
            sequence: 1,
            block_height: 7,
            block_hash: [0x54; 32],
            event_index: 0,
        },
        source_occurred_at_unix_ms: 1_000,
    };
    notification.notification_id = notification.canonical_id();
    let canonical_notification =
        norito::to_bytes(&notification).expect("encode canonical panel notification");
    test_moderation_runtime::ModerationDurablePanelNotificationRequestV1 {
        notification,
        canonical_notification,
        lease_expires_at_unix_ms: 2_000,
        attempt: 1,
        attempt_limit: 3,
    }
}
fn moderation_handoff_state(
    slot: IrohaRuntimeProviderSlotV1,
    boundary: Arc<dyn test_moderation_runtime::ModerationDurableHandoffBoundaryV1>,
) -> BrokerServerStateV1 {
    let backends = match slot {
        IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff => {
            RuntimeProviderBrokerBackendsV1::new().with_moderation_settlement_handoff(boundary)
        }
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff => {
            RuntimeProviderBrokerBackendsV1::new().with_moderation_publication_handoff(boundary)
        }
        _ => panic!("slot is not a moderation handoff boundary"),
    };
    prepare_test_server_state(&delivery_catalog(slot), backends)
        .expect("prepare exact moderation handoff broker state")
}
fn moderation_panel_state(
    boundary: Arc<dyn test_moderation_runtime::ModerationDurablePanelNotificationBoundaryV1>,
) -> BrokerServerStateV1 {
    prepare_test_server_state(
        &delivery_catalog(IrohaRuntimeProviderSlotV1::ModerationPanelNotification),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_panel_notification(boundary),
    )
    .expect("prepare exact moderation panel broker state")
}
fn moderation_delivery_request(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> OperationRequestV1 {
    make_operation_request(
        TEST_SESSION_ID,
        request_id,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        operation,
        payload,
    )
    .expect("build moderation delivery broker operation")
}
fn dispatch_moderation_delivery(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> Result<ScrubbedBytes, BrokerError> {
    let request = moderation_delivery_request(state, request_id, operation, payload);
    validate_operation_request(&request)?;
    dispatch_server_operation(state, &request)
}
fn checkpoint_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
        SERVER_TEST_CHECKPOINT_HANDLE,
        7,
        TEST_POLICY_DIGEST,
    )
}
fn moderation_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper,
        SERVER_TEST_MODERATION_HANDLE,
        7,
        TEST_POLICY_DIGEST,
    )
}
fn reputation_retention_server_test_catalog() -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority,
        SERVER_TEST_REPUTATION_RETENTION_HANDLE,
        7,
        TEST_POLICY_DIGEST,
    )
    .with_network_id_for_test(network_id())
}
fn reputation_runtime_test_handle(slot: IrohaRuntimeProviderSlotV1) -> &'static str {
    match slot {
        IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter => {
            SERVER_TEST_REPUTATION_JOURNAL_HANDLE
        }
        IrohaRuntimeProviderSlotV1::ReputationThresholdSigner => {
            SERVER_TEST_REPUTATION_THRESHOLD_HANDLE
        }
        IrohaRuntimeProviderSlotV1::ReputationGovernanceDag => {
            SERVER_TEST_REPUTATION_GOVERNANCE_HANDLE
        }
        IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint => {
            SERVER_TEST_REPUTATION_CHECKPOINT_HANDLE
        }
        _ => panic!("slot is not a reputation runtime provider"),
    }
}
fn reputation_catalog(slot: IrohaRuntimeProviderSlotV1) -> IrohaRuntimeProviderBindingsV1 {
    IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "server-test-chain",
        slot,
        reputation_runtime_test_handle(slot),
        if slot == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint {
            test_reputation::REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1
        } else {
            7
        },
        TEST_POLICY_DIGEST,
    )
}
include!("shared_fixture_support.rs");
include!("hedging_billing_domain_tests.rs");
#[derive(Debug)]
struct ServerTestBillingProvider {
    handle: &'static str,
    revision: u64,
}
impl ServerTestBillingProvider {
    fn exact(slot: IrohaRuntimeProviderSlotV1) -> Self {
        Self {
            handle: billing_runtime_test_handle(slot),
            revision: 7,
        }
    }
    const fn substituted() -> Self {
        Self {
            handle: "runtime://sorafs/billing/substituted-primary",
            revision: 7,
        }
    }
}
impl test_billing::HedgingBillingRuntimeProviderV1 for ServerTestBillingProvider {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_billing::HedgingBillingRuntimeProviderQualificationV1,
        test_billing::HedgingBillingRuntimeProviderReadinessErrorV1,
    > {
        Ok(
            test_billing::HedgingBillingRuntimeProviderQualificationV1::new(
                self.revision,
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_billing::HedgingBillingFinalizedQuery for ServerTestBillingProvider {
    fn identity(
        &self,
    ) -> Result<
        test_billing::HedgingBillingRuntimeAdapterIdentityV1,
        test_billing::HedgingBillingExternalError,
    > {
        Ok(test_billing::HedgingBillingRuntimeAdapterIdentityV1 {
            handle: self.handle.to_owned(),
        })
    }
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn supplies_period_closes(&self) -> bool {
        true
    }
    fn finalized_head(
        &self,
    ) -> Result<
        test_billing::HedgingBillingFinalizedCursorV1,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn query_finalized_page(
        &self,
        _position: test_billing::HedgingBillingQueryPositionV1,
        _max_events: u32,
    ) -> Result<
        Option<test_billing::HedgingBillingFinalizedEventPageV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn query_finalized_period_close(
        &self,
        _period_end_unix: u64,
        _position: test_billing::HedgingBillingQueryPositionV1,
    ) -> Result<
        Option<test_billing::HedgingBillingFinalizedPeriodCloseV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
impl test_billing::HedgingBillingJournalVerifier for ServerTestBillingProvider {
    fn identity(
        &self,
    ) -> Result<
        test_billing::HedgingBillingRuntimeAdapterIdentityV1,
        test_billing::HedgingBillingExternalError,
    > {
        Ok(test_billing::HedgingBillingRuntimeAdapterIdentityV1 {
            handle: self.handle.to_owned(),
        })
    }
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn verify_page(
        &self,
        _network_id: &iroha_data_model::NetworkId,
        _previous: Option<test_billing::HedgingBillingJournalCommitmentV1>,
        _page: &test_billing::HedgingBillingFinalizedEventPageV1,
    ) -> Result<(), test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn verify_period_close(
        &self,
        _network_id: &iroha_data_model::NetworkId,
        _close: &test_billing::HedgingBillingFinalizedPeriodCloseV1,
    ) -> Result<(), test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn verify_epoch_transition(
        &self,
        _network_id: &iroha_data_model::NetworkId,
        _transition: &test_billing::HedgingBillingEpochTransitionV1,
    ) -> Result<(), test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
impl test_billing::BillingStatementRuntimeSigner for ServerTestBillingProvider {
    fn identity(
        &self,
    ) -> Result<
        test_billing::BillingStatementSignerIdentityV1,
        test_billing::HedgingBillingExternalError,
    > {
        Ok(test_billing::BillingStatementSignerIdentityV1 {
            provider_handle: self.handle.to_owned(),
            signer_id: "billing-signer-primary".to_owned(),
            public_key: TEST_SIGNER_KEY,
        })
    }
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn sign_digest(
        &self,
        _digest: [u8; 32],
    ) -> Result<[u8; 64], test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
impl test_billing::BillingStatementPublisher for ServerTestBillingProvider {
    fn identity(
        &self,
    ) -> Result<
        test_billing::BillingStatementPublisherIdentityV1,
        test_billing::HedgingBillingExternalError,
    > {
        Ok(test_billing::BillingStatementPublisherIdentityV1 {
            provider_handle: self.handle.to_owned(),
            publisher_id: "billing-publisher-primary".to_owned(),
            route_id: "billing-publication-primary".to_owned(),
            public_key: TEST_SIGNER_KEY,
        })
    }
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn publish(
        &self,
        _idempotency_key: [u8; 32],
        _signed_statement_digest: [u8; 32],
        _statement: &test_billing::SignedGovernedBillingStatementV1,
    ) -> Result<
        test_billing::BillingStatementPublicationReceiptV1,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn lookup(
        &self,
        _statement_id: [u8; 32],
    ) -> Result<
        Option<test_billing::BillingStatementAuthoritativePublicationV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
impl test_billing::BillingStatementAcknowledgementAuthority for ServerTestBillingProvider {
    fn identity(
        &self,
    ) -> Result<
        test_billing::BillingStatementAcknowledgementAuthorityIdentityV1,
        test_billing::HedgingBillingExternalError,
    > {
        Ok(
            test_billing::BillingStatementAcknowledgementAuthorityIdentityV1 {
                provider_handle: self.handle.to_owned(),
            },
        )
    }
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn verify(
        &self,
        _statement: &test_billing::SignedGovernedBillingStatementV1,
        _acknowledgement: &test_billing::BillingStatementAcknowledgementV1,
    ) -> Result<(), test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn record(
        &self,
        _statement: &test_billing::SignedGovernedBillingStatementV1,
        _acknowledgement: &test_billing::BillingStatementAcknowledgementV1,
    ) -> Result<
        test_billing::BillingStatementAcknowledgementV1,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn lookup(
        &self,
        _statement_id: [u8; 32],
    ) -> Result<
        Option<test_billing::BillingStatementAcknowledgementV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
impl test_billing::HedgingBillingEpochWitnessStore for ServerTestBillingProvider {
    fn check_readiness(&self) -> Result<(), test_billing::HedgingBillingExternalError> {
        Ok(())
    }
    fn load_latest(
        &self,
    ) -> Result<
        Option<test_billing::HedgingBillingEpochWitnessRecordV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn load_epoch(
        &self,
        _epoch_sequence: u64,
    ) -> Result<
        Option<test_billing::HedgingBillingEpochWitnessRecordV1>,
        test_billing::HedgingBillingExternalError,
    > {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
    fn compare_and_swap_latest(
        &self,
        _expected_revision: Option<[u8; 32]>,
        _next: &test_billing::HedgingBillingEpochWitnessRecordV1,
    ) -> Result<(), test_billing::HedgingBillingExternalError> {
        Err(test_billing::HedgingBillingExternalError::Rejected)
    }
}
fn billing_runtime_backends(
    slot: IrohaRuntimeProviderSlotV1,
    substituted: bool,
) -> RuntimeProviderBrokerBackendsV1 {
    let provider = || {
        if substituted {
            Arc::new(ServerTestBillingProvider::substituted())
        } else {
            Arc::new(ServerTestBillingProvider::exact(slot))
        }
    };
    match slot {
        IrohaRuntimeProviderSlotV1::BillingFinalizedQuery => {
            RuntimeProviderBrokerBackendsV1::new().with_billing_finalized_query(provider())
        }
        IrohaRuntimeProviderSlotV1::BillingJournalVerifier => {
            RuntimeProviderBrokerBackendsV1::new().with_billing_journal_verifier(provider())
        }
        IrohaRuntimeProviderSlotV1::BillingStatementSigner => {
            RuntimeProviderBrokerBackendsV1::new().with_billing_statement_signer(provider())
        }
        IrohaRuntimeProviderSlotV1::BillingStatementPublisher => {
            RuntimeProviderBrokerBackendsV1::new().with_billing_statement_publisher(provider())
        }
        IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority => {
            RuntimeProviderBrokerBackendsV1::new()
                .with_billing_acknowledgement_authority(provider())
        }
        IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore => {
            RuntimeProviderBrokerBackendsV1::new().with_billing_epoch_witness_store(provider())
        }
        _ => panic!("slot is not a hedging/billing runtime provider"),
    }
}
fn reputation_backends(slot: IrohaRuntimeProviderSlotV1) -> RuntimeProviderBrokerBackendsV1 {
    match slot {
        IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_journal_transaction_submitter(
                Arc::new(ServerTestReputationJournalSubmitter::exact()),
            )
        }
        IrohaRuntimeProviderSlotV1::ReputationThresholdSigner => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_threshold_signer(Arc::new(
                ServerTestReputationThresholdSigner::exact(),
            ))
        }
        IrohaRuntimeProviderSlotV1::ReputationGovernanceDag => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_governance_dag(Arc::new(
                ServerTestReputationGovernanceDag::exact(),
            ))
        }
        IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_journal_checkpoint(Arc::new(
                ServerTestReputationJournalCheckpoint::exact(),
            ))
        }
        _ => panic!("slot is not a reputation runtime provider"),
    }
}
fn reputation_runtime_substituted_backends(
    slot: IrohaRuntimeProviderSlotV1,
) -> RuntimeProviderBrokerBackendsV1 {
    match slot {
        IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_journal_transaction_submitter(
                Arc::new(ServerTestReputationJournalSubmitter::substituted()),
            )
        }
        IrohaRuntimeProviderSlotV1::ReputationThresholdSigner => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_threshold_signer(Arc::new(
                ServerTestReputationThresholdSigner::substituted(),
            ))
        }
        IrohaRuntimeProviderSlotV1::ReputationGovernanceDag => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_governance_dag(Arc::new(
                ServerTestReputationGovernanceDag::substituted(),
            ))
        }
        IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint => {
            RuntimeProviderBrokerBackendsV1::new().with_reputation_journal_checkpoint(Arc::new(
                ServerTestReputationJournalCheckpoint::substituted(),
            ))
        }
        _ => panic!("slot is not a reputation runtime provider"),
    }
}
#[derive(Debug)]
struct ServerTestReputationJournalSubmitter {
    handle: &'static str,
    revision: AtomicU64,
    drift_after_operation: bool,
    submit_calls: AtomicU64,
}
impl ServerTestReputationJournalSubmitter {
    const fn exact() -> Self {
        Self {
            handle: SERVER_TEST_REPUTATION_JOURNAL_HANDLE,
            revision: AtomicU64::new(7),
            drift_after_operation: false,
            submit_calls: AtomicU64::new(0),
        }
    }
    const fn drifting_after_operation() -> Self {
        Self {
            drift_after_operation: true,
            ..Self::exact()
        }
    }
    const fn substituted() -> Self {
        Self {
            handle: "queue://sorafs/reputation/journal-substitute",
            ..Self::exact()
        }
    }
    fn finish_operation(&self) {
        if self.drift_after_operation {
            self.revision.store(8, Ordering::SeqCst);
        }
    }
}
impl test_reputation::ReputationRuntimeProviderV1 for ServerTestReputationJournalSubmitter {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_reputation::ReputationRuntimeProviderQualificationV1,
        test_reputation::ReputationExternalFailureV1,
    > {
        Ok(
            test_reputation::ReputationRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::SeqCst),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_reputation::ReputationJournalTransactionSubmitterV1
    for ServerTestReputationJournalSubmitter
{
    fn supports_authority(&self, _authority: &AccountId) -> bool {
        self.finish_operation();
        true
    }
    fn submit(
        &self,
        _request: &test_reputation::ReputationJournalTransactionRequestV1,
    ) -> test_reputation::ReputationJournalTransactionSubmitOutcomeV1 {
        self.submit_calls.fetch_add(1, Ordering::SeqCst);
        self.finish_operation();
        test_reputation::ReputationJournalTransactionSubmitOutcomeV1::Queued {
            receipt: [0x81; 32],
        }
    }
}
#[derive(Debug)]
struct ServerTestReputationThresholdSigner {
    handle: &'static str,
    revision: AtomicU64,
    drift_after_operation: bool,
    reconciled_keys: Mutex<Vec<[u8; 32]>>,
}
impl ServerTestReputationThresholdSigner {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_REPUTATION_THRESHOLD_HANDLE,
            revision: AtomicU64::new(7),
            drift_after_operation: false,
            reconciled_keys: Mutex::new(Vec::new()),
        }
    }
    fn drifting_after_operation() -> Self {
        Self {
            drift_after_operation: true,
            ..Self::exact()
        }
    }
    fn substituted() -> Self {
        Self {
            handle: "software://sorafs/reputation/substitute",
            ..Self::exact()
        }
    }
}
impl test_reputation::ReputationRuntimeProviderV1 for ServerTestReputationThresholdSigner {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_reputation::ReputationRuntimeProviderQualificationV1,
        test_reputation::ReputationExternalFailureV1,
    > {
        Ok(
            test_reputation::ReputationRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::SeqCst),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_reputation::ReputationThresholdSignerClientV1 for ServerTestReputationThresholdSigner {
    fn reconcile_signature(
        &self,
        request: &test_reputation::ReputationThresholdSigningRequestV1,
    ) -> Result<
        Option<test_reputation_signed::SignedReputationSnapshotV1>,
        test_reputation::ReputationExternalFailureV1,
    > {
        self.reconciled_keys
            .lock()
            .expect("threshold reconciled-key lock")
            .push(request.idempotency_key);
        if self.drift_after_operation {
            self.revision.store(8, Ordering::SeqCst);
        }
        Ok(None)
    }
}
#[derive(Debug)]
struct ServerTestReputationGovernanceDag {
    handle: &'static str,
    revision: AtomicU64,
    drift_after_operation: bool,
    reconciled_keys: Mutex<Vec<[u8; 32]>>,
}
impl ServerTestReputationGovernanceDag {
    fn exact() -> Self {
        Self {
            handle: SERVER_TEST_REPUTATION_GOVERNANCE_HANDLE,
            revision: AtomicU64::new(7),
            drift_after_operation: false,
            reconciled_keys: Mutex::new(Vec::new()),
        }
    }
    fn drifting_after_operation() -> Self {
        Self {
            drift_after_operation: true,
            ..Self::exact()
        }
    }
    fn substituted() -> Self {
        Self {
            handle: "dag://sorafs/reputation/publication-substitute",
            ..Self::exact()
        }
    }
}
impl test_reputation::ReputationRuntimeProviderV1 for ServerTestReputationGovernanceDag {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_reputation::ReputationRuntimeProviderQualificationV1,
        test_reputation::ReputationExternalFailureV1,
    > {
        Ok(
            test_reputation::ReputationRuntimeProviderQualificationV1::new(
                self.revision.load(Ordering::SeqCst),
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_reputation::ReputationGovernanceDagClientV1 for ServerTestReputationGovernanceDag {
    fn reconcile_publication(
        &self,
        request: &test_reputation::ReputationGovernanceDagPublicationRequestV1,
    ) -> Result<
        Option<test_reputation::ReputationGovernanceDagReadbackV1>,
        test_reputation::ReputationExternalFailureV1,
    > {
        self.reconciled_keys
            .lock()
            .expect("governance reconciled-key lock")
            .push(request.idempotency_key);
        if self.drift_after_operation {
            self.revision.store(8, Ordering::SeqCst);
        }
        Ok(None)
    }
}
#[derive(Debug)]
struct ServerTestReputationJournalCheckpoint {
    handle: &'static str,
}
impl ServerTestReputationJournalCheckpoint {
    const fn exact() -> Self {
        Self {
            handle: SERVER_TEST_REPUTATION_CHECKPOINT_HANDLE,
        }
    }
    const fn substituted() -> Self {
        Self {
            handle: "sealed://sorafs/reputation/checkpoint-substitute",
        }
    }
}
impl test_reputation::ReputationRuntimeProviderV1 for ServerTestReputationJournalCheckpoint {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        test_reputation::ReputationRuntimeProviderQualificationV1,
        test_reputation::ReputationExternalFailureV1,
    > {
        Ok(
            test_reputation::ReputationRuntimeProviderQualificationV1::new(
                test_reputation::REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                TEST_POLICY_DIGEST,
            ),
        )
    }
}
impl test_reputation::ReputationJournalCheckpointRuntimeV1
    for ServerTestReputationJournalCheckpoint
{
    fn load_latest(
        &self,
    ) -> Result<
        Option<test_reputation::ReputationJournalSealedCheckpointRecordV1>,
        test_reputation::ReputationJournalCheckpointExternalErrorV1,
    > {
        Ok(None)
    }
    fn compare_and_swap_latest(
        &self,
        _expected_revision: Option<[u8; 32]>,
        _next: &test_reputation::ReputationJournalSealedCheckpointRecordV1,
    ) -> Result<(), test_reputation::ReputationJournalCheckpointExternalErrorV1> {
        Err(test_reputation::ReputationJournalCheckpointExternalErrorV1::Rejected)
    }
}
fn reputation_snapshot() -> test_reputation_signed::SignedReputationSnapshotV1 {
    let scoring_evidence = test_reputation_signed::ReputationScoringEvidenceV1 {
        version: test_reputation_signed::REPUTATION_SCORING_EVIDENCE_VERSION_V1,
        provider_inputs: vec![sorafs_manifest::reputation::ReputationProviderInputV1 {
            version: sorafs_manifest::reputation::REPUTATION_PROVIDER_INPUT_VERSION_V1,
            provider_id: "provider-a".to_owned(),
            metrics: sorafs_manifest::reputation::ReputationProviderMetricsV1 {
                version: sorafs_manifest::reputation::REPUTATION_PROVIDER_METRICS_VERSION_V1,
                por_success_bps: 9_800,
                pdp_success_bps: 9_700,
                potr_success_bps: 9_600,
                latency_health_bps: 9_500,
                dispute_rate_bps: 0,
                token_violation_rate_bps: 0,
                repair_breach_rate_bps: 0,
            },
            reserve_stage: sorafs_manifest::reputation::ReputationReserveStageV1::Active,
            previous_score_bps: None,
            active_dispute: false,
            slashing_event: false,
        }],
        trust_edges: Vec::new(),
    };
    let snapshot = sorafs_manifest::reputation::build_reputation_snapshot(
        [0x91; 16],
        1_700_000_000,
        sorafs_manifest::reputation::ReputationWeightsV1::default(),
        &scoring_evidence.provider_inputs,
        None,
    )
    .expect("build reputation broker snapshot");
    let scoring_evidence_digest = scoring_evidence
        .canonical_digest()
        .expect("digest reputation broker evidence");
    let policy_digest = [0x92; 32];
    let signing_digest = test_reputation_signed::snapshot_signing_digest(
        &snapshot,
        policy_digest,
        scoring_evidence_digest,
    )
    .expect("digest reputation broker snapshot");
    let keypair = KeyPair::try_from_seed(vec![0x93; 32], Algorithm::Ed25519)
        .expect("derive reputation broker signer");
    let signature = Signature::new(keypair.private_key(), &signing_digest);
    let signature: [u8; 64] = signature
        .payload()
        .try_into()
        .expect("Ed25519 signature length");
    test_reputation_signed::SignedReputationSnapshotV1 {
        version: test_reputation_signed::SIGNED_REPUTATION_SNAPSHOT_VERSION_V1,
        policy_digest,
        snapshot,
        scoring_evidence_digest,
        scoring_evidence,
        signatures: vec![test_reputation_signed::ReputationSnapshotSignatureV1 {
            signer_id: "threshold-a".to_owned(),
            signature,
        }],
    }
}
fn threshold_request() -> test_reputation::ReputationThresholdSigningRequestV1 {
    let signed = reputation_snapshot();
    let snapshot_signing_digest = signed
        .signing_digest()
        .expect("digest signed reputation snapshot");
    let target_finalized = node::reputation::ReputationFinalizedIdentityV1 {
        height: 10,
        block_hash: [0x94; 32],
    };
    let material = node::reputation::ReputationUnsignedSigningMaterialV1 {
        version: node::reputation::REPUTATION_UNSIGNED_MATERIAL_VERSION_V1,
        network_id: network_id(),
        ingest_policy_digest: [0x95; 32],
        snapshot_trust_policy_digest: signed.policy_digest,
        window_start_height: 1,
        window_end_height: target_finalized.height,
        target_finalized,
        target_finalized_at_unix_ms: 1_700_000_000_000,
        source_finality: vec![node::reputation::ReputationSourceFinalityV1 {
            source: node::reputation::ReputationSourceV1::Proof,
            observed_through: target_finalized,
            last_event: None,
        }],
        scoring_evidence: signed.scoring_evidence.clone(),
        scoring_evidence_digest: signed.scoring_evidence_digest,
        snapshot: signed.snapshot,
        snapshot_signing_digest,
    };
    let material_digest = reputation_hash_canonical(
        b"sorafs-reputation-unsigned-material-delivery-v1",
        &material,
    )
    .expect("digest reputation threshold material");
    let idempotency_key = reputation_publication_idempotency_key(
        b"sorafs-reputation-threshold-signing-operation-v1",
        1,
        material_digest,
        None,
    )
    .expect("derive reputation threshold idempotency key");
    test_reputation::ReputationThresholdSigningRequestV1 {
        sequence: 1,
        material_digest,
        idempotency_key,
        material,
    }
}
fn governance_request() -> test_reputation::ReputationGovernanceDagPublicationRequestV1 {
    let signed_result = reputation_snapshot();
    let canonical_signed_result = signed_result
        .canonical_bytes()
        .expect("encode signed reputation snapshot");
    let signed_result_digest = reputation_signed_result_digest(&canonical_signed_result)
        .expect("digest signed reputation result");
    let material_digest = [0x96; 32];
    let idempotency_key = reputation_publication_idempotency_key(
        b"sorafs-reputation-governance-publication-operation-v1",
        1,
        material_digest,
        Some(signed_result_digest),
    )
    .expect("derive reputation Governance DAG idempotency key");
    test_reputation::ReputationGovernanceDagPublicationRequestV1 {
        sequence: 1,
        material_digest,
        signed_result_digest,
        idempotency_key,
        signed_result,
        canonical_signed_result,
    }
}
fn reputation_request(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> OperationRequestV1 {
    make_operation_request(
        TEST_SESSION_ID,
        request_id,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        operation,
        payload,
    )
    .expect("build reputation broker operation")
}
fn server_test_backends() -> RuntimeProviderBrokerBackendsV1 {
    RuntimeProviderBrokerBackendsV1::new()
        .with_governance_dag_signer(Arc::new(ServerTestGovernanceSigner))
}
fn request_auth_backends() -> RuntimeProviderBrokerBackendsV1 {
    RuntimeProviderBrokerBackendsV1::new().with_governance_dag_ipfs_authenticator(Arc::new(
        ServerTestGovernanceRequestAuthenticator::exact(),
    ))
}
fn proof_native_signer_test_state(
    signer: Arc<dyn iroha_torii::SoraFsProofOutcomeTransactionSigner>,
) -> BrokerServerStateV1 {
    prepare_test_server_state(
        &signer_catalog(),
        RuntimeProviderBrokerBackendsV1::new().with_proof_outcome_transaction_signer(signer),
    )
    .expect("prepare exact proof-outcome signer broker state")
}
fn request_auth_server_test_state() -> BrokerServerStateV1 {
    prepare_test_server_state(&request_auth_catalog(), request_auth_backends())
        .expect("prepare exact request-auth broker state")
}
fn canonical_request_auth_test_request(
    scope: node::GovernanceDagAuthenticationScope,
) -> node::GovernanceDagCanonicalRequestV1 {
    node::GovernanceDagCanonicalRequestV1::try_new(
        scope,
        "POST",
        "https://kubo.example/api/v0/dag/put?pin=true",
        vec![
            node::GovernanceDagCanonicalRequestHeaderV1::try_new(
                "content-type",
                "application/vnd.ipld.car",
            )
            .expect("canonical request-auth header"),
        ],
        4,
        *blake3::hash(b"body").as_bytes(),
        1024,
    )
    .expect("canonical request-auth descriptor")
}
fn checkpoint_state(
    store: Arc<dyn node::GovernanceDagSealedCheckpointStore>,
) -> BrokerServerStateV1 {
    prepare_test_server_state(
        &checkpoint_catalog(),
        RuntimeProviderBrokerBackendsV1::new().with_governance_dag_checkpoint_store(store),
    )
    .expect("prepare exact checkpoint broker state")
}
fn moderation_state(
    key_wrapper: Arc<dyn node::ModerationQuarantineKeyWrapper>,
) -> BrokerServerStateV1 {
    prepare_test_server_state(
        &moderation_catalog(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_quarantine_key_wrapper(key_wrapper),
    )
    .expect("prepare exact moderation quarantine broker state")
}
fn checkpoint_operation_request(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> OperationRequestV1 {
    make_operation_request(
        TEST_SESSION_ID,
        request_id,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        operation,
        payload,
    )
    .expect("build checkpoint broker operation")
}
fn dispatch_checkpoint(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> Result<ScrubbedBytes, BrokerError> {
    let request = checkpoint_operation_request(state, request_id, operation, payload);
    validate_operation_request(&request)?;
    dispatch_server_operation(state, &request)
}
fn dispatch_moderation(
    state: &BrokerServerStateV1,
    request_id: u64,
    operation: u16,
    payload: Vec<u8>,
) -> Result<ScrubbedBytes, BrokerError> {
    let request = make_operation_request(
        TEST_SESSION_ID,
        request_id,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        operation,
        payload,
    )
    .expect("build moderation quarantine broker operation");
    validate_operation_request(&request)?;
    dispatch_server_operation(state, &request)
}
fn compare_payload(
    slot: node::GovernanceDagSealedStateSlot,
    expected_revision: Option<[u8; 32]>,
    next: &node::GovernanceDagSealedStateRecord,
) -> Vec<u8> {
    encode_canonical(
        &SealedCompareAndSwapRequestWireV1 {
            slot: sealed_slot_to_wire(slot),
            expected_revision,
            next: SealedRecordWireV1 {
                generation: next.generation,
                revision: next.revision,
                payload: next.payload.clone(),
            },
        },
        MAX_OPERATION_FRAME_BYTES_V1,
    )
    .expect("encode sealed compare-and-swap request")
}
fn delete_payload(
    slot: node::GovernanceDagSealedStateSlot,
    expected_revision: [u8; 32],
) -> Vec<u8> {
    encode_canonical(
        &SealedDeleteRequestWireV1 {
            slot: sealed_slot_to_wire(slot),
            expected_revision,
        },
        MAX_OPERATION_FRAME_BYTES_V1,
    )
    .expect("encode sealed delete request")
}
fn signer_binding() -> ProviderBindingWireV1 {
    ProviderBindingWireV1 {
        slot: IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id(),
        handle: "software://sorafs/governance-dag/primary".to_owned(),
        revision: Some(7),
        policy_digest: Some(TEST_POLICY_DIGEST),
        bootle_lantern_issuance_bindings: None,
        stream_token_signer_binding: None,
        appeal_finance_signer_binding: None,
        appeal_finance_checkpoint_binding: None,
        appeal_finance_checkpoint_max_bytes: None,
        pop_credential_runtime_binding: None,
        por_replay_archive_binding: None,
        por_replay_archive_proof_limits: None,
        potr_runtime_binding: None,
        native_signer_binding: None,
        governance_dag_publisher_peer_id: Some(b"12D3KooWRuntimeBrokerPrimary".to_vec()),
        governance_dag_publisher_public_key: Some(TEST_SIGNER_KEY),
        governance_request_ingress_binding: None,
        provider_ingest_signer_binding: None,
        provider_ingest_source_limits: None,
        provider_ingest_checkpoint_max_bytes: None,
        provider_ingest_max_signed_transaction_bytes: None,
        evidence_viewer_webauthn_binding: None,
        evidence_viewer_grant_ttl_ms: None,
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_transparency_publisher_public_key: None,
        evidence_viewer_checkpoint_max_bytes: None,
        moderation_checkpoint_max_bytes: None,
        moderation_checkpoint_attestation_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        evidence_viewer_archive_max_bytes: None,
        moderation_panel_notification_archive_binding: None,
    }
}
fn token_signer_binding() -> ProviderBindingWireV1 {
    let signer_backend = stream_token_signer_test_support::signer_binding();
    let mut binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::StreamTokenSigner,
        &signer_backend.custody().runtime_handle,
    );
    binding.revision = Some(signer_backend.custody().key_revision);
    binding.policy_digest = Some(signer_backend.custody().policy_digest);
    binding.stream_token_signer_binding = Some(signer_backend);
    binding
}
fn runtime_binding(slot: IrohaRuntimeProviderSlotV1, handle: &str) -> ProviderBindingWireV1 {
    let mut binding = signer_binding();
    binding.slot = slot.wire_id();
    binding.handle = handle.to_owned();
    binding.governance_dag_publisher_peer_id = None;
    binding.governance_dag_publisher_public_key = None;
    binding
}
fn singleton_state(
    chain_id: &str,
    binding: ProviderBindingWireV1,
    observation: ProviderObservationWireV1,
    backends: RuntimeProviderBrokerBackendsV1,
) -> BrokerServerStateV1 {
    BrokerServerStateV1 {
        decode_pool: new_test_process_pool(),
        chain_id: chain_id.to_owned(),
        network_id: network_id(),
        catalog: vec![binding],
        observations: vec![observation],
        backends,
    }
}
fn bootle_bindings() -> test_privacy_issuance::BootleLanternIssuanceRuntimeProviderBindingsV1 {
    test_privacy_issuance::BootleLanternIssuanceRuntimeProviderBindingsV1::try_new(
        iroha_data_model::privacy::PrivacyIssuerIdV1::new([0x91; 32]),
        iroha_data_model::privacy::PrivacyPolicyIdV1::new([0x92; 32]),
        64,
    )
    .expect("valid Bootle/Lantern broker test bindings")
}
fn bootle_binding() -> ProviderBindingWireV1 {
    let exact = bootle_bindings();
    let mut binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry,
        SERVER_TEST_BOOTLE_LANTERN_HANDLE,
    );
    binding.bootle_lantern_issuance_bindings = Some(BootleLanternIssuanceBindingsWireV1 {
        issuer_id: *exact.issuer_id().as_bytes(),
        policy_id: *exact.policy_id().as_bytes(),
        authorization_lifetime_blocks: exact.authorization_lifetime_blocks(),
    });
    binding
}
fn bootle_lantern_test_state(backend: Arc<ServerTestBootleLanternBackend>) -> BrokerServerStateV1 {
    let binding = bootle_binding();
    let backends = RuntimeProviderBrokerBackendsV1::new().with_bootle_lantern_issuance(backend);
    let observation = make_server_observation(network_id(), &binding, &backends)
        .expect("observe exact Bootle/Lantern test backend");
    singleton_state("server-test-chain", binding, observation, backends)
}
fn bootle_state_auth(
    state: &BrokerServerStateV1,
    request_id: u64,
    opaque_credential: Vec<u8>,
) -> OperationRequestV1 {
    let payload = encode_canonical(
        &BootleLanternAuthenticateRequestWireV1 {
            opaque_credential,
            action: 1,
            request_binding: [0x96; 32],
            committed_height: 17,
        },
        MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
    )
    .expect("encode Bootle/Lantern state authentication request");
    make_operation_request(
        TEST_SESSION_ID,
        request_id,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1,
        payload,
    )
    .expect("build Bootle/Lantern state authentication operation")
}
fn bootle_auth(
    request_id: u64,
    binding: ProviderBindingWireV1,
    request: &BootleLanternAuthenticateRequestWireV1,
) -> OperationRequestV1 {
    let payload = encode_canonical(request, MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1)
        .expect("encode Bootle/Lantern authentication request");
    make_operation_request(
        TEST_SESSION_ID,
        request_id,
        binding,
        [0x93; 32],
        OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1,
        payload,
    )
    .expect("build Bootle/Lantern authentication operation")
}
#[test]
fn bootle_lantern_binding_rejects_slot_handle_qualification_and_metadata_substitution() {
    let binding = bootle_binding();
    validate_wire_binding(&binding).expect("accept exact slot-56 binding");
    let mut wrong = binding.clone();
    wrong.slot = IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id();
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong.handle = "test://privacy/bootle-lantern".to_owned();
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong.revision = Some(0);
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong.policy_digest = Some([0; 32]);
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong.bootle_lantern_issuance_bindings = None;
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong
        .bootle_lantern_issuance_bindings
        .as_mut()
        .expect("slot metadata")
        .issuer_id = [0; 32];
    assert!(validate_wire_binding(&wrong).is_err());
    let mut wrong = binding.clone();
    wrong
        .bootle_lantern_issuance_bindings
        .as_mut()
        .expect("slot metadata")
        .policy_id = [0; 32];
    assert!(validate_wire_binding(&wrong).is_err());
    for lifetime in [
        0,
        iroha_core_privacy::privacy_engines::bootle_lantern::issuer::
            MAX_BOOTLE_LANTERN_AUTHORIZATION_LIFETIME_BLOCKS_V1
            + 1,
    ] {
        let mut wrong = binding.clone();
        wrong
            .bootle_lantern_issuance_bindings
            .as_mut()
            .expect("slot metadata")
            .authorization_lifetime_blocks = lifetime;
        assert!(validate_wire_binding(&wrong).is_err());
    }
    let mut wrong = binding;
    wrong.evidence_viewer_grant_ttl_ms = Some(1);
    assert!(validate_wire_binding(&wrong).is_err());
}
#[test]
fn bootle_lantern_auth_rejects_action_body_height_and_canonical_wire_attacks() {
    let binding = bootle_binding();
    let valid = BootleLanternAuthenticateRequestWireV1 {
        opaque_credential: vec![0xA4; 32],
        action: 1,
        request_binding: [0xA5; 32],
        committed_height: 9,
    };
    let request = bootle_auth(1, binding.clone(), &valid);
    validate_operation_payload(&request, Some("server-test-chain"), &network_id())
        .expect("accept exact authentication payload");
    let mut invalid_requests = Vec::new();
    let mut invalid = valid.clone();
    invalid.action = 0;
    invalid_requests.push(invalid);
    let mut invalid = valid.clone();
    invalid.action = 3;
    invalid_requests.push(invalid);
    let mut invalid = valid.clone();
    invalid.opaque_credential.clear();
    invalid_requests.push(invalid);
    let mut invalid = valid.clone();
    invalid.request_binding = [0; 32];
    invalid_requests.push(invalid);
    let mut invalid = valid.clone();
    invalid.committed_height = 0;
    invalid_requests.push(invalid);
    let mut invalid = valid.clone();
    invalid.opaque_credential = vec![0xA4; MAX_BOOTLE_LANTERN_AUTH_CREDENTIAL_BYTES_V1 + 1];
    invalid_requests.push(invalid);
    for invalid in invalid_requests {
        let request = bootle_auth(2, binding.clone(), &invalid);
        assert!(validate_operation_payload(&request, None, &network_id()).is_err());
    }
    let mut wrong_slot = bootle_auth(3, binding.clone(), &valid);
    wrong_slot.binding.slot = IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id();
    assert!(validate_operation_payload(&wrong_slot, None, &network_id()).is_err());
    let mut wrong_operation = bootle_auth(4, binding, &valid);
    wrong_operation.operation = OPERATION_BOOTLE_LANTERN_ISSUANCE_PREPARE_AUTHORIZATION_V1;
    assert!(validate_operation_payload(&wrong_operation, None, &network_id()).is_err());
    let mut truncated = request.clone();
    truncated.payload.pop();
    assert!(validate_operation_payload(&truncated, None, &network_id()).is_err());
    let mut trailing = request;
    trailing.payload.push(0);
    assert!(validate_operation_payload(&trailing, None, &network_id()).is_err());
}
#[test]
fn bootle_lantern_auth_dispatch_requalifies_and_redacts_backend_failures() {
    let backend = Arc::new(ServerTestBootleLanternBackend::new(bootle_bindings()));
    let state = bootle_lantern_test_state(Arc::clone(&backend));
    let request = bootle_state_auth(&state, 1, vec![0x31; 32]);
    validate_operation_request(&request).expect("accept exact broker request");
    let result = dispatch_server_operation(&state, &request)
        .expect("authenticate through exact broker backend");
    let principal = decode_scrubbed_canonical::<BootleLanternAuthenticatedPrincipalWireV1>(
        &result,
        MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
    )
    .expect("decode exact authenticated principal");
    assert_eq!(principal.principal_digest, [0x95; 32]);
    assert_eq!(principal.issued_at_height, 17);
    assert_eq!(principal.expires_at_height, 21);
    let denied = bootle_state_auth(&state, 2, vec![0]);
    assert!(matches!(
        dispatch_server_operation(&state, &denied),
        Err(BrokerError::Rejected)
    ));
    let unavailable = bootle_state_auth(&state, 3, vec![u8::MAX]);
    assert!(matches!(
        dispatch_server_operation(&state, &unavailable),
        Err(BrokerError::Unavailable)
    ));
    backend
        .drift_after_authenticate
        .store(true, Ordering::Release);
    let drifted = bootle_state_auth(&state, 4, vec![0x32; 32]);
    assert!(matches!(
        dispatch_server_operation(&state, &drifted),
        Err(BrokerError::StaleOrRevoked)
    ));
}
#[test]
fn bootle_lantern_response_validation_rejects_operation_and_body_substitution() {
    let request = bootle_auth(
        1,
        bootle_binding(),
        &BootleLanternAuthenticateRequestWireV1 {
            opaque_credential: vec![0xB1; 16],
            action: 2,
            request_binding: [0xB2; 32],
            committed_height: 11,
        },
    );
    let result = encode_canonical(
        &BootleLanternAuthenticatedPrincipalWireV1 {
            principal_digest: [0xB3; 32],
            issued_at_height: 10,
            expires_at_height: 12,
        },
        MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1,
    )
    .expect("encode principal result");
    validate_operation_result(&request, STATUS_OK_V1, &result, &network_id())
        .expect("accept exact principal result");
    let substituted = encode_canonical(&[0xB4; 32], MAX_BOOTLE_LANTERN_ISSUANCE_FRAME_BYTES_V1)
        .expect("encode substituted digest result");
    assert!(
        validate_operation_result(&request, STATUS_OK_V1, &substituted, &network_id(),).is_err()
    );
    let mut truncated = result.clone();
    truncated.pop();
    assert!(validate_operation_result(&request, STATUS_OK_V1, &truncated, &network_id(),).is_err());
    let mut trailing = result.clone();
    trailing.push(0);
    assert!(validate_operation_result(&request, STATUS_OK_V1, &trailing, &network_id(),).is_err());
    assert!(
        validate_operation_result(&request, STATUS_REJECTED_V1, &result, &network_id(),).is_err()
    );
    let mut wrong_operation = request;
    wrong_operation.operation = OPERATION_BOOTLE_LANTERN_ISSUANCE_VALIDATE_REQUEST_V1;
    assert!(
        validate_operation_result(&wrong_operation, STATUS_OK_V1, &result, &network_id(),).is_err()
    );
}
#[test]
fn bootle_lantern_backend_set_rejects_drift_unavailability_and_substitution() {
    let binding = bootle_binding();
    let backend = Arc::new(ServerTestBootleLanternBackend::new(bootle_bindings()));
    let backends =
        RuntimeProviderBrokerBackendsV1::new().with_bootle_lantern_issuance(backend.clone());
    validate_exact_backend_set(std::slice::from_ref(&binding), &backends)
        .expect("accept exact slot-56 backend set");
    make_server_observation(network_id(), &binding, &backends)
        .expect("observe exact slot-56 backend");
    let mutations: [fn(&mut ProviderBindingWireV1); 4] = [
        |binding: &mut ProviderBindingWireV1| binding.revision = Some(8),
        |binding: &mut ProviderBindingWireV1| {
            binding.policy_digest = Some([0x72; 32]);
        },
        |binding: &mut ProviderBindingWireV1| {
            binding.handle = "runtime://sorafs/privacy/bootle-lantern-substituted".to_owned();
        },
        |binding: &mut ProviderBindingWireV1| {
            binding
                .bootle_lantern_issuance_bindings
                .as_mut()
                .expect("slot metadata")
                .issuer_id = [0x94; 32];
        },
    ];
    for mutate in mutations {
        let mut substituted = binding.clone();
        mutate(&mut substituted);
        assert!(make_server_observation(network_id(), &substituted, &backends).is_err());
    }
    backend.revision.store(8, Ordering::Release);
    assert!(make_server_observation(network_id(), &binding, &backends).is_err());
    backend.revision.store(7, Ordering::Release);
    backend.unavailable.store(true, Ordering::Release);
    assert!(make_server_observation(network_id(), &binding, &backends).is_err());
    backend.unavailable.store(false, Ordering::Release);
    assert!(
        validate_exact_backend_set(
            std::slice::from_ref(&binding),
            &RuntimeProviderBrokerBackendsV1::new(),
        )
        .is_err()
    );
    assert!(validate_exact_backend_set(&[], &backends).is_err());
}
fn appeal_finance_signer_test_state(
    signer: Arc<ServerTestAppealFinanceSigner>,
) -> BrokerServerStateV1 {
    let public_key = ServerTestAppealFinanceSigner::keypair()
        .public_key()
        .clone();
    let authority = AccountId::new(public_key.clone());
    let mut binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner,
        SERVER_TEST_APPEAL_FINANCE_SIGNER_HANDLE,
    );
    binding.appeal_finance_signer_binding = Some(AppealFinanceSignerBindingWireV1 {
        authority,
        public_key,
        valid_from_block_height: 1,
        revoked_at_block_height: None,
    });
    validate_wire_binding(&binding)
        .expect("accept exact appeal-finance transaction signer binding");
    let backends =
        RuntimeProviderBrokerBackendsV1::new().with_appeal_finance_transaction_signer(signer);
    let observation = make_server_observation(network_id(), &binding, &backends)
        .expect("observe exact appeal-finance transaction signer");
    singleton_state("server-test-chain", binding, observation, backends)
}
fn pop_runtime_binding() -> ProviderBindingWireV1 {
    let mut binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry,
        SERVER_TEST_POP_HANDLE,
    );
    binding.pop_credential_runtime_binding = Some(PopCredentialRuntimeBindingWireV1 {
        issuer_policy_digest: [0x81; 32],
        issuer_id: "pop-issuer-production-primary".to_owned(),
        issuer_signer_handle: "software://sorafs/pop-credentials/primary".to_owned(),
        issuer_public_key: test_auth_public_key(),
        enrollment_recipient_key_id: "kms:pop/enrollment:primary".to_owned(),
        enrollment_recipient_public_key_digest: [0x82; 32],
        wallet_recipient_key_id: "kms:pop/wallet-recipient:primary".to_owned(),
        wallet_recipient_public_key_digest: [0x83; 32],
        wallet_wrapping_key_id: "kms:pop/wallet:primary".to_owned(),
    });
    binding
}
fn replay_archive_binding() -> ProviderBindingWireV1 {
    let mut binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive,
        SERVER_TEST_POR_ARCHIVE_HANDLE,
    );
    binding.por_replay_archive_binding = Some(
        node::PorFinalizedReplayArchiveBindingV1::try_new(
            [0xB7; 32],
            7,
            TEST_POLICY_DIGEST,
            test_auth_public_key(),
        )
        .expect("valid replay-archive test binding"),
    );
    binding.por_replay_archive_proof_limits = Some(PorReplayArchiveProofLimitsWireV1 {
        max_successor_receipts: 1_024,
        max_successor_proof_bytes: 1_048_576,
    });
    binding
}
fn test_signature(payload: &[u8]) -> [u8; 64] {
    let signature = Signature::try_new(test_auth_keypair().private_key(), payload)
        .expect("sign replay-archive test payload");
    signature
        .payload()
        .try_into()
        .expect("Ed25519 signatures are exactly 64 bytes")
}
fn privacy_prf_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider,
        SERVER_TEST_PRIVACY_PRF_HANDLE,
    )
}
fn privacy_release_anchor_runtime_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor,
        SERVER_TEST_PRIVACY_RELEASE_ANCHOR_HANDLE,
    )
}
fn transparency_leader_lease_runtime_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::TransparencyLeaderLease,
        SERVER_TEST_TRANSPARENCY_LEADER_LEASE_HANDLE,
    )
}
fn privacy_publisher_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher,
        SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE,
    )
}
fn privacy_reader_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader,
        SERVER_TEST_FENCED_PRIVACY_PUBLISHER_HANDLE,
    )
}
fn sample_fenced_privacy_head_evidence() -> (
    node::FencedTransparencyTargetHeadV1,
    node::FencedTransparencyPublicationInclusionV1,
) {
    let head = node::FencedTransparencyTargetHeadV1::try_new(3, [0x6B; 32], 2)
        .expect("canonical fenced privacy target head");
    let publication =
        node::FencedTransparencyPublicationInclusionV1::try_new([0x6C; 32], [0x6D; 32], head)
            .expect("canonical fenced privacy publication inclusion");
    (head, publication)
}
fn fenced_request() -> node::FencedPrivacyPublicationRequestV1 {
    let query_id = [0x51; 32];
    let cycle_start_unix = 1_000;
    let cycle_end_unix = 2_000;
    let cycle_id = node::privacy_aggregate_cycle_id(query_id, cycle_start_unix, cycle_end_unix);
    let aggregate = sorafs_manifest::ModerationPrivacyAggregateV1 {
        version: sorafs_manifest::MODERATION_PRIVACY_AGGREGATE_VERSION_V1,
        aggregate_id: "sfm4c-runtime-broker-fenced-publication".to_owned(),
        window_start_unix: cycle_start_unix,
        window_end_unix: cycle_end_unix,
        generated_at_unix: cycle_end_unix,
        population_label: "runtime-broker-population".to_owned(),
        population_digest: [0x52; 32],
        source_commitment: [0x51; 32],
        privacy: sorafs_manifest::ModerationPrivacyParametersV1 {
            version: sorafs_manifest::MODERATION_PRIVACY_PARAMETERS_VERSION_V1,
            mode: sorafs_manifest::ModerationPrivacyModeV1::DifferentialPrivacyWithSuppression,
            epsilon_numerator: Some(4),
            epsilon_denominator: Some(5),
            delta_ppb: Some(0),
            per_subject_metric_cap: Some(1),
            suppression_threshold: Some(25),
        },
        noise_source: sorafs_manifest::ModerationPrivacyNoiseSourceV1::ThresholdPrf(
            sorafs_manifest::ModerationPrivacyThresholdPrfCommitmentV1 {
                commitment: [0x53; 32],
            },
        ),
        metrics: vec![sorafs_manifest::ModerationPrivacyAggregateMetricV1 {
            key: "moderation_actions".to_owned(),
            value: 7,
            unit: "count".to_owned(),
        }],
        policy_digest: [0x54; 32],
        metadata: vec![sorafs_manifest::ModerationLedgerMetadataV1 {
            key: "publisher".to_owned(),
            value: "runtime-broker".to_owned(),
        }],
    };
    let publication = sorafs_manifest::ModerationLedgerCyclePublicationV1 {
        version: sorafs_manifest::MODERATION_LEDGER_PUBLICATION_VERSION_V1,
        block: sorafs_manifest::ModerationLedgerBlockV1 {
            version: sorafs_manifest::MODERATION_LEDGER_BLOCK_VERSION_V1,
            cycle_id,
            cycle_start_unix,
            cycle_end_unix,
            generated_at_unix: cycle_end_unix,
            entry_count: 0,
            entry_root: [0x55; 32],
            previous_block_hash: None,
        },
        proofs: Vec::new(),
        privacy_aggregates: vec![aggregate],
    };
    let canonical_payload = norito::to_bytes(&publication).expect("encode fenced publication");
    let payload_digest = *blake3::hash(&canonical_payload).as_bytes();
    let scope = node::TransparencyLeaderLeaseScopeV1::try_new(
        query_id,
        node::PrivacyAggregateCycleWindow {
            cycle_start_unix,
            cycle_end_unix,
            due_at_unix: cycle_end_unix,
        },
        [0x56; 32],
    )
    .expect("canonical fenced-publication lease scope");
    let lease_binding = node::TransparencyRuntimeProviderBindingV1::try_new(
        "sealed-cas://sorafs/transparency/leader-primary",
        9,
        [0x57; 32],
    )
    .expect("canonical fenced-publication lease binding");
    let lease = node::TransparencyLeaderLeaseGrantV1::try_new(
        [0x58; 32],
        scope,
        1,
        cycle_end_unix,
        cycle_end_unix + 1_000,
        lease_binding,
    )
    .expect("canonical fenced-publication leader lease");
    let anchor = node::PrivacyReleaseAnchorHeadV1::try_from_parts(
        query_id,
        1,
        cycle_id,
        [0x59; 32],
        Some([0x5A; 32]),
    )
    .expect("canonical fenced-publication anchor");
    let authorization = node::PrivacyPublicationAuthorizationV1::try_from_runtime_parts(
        lease,
        anchor,
        1,
        [0x59; 32],
        payload_digest,
    )
    .expect("canonical fenced-publication authorization");
    node::FencedPrivacyPublicationRequestV1::try_new(
        authorization,
        &publication,
        canonical_payload,
        None,
        0,
    )
    .expect("canonical fenced publication request")
}
fn checkpoint_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore,
        "kms://governance/checkpoint-primary",
    )
}
fn moderation_binding() -> ProviderBindingWireV1 {
    runtime_binding(
        IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper,
        SERVER_TEST_MODERATION_HANDLE,
    )
}
fn evidence_viewer_binding(slot: IrohaRuntimeProviderSlotV1) -> ProviderBindingWireV1 {
    let mut binding = runtime_binding(
        slot,
        &format!("runtime://sorafs/evidence-viewer/slot-{}", slot.wire_id()),
    );
    match slot {
        IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn => {
            binding.evidence_viewer_webauthn_binding = Some(EvidenceViewerWebAuthnBindingWireV1 {
                rp_id: "review.example".to_owned(),
                allowed_origins: vec!["https://review.example".to_owned()],
                challenge_ttl_ms: 60_000,
            });
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority => {
            binding.evidence_viewer_grant_ttl_ms = Some(300_000);
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner => {
            binding.handle = "software://sorafs/evidence-viewer/primary".to_owned();
            binding.evidence_viewer_receipt_signer_public_key = Some(TEST_SIGNER_KEY);
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore => {
            binding.evidence_viewer_checkpoint_max_bytes = Some(64 * 1024 * 1024);
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive => {
            binding.evidence_viewer_archive_id = Some([0xC7; 32]);
            binding.evidence_viewer_archive_public_key = Some(TEST_SIGNER_KEY);
            binding.evidence_viewer_archive_max_bytes = Some(64 * 1024 * 1024 + 16 * 1024);
        }
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive => {
            binding.moderation_panel_notification_archive_binding =
                Some(ModerationPanelNotificationArchiveBindingWireV1 {
                    archive_id: [0xC8; 32],
                    bootstrap_public_key: TEST_SIGNER_KEY,
                    public_key: TEST_SIGNER_KEY,
                    max_bytes: 64 * 1024 * 1024 + 16 * 1024,
                    max_records: 4_096,
                });
        }
        IrohaRuntimeProviderSlotV1::ModerationCheckpointStore => {
            binding.moderation_checkpoint_max_bytes = Some(32 * 1024 * 1024);
            binding.moderation_checkpoint_attestation_public_key = Some(TEST_SIGNER_KEY);
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher => {
            binding.evidence_viewer_transparency_publisher_public_key = Some(TEST_SIGNER_KEY);
        }
        IrohaRuntimeProviderSlotV1::EvidenceViewerErasure => {}
        _ => panic!("not an evidence-viewer or moderation runtime slot"),
    }
    binding
}
fn observation(binding: &ProviderBindingWireV1) -> ProviderObservationWireV1 {
    let signer_metadata =
        if binding.slot == IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id() {
            Some(SignerMetadataWireV1 {
                publisher_peer_id: binding
                    .governance_dag_publisher_peer_id
                    .clone()
                    .expect("Governance signer binding peer ID"),
                public_key: binding
                    .governance_dag_publisher_public_key
                    .expect("Governance signer binding key"),
            })
        } else {
            None
        };
    let governance_request_ingress_qualification = matches!(
        binding.slot,
        slot if slot
            == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id()
    )
    .then(|| {
        let qualification = node::GovernanceDagRequestIngressQualificationV1::try_new(
            qualification_from_binding(binding).expect("test request-auth provider qualification"),
            governance_request_ingress_binding_from_provider_binding(binding)
                .expect("test request-auth ingress binding"),
            [0x91; 32],
            [0x92; 32],
            [0x93; 32],
        )
        .expect("test request-auth ingress qualification");
        governance_request_ingress_qualification_to_wire(qualification)
    });
    let moderation_quarantine_active_key_id = (binding.slot
        == IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id())
    .then(|| SERVER_TEST_MODERATION_KEY_ID.to_owned());
    let evidence_viewer_receipt_signer_public_key =
        if binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id() {
            binding.evidence_viewer_receipt_signer_public_key
        } else {
            None
        };
    let evidence_viewer_archive_id =
        if binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id() {
            binding.evidence_viewer_archive_id
        } else {
            None
        };
    let evidence_viewer_archive_public_key =
        if binding.slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id() {
            binding.evidence_viewer_archive_public_key
        } else {
            None
        };
    let moderation_panel_notification_archive_binding = if binding.slot
        == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
    {
        binding.moderation_panel_notification_archive_binding
    } else {
        None
    };
    let moderation_checkpoint_attestation_public_key =
        if binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id() {
            binding.moderation_checkpoint_attestation_public_key
        } else {
            None
        };
    ProviderObservationWireV1 {
        binding: binding.clone(),
        metadata_digest: provider_metadata_digest(
            &signer_metadata,
            &governance_request_ingress_qualification,
            &moderation_quarantine_active_key_id,
            &None,
            &[],
            &[],
            &evidence_viewer_receipt_signer_public_key,
            &evidence_viewer_archive_id,
            &evidence_viewer_archive_public_key,
            &moderation_checkpoint_attestation_public_key,
            &moderation_panel_notification_archive_binding,
        )
        .expect("encode test provider metadata"),
        signer_metadata,
        governance_request_ingress_qualification,
        moderation_quarantine_active_key_id,
        provider_ingest_signer_binding: None,
        provider_ingest_source_provider_ids: Vec::new(),
        potr_signer_public_key: Vec::new(),
        evidence_viewer_receipt_signer_public_key,
        evidence_viewer_archive_id,
        evidence_viewer_archive_public_key,
        moderation_checkpoint_attestation_public_key,
        moderation_panel_notification_archive_binding,
    }
}
fn metadata_digest(observed: &mut ProviderObservationWireV1) {
    observed.metadata_digest = provider_metadata_digest(
        &observed.signer_metadata,
        &observed.governance_request_ingress_qualification,
        &observed.moderation_quarantine_active_key_id,
        &observed.provider_ingest_signer_binding,
        &observed.provider_ingest_source_provider_ids,
        &observed.potr_signer_public_key,
        &observed.evidence_viewer_receipt_signer_public_key,
        &observed.evidence_viewer_archive_id,
        &observed.evidence_viewer_archive_public_key,
        &observed.moderation_checkpoint_attestation_public_key,
        &observed.moderation_panel_notification_archive_binding,
    )
    .expect("encode mutated test provider metadata");
}
fn assert_backend_fixture(
    binding: &ProviderBindingWireV1,
    backends: &RuntimeProviderBrokerBackendsV1,
    qualification_message: &str,
) {
    assert_eq!(
        validate_exact_backend_set(std::slice::from_ref(binding), backends),
        Ok(())
    );
    make_server_observation(network_id(), binding, backends).expect(qualification_message);
    assert_eq!(
        validate_exact_backend_set(&[], backends),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    );
    assert_eq!(
        validate_exact_backend_set(
            std::slice::from_ref(binding),
            &RuntimeProviderBrokerBackendsV1::new(),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    );
    let mut confused = binding.clone();
    confused.governance_request_ingress_binding = Some(governance_request_ingress_binding_to_wire(
        ingress_fixture(TEST_SIGNER_KEY),
    ));
    assert_eq!(
        validate_wire_binding(&confused),
        Err(BrokerError::BindingMismatch)
    );
}
fn validated_operation(
    binding: ProviderBindingWireV1,
    operation: u16,
    payload: Vec<u8>,
) -> OperationRequestV1 {
    let metadata_digest = observation(&binding).metadata_digest;
    let request = make_operation_request(
        TEST_SESSION_ID,
        u64::from(operation) + 1,
        binding,
        metadata_digest,
        operation,
        payload,
    )
    .expect("construct evidence-viewer operation");
    if matches!(
        operation,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1
            | OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1
    ) {
        validate_operation_request_for_session(&request, "server-test-chain", &network_id())
            .expect("validate chain-bound moderation archive operation");
    } else {
        validate_operation_request(&request).expect("validate evidence-viewer operation");
    }
    request
}
fn handshake_response(request: &HandshakeRequestV1) -> HandshakeResponseV1 {
    let observations = request
        .requested_catalog
        .iter()
        .map(observation)
        .collect::<Vec<_>>();
    let transcript = ServerTranscriptFieldsV1 {
        chain_id: request.chain_id.clone(),
        network_id: request.network_id,
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
        client_transcript_digest: request.client_transcript_digest,
        session_id: TEST_SESSION_ID,
        observations: observations.clone(),
    };
    HandshakeResponseV1 {
        chain_id: request.chain_id.clone(),
        network_id: request.network_id,
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
        client_transcript_digest: request.client_transcript_digest,
        session_id: TEST_SESSION_ID,
        observations,
        server_transcript_digest: server_transcript_digest(&transcript)
            .expect("seal test server transcript"),
    }
}
fn assert_valid_handshake_request(request: &HandshakeRequestV1) {
    assert_eq!(
        request.catalog_digest,
        catalog_digest(
            &request.chain_id,
            &request.network_id,
            &request.requested_catalog,
        )
        .expect("digest test requested catalog")
    );
    let transcript = HandshakeTranscriptFieldsV1 {
        chain_id: request.chain_id.clone(),
        network_id: request.network_id,
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
    };
    assert_eq!(
        request.client_transcript_digest,
        client_transcript_digest(&transcript).expect("digest test client transcript")
    );
}
fn operation_response(
    request: &OperationRequestV1,
    status: u8,
    result: Vec<u8>,
) -> OperationResponseV1 {
    let result_digest = operation_result_digest(&result);
    let fields = OperationResponseFieldsV1 {
        session_id: request.session_id,
        request_id: request.request_id,
        request_digest: request.request_digest,
        observed_binding: request.binding.clone(),
        provider_metadata_digest: request.provider_metadata_digest,
        operation: request.operation,
        payload_digest: request.payload_digest,
        status,
        result_digest,
        result_len: u64::try_from(result.len()).expect("test result length fits u64"),
    };
    OperationResponseV1 {
        session_id: fields.session_id,
        request_id: fields.request_id,
        request_digest: fields.request_digest,
        observed_binding: fields.observed_binding.clone(),
        provider_metadata_digest: fields.provider_metadata_digest,
        operation: fields.operation,
        payload_digest: fields.payload_digest,
        status: fields.status,
        result_digest: fields.result_digest,
        result,
        response_digest: operation_response_digest(&fields).expect("seal test operation response"),
    }
}
fn reseal_response(response: &mut OperationResponseV1) {
    let fields = OperationResponseFieldsV1 {
        session_id: response.session_id,
        request_id: response.request_id,
        request_digest: response.request_digest,
        observed_binding: response.observed_binding.clone(),
        provider_metadata_digest: response.provider_metadata_digest,
        operation: response.operation,
        payload_digest: response.payload_digest,
        status: response.status,
        result_digest: response.result_digest,
        result_len: u64::try_from(response.result.len()).expect("test result length fits u64"),
    };
    response.response_digest = operation_response_digest(&fields).expect("reseal test response");
}
fn start_broker(
    bindings: IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    diagnostics: [&'static str; 5],
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    let directory = new_broker_socket_test_directory();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect(diagnostics[1]);
    let path = directory.path().join("runtime-provider-broker-v1.sock");
    let policy = BrokerTestEndpoint::for_test(path.clone());
    let server_policy = policy.clone();
    let shutdown = Arc::new(RuntimeProviderBrokerLifecycleV1::new());
    let server_shutdown = Arc::clone(&shutdown);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        serve_test_process_with_lifecycle(
            &bindings,
            backends,
            &server_policy,
            server_shutdown,
            move || ready_sender.send(()).expect(diagnostics[2]),
        )
    });
    if let Err(error) = ready_receiver.recv_timeout(Duration::from_secs(2)) {
        assert!(
            error != mpsc::RecvTimeoutError::Disconnected,
            "{}: broker thread exited before readiness: {:?}",
            diagnostics[3],
            server.join(),
        );
        panic!("{}: {error}", diagnostics[3]);
    }
    endpoint_identity(&policy).expect(diagnostics[4]);
    (directory, path, policy, shutdown, server)
}
fn start_test_server() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    start_broker(
        server_test_catalog(),
        server_test_backends(),
        [
            "create broker server directory",
            "harden broker server directory",
            "publish broker readiness",
            "broker server reaches its ready callback",
            "ready broker endpoint remains pinned",
        ],
    )
}
fn start_request_auth_test_server() -> (
    tempfile::TempDir,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    let (directory, _, policy, shutdown, server) = start_broker(
        request_auth_catalog(),
        request_auth_backends(),
        [
            "create request-auth broker directory",
            "harden request-auth broker directory",
            "publish request-auth broker readiness",
            "request-auth broker reaches its ready callback",
            "ready request-auth endpoint remains pinned",
        ],
    );
    (directory, policy, shutdown, server)
}
fn start_signer(
    bindings: IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
) -> (
    tempfile::TempDir,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    let (directory, _, policy, shutdown, server) = start_broker(
        bindings,
        backends,
        [
            "create native signer broker directory",
            "harden native signer broker directory",
            "publish native signer broker readiness",
            "native signer broker reaches its ready callback",
            "ready native signer endpoint remains pinned",
        ],
    );
    (directory, policy, shutdown, server)
}
fn start_native_signer_test_server() -> (
    tempfile::TempDir,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    start_signer(native_signer_test_catalog(), native_signer_test_backends())
}
fn start_source_test_server(
    source: ServerTestProviderSource,
    bindings: IrohaRuntimeProviderBindingsV1,
) -> (
    tempfile::TempDir,
    BrokerTestEndpoint,
    Arc<RuntimeProviderBrokerLifecycleV1>,
    thread::JoinHandle<Result<(), RuntimeProviderBrokerServerErrorV1>>,
) {
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_provider_ingest_authenticated_source(Arc::new(source));
    let (directory, _, policy, shutdown, server) = start_broker(
        bindings,
        backends,
        [
            "create source broker directory",
            "harden source broker directory",
            "publish source broker readiness",
            "source broker reaches its ready callback",
            "ready source endpoint remains pinned",
        ],
    );
    (directory, policy, shutdown, server)
}
fn connect_test_source(
    policy: &BrokerTestEndpoint,
    bindings: &IrohaRuntimeProviderBindingsV1,
) -> Arc<ProviderIngestBrokerAuthenticatedSource> {
    let requested_catalog = bindings
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project source test catalog");
    let (session, observations) = connect_test_process(
        policy,
        bindings.chain_id(),
        *bindings.network_id(),
        requested_catalog.clone(),
    )
    .expect("connect source broker session");
    let binding = requested_catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id()
        })
        .expect("source binding")
        .clone();
    let observation = observations
        .iter()
        .find(|observation| observation.binding == binding)
        .expect("source observation");
    Arc::new(ProviderIngestBrokerAuthenticatedSource {
        session,
        endpoint: EndpointPolicy::clone(policy),
        chain_id: bindings.chain_id().to_owned(),
        requested_catalog,
        binding,
        metadata_digest: observation.metadata_digest,
        source_provider_ids: observation.provider_ingest_source_provider_ids.clone(),
    })
}
fn connect_test_server_session(policy: &BrokerTestEndpoint) -> Arc<BrokerSession> {
    let binding = signer_binding_for_server();
    let (session, _) =
        connect_test_process(policy, "server-test-chain", network_id(), vec![binding])
            .expect("connect authenticated broker server session");
    session
}
fn signer_binding_for_server() -> ProviderBindingWireV1 {
    let mut binding = signer_binding();
    binding.handle = SERVER_TEST_SIGNER_HANDLE.to_owned();
    binding.governance_dag_publisher_peer_id = Some(b"12D3KooWRuntimeBrokerServerPrimary".to_vec());
    binding
}
include!("server_source_tests.rs");
include!("codec_signer_tests.rs");
include!("native_role_authorization_tests.rs");

include!("stream_token_signer_test_support.rs");
