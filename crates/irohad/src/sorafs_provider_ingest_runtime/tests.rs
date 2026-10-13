use super::*;
use iroha_config_base::util::Bytes;
use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    isi::InstructionBox,
    musubi::{
        ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiContentDigestV1,
        MusubiProviderBundleVerificationApprovalV1, MusubiProviderBundleVerificationBindingV1,
        MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1,
    },
    sorafs::pin_registry::ProviderIngestCompletionAuthorityV1,
};
use sorafs_node::provider_ingest_runtime::{
    ProviderIngestAuthenticatedProviderSourceV1, ProviderIngestAuthenticatedSourceBindingV1,
    ProviderIngestAuthenticatedSourceRegistrationV1, ProviderIngestMusubiArchiveFetchBindingV1,
    ProviderIngestSourceQualificationV1,
};
mod quarantine_restart;
#[test]
fn completed_musubi_capture_composer_has_one_concrete_inert_shape() {
    let composer: fn(
        &NodeHandle,
        &mut PreparedProviderIngestFinalizedArchiveV1,
        NetworkId,
        usize,
    ) -> Result<ProviderIngestCompletedMusubiCaptureCoordinatorV1> =
        compose_inert_completed_musubi_capture_coordinator_v1;
    let _ = composer;
    let source = include_str!("../sorafs_provider_ingest_runtime.rs");
    let start = source
        .find("pub(crate) fn compose_inert_completed_musubi_capture_coordinator_v1")
        .expect("concrete inert capture composer");
    let body = &source[start..source.len().min(start.saturating_add(1_600))];
    assert!(body.contains("prepared.take_signed_capture_reader()"));
    assert!(body.contains("take_provider_ingest_completed_musubi_capture_coordinator"));
    assert!(!body.contains("try_activate"));
    assert!(!body.contains("read_signed_completed_musubi_capture_page"));
}
#[test]
fn completed_musubi_attestation_driver_composer_remains_inert_and_open_only() {
    // The composer remains effect-free; native supervision owns the subsequent drive loop.
    let _ = compose_inert_completed_musubi_attestation_driver_v1;
    let source = include_str!("../sorafs_provider_ingest_runtime.rs");
    let start = source
        .find("pub(crate) fn compose_inert_completed_musubi_attestation_driver_v1")
        .expect("inert effect-pump composer");
    let body = &source[start..source.len().min(start.saturating_add(3_500))];
    assert!(body.contains("bind_provider_ingest_completed_musubi_attestation_driver_v1"));
    assert!(body.contains("GovernedMusubiProviderAttestationSignerV1::new"));
    assert!(body.contains("GovernedMusubiProviderAttestationInventoryV1::new"));
    assert!(!body.contains("initialize_journal_runtime"));
    assert!(!body.contains("drive_one_bounded_page"));
    let main = include_str!("../main.rs");
    assert!(!main.contains("compose_inert_completed_musubi_attestation_driver_v1"));
}
#[derive(Debug)]
struct TestClockV1 {
    now: Mutex<Instant>,
}
impl TestClockV1 {
    fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
        }
    }
    fn now(&self) -> Instant {
        *self.now.lock().expect("test clock lock")
    }
    fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("test clock lock");
        *now = now.checked_add(duration).expect("test clock advance");
    }
}
#[derive(Debug)]
enum TestTerminalBehaviorV1 {
    Eof,
    Error {
        kind: io::ErrorKind,
        message: &'static str,
    },
    ExtraByte(u8),
    AdvancingEof {
        clock: Arc<TestClockV1>,
        advance: Duration,
    },
}
struct TestTerminalReaderV1 {
    payload: Vec<u8>,
    offset: usize,
    terminal_behavior: TestTerminalBehaviorV1,
    terminal_probe_count: Arc<AtomicU64>,
    terminal_probe_width: Arc<AtomicU64>,
}
impl TestTerminalReaderV1 {
    fn new(
        payload: impl Into<Vec<u8>>,
        terminal_behavior: TestTerminalBehaviorV1,
    ) -> (Self, Arc<AtomicU64>, Arc<AtomicU64>) {
        let terminal_probe_count = Arc::new(AtomicU64::new(0));
        let terminal_probe_width = Arc::new(AtomicU64::new(0));
        (
            Self {
                payload: payload.into(),
                offset: 0,
                terminal_behavior,
                terminal_probe_count: Arc::clone(&terminal_probe_count),
                terminal_probe_width: Arc::clone(&terminal_probe_width),
            },
            terminal_probe_count,
            terminal_probe_width,
        )
    }
}
impl Read for TestTerminalReaderV1 {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset < self.payload.len() {
            let copied = output.len().min(self.payload.len() - self.offset);
            output[..copied].copy_from_slice(&self.payload[self.offset..self.offset + copied]);
            self.offset += copied;
            return Ok(copied);
        }
        self.terminal_probe_count.fetch_add(1, Ordering::SeqCst);
        self.terminal_probe_width.store(
            u64::try_from(output.len()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        match &self.terminal_behavior {
            TestTerminalBehaviorV1::Eof => Ok(0),
            TestTerminalBehaviorV1::Error { kind, message } => Err(io::Error::new(*kind, *message)),
            TestTerminalBehaviorV1::ExtraByte(byte) => {
                output[0] = *byte;
                Ok(1)
            }
            TestTerminalBehaviorV1::AdvancingEof { clock, advance } => {
                clock.advance(*advance);
                Ok(0)
            }
        }
    }
}
#[derive(Clone)]
struct TestOwnerAuthorityV1 {
    authority: Arc<Mutex<ProviderIngestCompletionAuthorityV1>>,
}
impl TestOwnerAuthorityV1 {
    fn new(owner: AccountId, policy: ProviderIngestCompletionSignerPolicyV1) -> Self {
        Self {
            authority: Arc::new(Mutex::new(ProviderIngestCompletionAuthorityV1::new(
                owner.clone(),
                owner,
                policy,
            ))),
        }
    }
    fn replace(&self, owner: AccountId) {
        self.authority
            .lock()
            .expect("authority lock")
            .provider_owner = owner;
    }
}
impl ProviderIngestFinalizedCompletionAuthorityV1 for TestOwnerAuthorityV1 {
    fn authority_matches(
        &self,
        _provider_id: ProviderId,
        expected: &ProviderIngestCompletionAuthorityV1,
    ) -> bool {
        &*self.authority.lock().expect("authority lock") == expected
    }
}
enum TestMusubiSignerMutationV1 {
    Owner(AccountId),
    AdapterRevision(u64),
}
struct TestMusubiAttestationSignerV1 {
    handle: String,
    key: KeyPair,
    authority: AccountId,
    policy: ProviderIngestCompletionSignerPolicyV1,
    adapter_revision: AtomicU64,
    adapter_policy_digest: [u8; 32],
    controller_policy_digest: [u8; 32],
    owner_authority: TestOwnerAuthorityV1,
    mutation: Mutex<Option<TestMusubiSignerMutationV1>>,
    qualification_calls: AtomicU64,
    eligibility_calls: AtomicU64,
    approval_calls: AtomicU64,
}
impl TestMusubiAttestationSignerV1 {
    fn new(key: KeyPair, owner_authority: TestOwnerAuthorityV1) -> Self {
        let authority = AccountId::new(key.public_key().clone());
        Self {
            handle: "provider://sorafs/musubi/provider-attestation/primary".to_owned(),
            controller_policy_digest: musubi_provider_attestation_controller_policy_digest_v1(
                &authority,
            )
            .expect("test controller digest"),
            key,
            authority,
            policy: test_signer_policy(1),
            adapter_revision: AtomicU64::new(7),
            adapter_policy_digest: [0xA7; 32],
            owner_authority,
            mutation: Mutex::new(None),
            qualification_calls: AtomicU64::new(0),
            eligibility_calls: AtomicU64::new(0),
            approval_calls: AtomicU64::new(0),
        }
    }
    fn approve_payload<'a>(
        &'a self,
        payload: &'a MusubiProviderBundleVerificationPayloadV1,
    ) -> MusubiProviderAttestationApprovalFutureV1<'a> {
        Box::pin(async move {
            self.approval_calls.fetch_add(1, Ordering::SeqCst);
            let attestation = MusubiProviderBundleVerificationAttestationV1 {
                payload: payload.clone(),
                approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                    public_key: self.key.public_key().clone(),
                    signature: SignatureOf::try_from_hash(
                        self.key.private_key(),
                        payload.signing_hash(),
                    )
                    .map_err(|_| MusubiProviderAttestationSignerErrorV1::Rejected)?,
                }],
            };
            match self
                .mutation
                .lock()
                .expect("Musubi signer mutation lock")
                .take()
            {
                Some(TestMusubiSignerMutationV1::Owner(owner)) => {
                    self.owner_authority.replace(owner);
                }
                Some(TestMusubiSignerMutationV1::AdapterRevision(revision)) => {
                    self.adapter_revision.store(revision, Ordering::SeqCst);
                }
                None => {}
            }
            Ok(attestation)
        })
    }
}
impl MusubiProviderAttestationSignerV1 for TestMusubiAttestationSignerV1 {
    fn runtime_handle(&self) -> &str {
        &self.handle
    }
    fn authority(&self) -> &AccountId {
        &self.authority
    }
    fn qualification(
        &self,
    ) -> Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        self.qualification_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MusubiProviderAttestationSignerQualificationV1::new(
            self.adapter_revision.load(Ordering::SeqCst),
            self.adapter_policy_digest,
            self.policy,
            self.authority.clone(),
            self.controller_policy_digest,
        ))
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.policy
    }
    fn current_eligibility(
        &self,
    ) -> Result<ProviderIngestCompletionSignerPolicyV1, MusubiProviderAttestationSignerErrorV1>
    {
        self.eligibility_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.policy)
    }
    fn approve<'a>(
        &'a self,
        _request: &'a ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> MusubiProviderAttestationApprovalFutureV1<'a> {
        Box::pin(async { Err(MusubiProviderAttestationSignerErrorV1::Rejected) })
    }
}
pub(super) fn test_musubi_attestation_payload(
    owner_key: &KeyPair,
) -> MusubiProviderBundleVerificationPayloadV1 {
    let owner = AccountId::new(owner_key.public_key().clone());
    let policy = test_signer_policy(1);
    let payload = MusubiProviderBundleVerificationPayloadV1 {
        version: MUSUBI_REGISTRY_VERSION_V1,
        binding: MusubiProviderBundleVerificationBindingV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x21; 32])),
            ),
            provider_id: ProviderId::new([0x22; 32]),
            completed_by: owner.clone(),
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                (owner).clone(),
                owner,
                policy,
            ),
            replication_order: ReplicationOrderId::new([0x23; 32]),
            assignment_revision: 3,
            completion_epoch: 9,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 77,
                block_hash: [0x24; 32],
            },
            archive_id: ArchiveId::new([0x25; 32]),
            bundle_digest: MusubiContentDigestV1::new([0x26; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x27; 32]),
            semantic_release_manifest_digest: MusubiSemanticReleaseDigestV1::new([0x28; 32]),
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0x29; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x2A; 32]),
        },
    };
    payload
        .validate()
        .expect("valid Musubi attestation payload");
    payload
}
fn test_musubi_request_binding(
    payload: &MusubiProviderBundleVerificationPayloadV1,
) -> MusubiProviderAttestationRequestBindingV1<'_> {
    MusubiProviderAttestationRequestBindingV1 {
        payload,
        completion_claim_digest: [0x2B; 32],
        observed_finalized_cursor: ProviderIngestFinalizedCursorV1 {
            height: 80,
            block_hash: [0x2C; 32],
        },
        signer_policy: payload.binding.completion_authority.signer_policy,
    }
}
fn test_musubi_signer_binding() -> SorafsProviderAttestationRuntimeBinding {
    SorafsProviderAttestationRuntimeBinding {
        handle: "provider://sorafs/musubi/provider-attestation/primary".to_owned(),
        revision: 7,
        policy_digest: [0xA7; 32],
    }
}
fn test_musubi_signer_fixture() -> (
    Arc<TestMusubiAttestationSignerV1>,
    TestOwnerAuthorityV1,
    MusubiProviderBundleVerificationPayloadV1,
) {
    let owner_key = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
        .expect("derive Musubi provider owner");
    let owner = AccountId::new(owner_key.public_key().clone());
    let owner_authority = TestOwnerAuthorityV1::new(owner, test_signer_policy(1));
    let payload = test_musubi_attestation_payload(&owner_key);
    let signer = Arc::new(TestMusubiAttestationSignerV1::new(
        owner_key,
        owner_authority.clone(),
    ));
    (signer, owner_authority, payload)
}
fn test_governed_musubi_signer(
    signer: Arc<TestMusubiAttestationSignerV1>,
    configured_binding: SorafsProviderAttestationRuntimeBinding,
    owner_authority: TestOwnerAuthorityV1,
    payload: &MusubiProviderBundleVerificationPayloadV1,
) -> GovernedMusubiProviderAttestationSignerV1 {
    let signer: Arc<dyn MusubiProviderAttestationSignerV1> = signer;
    let owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1> =
        Arc::new(owner_authority);
    GovernedMusubiProviderAttestationSignerV1::new(
        signer,
        configured_binding,
        owner_authority,
        payload.binding.network_id,
        payload.binding.provider_id,
    )
}
struct TestMusubiAttestationInventoryV1 {
    handle: String,
    adapter_revision: AtomicU64,
    policy_digest: [u8; 32],
    readiness_result:
        Mutex<std::result::Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1>>,
    put_result: Mutex<std::result::Result<u64, MusubiProviderAttestationInventoryErrorV1>>,
    get_result: Mutex<
        std::result::Result<
            Option<MusubiProviderAttestationInventoryReadbackV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    >,
    inventory_result: Mutex<
        std::result::Result<
            Option<MusubiProviderAttestationInventoryV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    >,
    drift_after_readiness: AtomicBool,
    drift_after_put: AtomicBool,
    handle_calls: AtomicU64,
    qualification_calls: AtomicU64,
    readiness_calls: AtomicU64,
    put_calls: AtomicU64,
    get_calls: AtomicU64,
    inventory_calls: AtomicU64,
}
impl TestMusubiAttestationInventoryV1 {
    fn new(item: MusubiProviderAttestationInventoryItemV1) -> Self {
        let scope = item.scope().clone();
        Self {
            handle: "inventory://sorafs/musubi/provider-attestation/primary".to_owned(),
            adapter_revision: AtomicU64::new(13),
            policy_digest: [0xD1; 32],
            readiness_result: Mutex::new(Ok(())),
            put_result: Mutex::new(Ok(29)),
            get_result: Mutex::new(Ok(Some(
                MusubiProviderAttestationInventoryReadbackV1::try_new(item.clone(), 29)
                    .expect("valid test inventory readback"),
            ))),
            inventory_result: Mutex::new(Ok(Some(
                MusubiProviderAttestationInventoryV1::new(scope, vec![item])
                    .expect("valid test inventory"),
            ))),
            drift_after_readiness: AtomicBool::new(false),
            drift_after_put: AtomicBool::new(false),
            handle_calls: AtomicU64::new(0),
            qualification_calls: AtomicU64::new(0),
            readiness_calls: AtomicU64::new(0),
            put_calls: AtomicU64::new(0),
            get_calls: AtomicU64::new(0),
            inventory_calls: AtomicU64::new(0),
        }
    }
    fn maybe_drift(&self, configured: &AtomicBool) {
        if configured.swap(false, Ordering::SeqCst) {
            self.adapter_revision.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn external_call_count(&self) -> u64 {
        self.handle_calls.load(Ordering::SeqCst)
            + self.qualification_calls.load(Ordering::SeqCst)
            + self.readiness_calls.load(Ordering::SeqCst)
            + self.put_calls.load(Ordering::SeqCst)
            + self.get_calls.load(Ordering::SeqCst)
            + self.inventory_calls.load(Ordering::SeqCst)
    }
}
impl MusubiProviderAttestationInventoryRuntimeV1 for TestMusubiAttestationInventoryV1 {
    fn runtime_handle(&self) -> &str {
        self.handle_calls.fetch_add(1, Ordering::SeqCst);
        &self.handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        MusubiProviderAttestationInventoryQualificationV1,
        MusubiProviderAttestationInventoryRuntimeErrorV1,
    > {
        self.qualification_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MusubiProviderAttestationInventoryQualificationV1::new(
            self.adapter_revision.load(Ordering::SeqCst),
            self.policy_digest,
        ))
    }
    fn check_readiness(
        &self,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<(), MusubiProviderAttestationInventoryRuntimeErrorV1>,
    > {
        Box::pin(async move {
            self.readiness_calls.fetch_add(1, Ordering::SeqCst);
            let result = *self
                .readiness_result
                .lock()
                .expect("test inventory readiness lock");
            self.maybe_drift(&self.drift_after_readiness);
            result
        })
    }
}
impl MusubiProviderAttestationInventorySinkV1 for TestMusubiAttestationInventoryV1 {
    fn put(
        &self,
        _item: MusubiProviderAttestationInventoryItemV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<u64, MusubiProviderAttestationInventoryErrorV1>,
    > {
        Box::pin(async move {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            let result = *self.put_result.lock().expect("test inventory put lock");
            self.maybe_drift(&self.drift_after_put);
            result
        })
    }
}
impl MusubiProviderAttestationInventoryReaderV1 for TestMusubiAttestationInventoryV1 {
    fn get<'a>(
        &'a self,
        _scope: &'a MusubiProviderAttestationInventoryScopeV1,
        _key: MusubiProviderBundleAttestationKeyV1,
    ) -> ProviderIngestFutureV1<
        'a,
        std::result::Result<
            Option<MusubiProviderAttestationInventoryReadbackV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            self.get_result
                .lock()
                .expect("test inventory get lock")
                .clone()
        })
    }
    fn inventory<'a>(
        &'a self,
        _scope: &'a MusubiProviderAttestationInventoryScopeV1,
    ) -> ProviderIngestFutureV1<
        'a,
        std::result::Result<
            Option<MusubiProviderAttestationInventoryV1>,
            MusubiProviderAttestationInventoryErrorV1,
        >,
    > {
        Box::pin(async move {
            self.inventory_calls.fetch_add(1, Ordering::SeqCst);
            self.inventory_result
                .lock()
                .expect("test inventory list lock")
                .clone()
        })
    }
}
fn test_musubi_inventory_item(
    network_id: NetworkId,
    provider_id: ProviderId,
    archive_id: ArchiveId,
    replication_order: ReplicationOrderId,
) -> MusubiProviderAttestationInventoryItemV1 {
    let owner_key = KeyPair::try_from_seed(vec![0x79; 32], Algorithm::Ed25519)
        .expect("derive Musubi inventory owner");
    let mut payload = test_musubi_attestation_payload(&owner_key);
    payload.binding.network_id = network_id;
    payload.binding.provider_id = provider_id;
    payload.binding.archive_id = archive_id;
    payload.binding.replication_order = replication_order;
    payload.validate().expect("valid Musubi inventory payload");
    let attestation = MusubiProviderBundleVerificationAttestationV1 {
        approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
            public_key: owner_key.public_key().clone(),
            signature: SignatureOf::try_from_hash(owner_key.private_key(), payload.signing_hash())
                .expect("sign Musubi inventory payload"),
        }],
        payload,
    };
    MusubiProviderAttestationInventoryItemV1::new(attestation).expect("valid Musubi inventory item")
}
fn exact_test_musubi_inventory_item() -> MusubiProviderAttestationInventoryItemV1 {
    test_musubi_inventory_item(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xC1; 32]),
        )),
        ProviderId::new([0xC2; 32]),
        ArchiveId::new([0xC3; 32]),
        ReplicationOrderId::new([0x44; 32]),
    )
}
fn test_musubi_inventory_binding() -> SorafsProviderAttestationRuntimeBinding {
    SorafsProviderAttestationRuntimeBinding {
        handle: "inventory://sorafs/musubi/provider-attestation/primary".to_owned(),
        revision: 13,
        policy_digest: [0xD1; 32],
    }
}
fn test_governed_musubi_inventory(
    inventory: Arc<TestMusubiAttestationInventoryV1>,
    configured_binding: SorafsProviderAttestationRuntimeBinding,
    item: &MusubiProviderAttestationInventoryItemV1,
) -> GovernedMusubiProviderAttestationInventoryV1 {
    let inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1> = inventory;
    GovernedMusubiProviderAttestationInventoryV1::new(
        inventory,
        configured_binding,
        item.scope().network_id,
        item.key().provider_id,
    )
}
enum TestSignerMutationV1 {
    Owner(AccountId),
    Policy(ProviderIngestCompletionSignerPolicyV1),
    QualificationRevision(u64),
}
struct TestGovernedCompletionSignerV1 {
    key: KeyPair,
    authority: AccountId,
    policy: Mutex<ProviderIngestCompletionSignerPolicyV1>,
    qualification_revision: AtomicU64,
    owner_authority: TestOwnerAuthorityV1,
    mutation: Mutex<Option<TestSignerMutationV1>>,
    sign_calls: AtomicU64,
}
impl ProviderIngestCompletionSignerV1 for TestGovernedCompletionSignerV1 {
    fn runtime_handle(&self) -> &'static str {
        "provider:sorafs-provider-ingest-primary"
    }
    fn authority(&self) -> &AccountId {
        &self.authority
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerQualificationV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        Ok(ProviderIngestCompletionSignerQualificationV1::new(
            self.qualification_revision.load(Ordering::SeqCst),
            self.signer_policy(),
            self.key.public_key().algorithm(),
            self.key.public_key().clone(),
        ))
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        *self.policy.lock().expect("signer policy lock")
    }
    fn current_eligibility(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerPolicyV1,
        ProviderIngestCompletionSignerErrorV1,
    > {
        let policy = self.signer_policy();
        if policy.is_valid() {
            Ok(policy)
        } else {
            Err(ProviderIngestCompletionSignerErrorV1::Rejected)
        }
    }
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<SignedTransaction, ProviderIngestCompletionSignerErrorV1>,
    > {
        Box::pin(async move {
            self.sign_calls.fetch_add(1, Ordering::SeqCst);
            let transaction = TransactionBuilder::from_payload(payload)
                .and_then(|builder| builder.try_sign(self.key.private_key()))
                .map_err(|_| ProviderIngestCompletionSignerErrorV1::Rejected)?;
            match self.mutation.lock().expect("signer mutation lock").take() {
                Some(TestSignerMutationV1::Owner(owner)) => {
                    self.owner_authority.replace(owner);
                }
                Some(TestSignerMutationV1::Policy(policy)) => {
                    *self.policy.lock().expect("signer policy lock") = policy;
                }
                Some(TestSignerMutationV1::QualificationRevision(revision)) => {
                    self.qualification_revision
                        .store(revision, Ordering::SeqCst);
                }
                None => {}
            }
            Ok(transaction)
        })
    }
}
struct TestGovernedSignerResolverV1 {
    signer: Arc<dyn ProviderIngestCompletionSignerV1>,
    qualification: Mutex<ProviderIngestRuntimeProviderQualificationV1>,
    qualification_after_readiness: Mutex<Option<ProviderIngestRuntimeProviderQualificationV1>>,
    qualification_after_resolve: Mutex<Option<ProviderIngestRuntimeProviderQualificationV1>>,
    readiness: Mutex<std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1>>,
    last_resolution_context: Mutex<Option<ProviderIngestCompletionSignerResolutionContextV1>>,
}
impl TestGovernedSignerResolverV1 {
    fn new(signer: Arc<dyn ProviderIngestCompletionSignerV1>) -> Self {
        Self {
            signer,
            qualification: Mutex::new(ProviderIngestRuntimeProviderQualificationV1::new(
                6, [0xB2; 32],
            )),
            qualification_after_readiness: Mutex::new(None),
            qualification_after_resolve: Mutex::new(None),
            readiness: Mutex::new(Ok(())),
            last_resolution_context: Mutex::new(None),
        }
    }
}
impl ProviderIngestGovernedSignerResolverRuntimeV1 for TestGovernedSignerResolverV1 {
    fn runtime_handle(&self) -> &'static str {
        "provider:sorafs-provider-ingest-resolver"
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    > {
        Ok(*self
            .qualification
            .lock()
            .expect("resolver qualification lock"))
    }
    fn signer_binding(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerBindingV1,
        ProviderIngestCompletionSignerResolverErrorV1,
    > {
        let qualification = self.signer.qualification().map_err(|error| match error {
            ProviderIngestCompletionSignerErrorV1::Unavailable => {
                ProviderIngestCompletionSignerResolverErrorV1::Unavailable
            }
            ProviderIngestCompletionSignerErrorV1::Rejected => {
                ProviderIngestCompletionSignerResolverErrorV1::Rejected
            }
        })?;
        Ok(ProviderIngestCompletionSignerBindingV1::new(
            self.signer.runtime_handle(),
            qualification,
        ))
    }
    fn check_readiness(
        &self,
    ) -> std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1> {
        if let Some(qualification) = self
            .qualification_after_readiness
            .lock()
            .expect("resolver readiness mutation lock")
            .take()
        {
            *self
                .qualification
                .lock()
                .expect("resolver qualification lock") = qualification;
        }
        *self.readiness.lock().expect("resolver readiness lock")
    }
    fn resolve(
        &self,
        context: ProviderIngestCompletionSignerResolutionContextV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<
            Option<Arc<dyn ProviderIngestCompletionSignerV1>>,
            ProviderIngestCompletionSignerResolverErrorV1,
        >,
    > {
        *self
            .last_resolution_context
            .lock()
            .expect("resolver context lock") = Some(context);
        let signer = Arc::clone(&self.signer);
        if let Some(qualification) = self
            .qualification_after_resolve
            .lock()
            .expect("resolver resolution mutation lock")
            .take()
        {
            *self
                .qualification
                .lock()
                .expect("resolver qualification lock") = qualification;
        }
        Box::pin(async move { Ok(Some(signer)) })
    }
}
fn test_signer_policy(revision: u64) -> ProviderIngestCompletionSignerPolicyV1 {
    let digest_byte = u8::try_from(revision).unwrap_or(0xFE);
    ProviderIngestCompletionSignerPolicyV1 {
        policy_id: [0xA1; 32],
        revision,
        predecessor_digest: (revision > 1).then(|| [digest_byte.saturating_sub(1); 32]),
        policy_digest: [digest_byte; 32],
    }
}
fn test_completion_payload(
    key: &KeyPair,
    provider_id: ProviderId,
    completion_epoch: u64,
    expected_assignment_revision: u64,
) -> TransactionPayload {
    let provider_owner = AccountId::new(key.public_key().clone());
    let signer_policy = test_signer_policy(1);
    let mut builder = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x15; Hash::LENGTH]),
        )),
        provider_owner.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([InstructionBox::from(CompleteReplicationOrder {
        order_id: ReplicationOrderId::new([0x31; 32]),
        provider_id,
        completion_epoch,
        expected_authority:
            iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1::new(
                (provider_owner).clone(),
                provider_owner,
                signer_policy,
            ),
        expected_assignment_revision,
        finalized_anchor: ProviderIngestFinalizedAnchorV1 {
            height: completion_epoch,
            block_hash: [0xB2; 32],
        },
    })]);
    builder.set_creation_time(Duration::from_secs(1));
    builder.set_ttl(Duration::from_secs(30));
    builder
        .try_sign(key.private_key())
        .expect("sign payload fixture")
        .payload()
        .clone()
}
#[test]
fn canonical_completion_payload_fixture_fits_production_floor() {
    assert_eq!(
        provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN,
        64 * 1024
    );
    let key =
        KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).expect("derive signer key");
    let payload = test_completion_payload(&key, ProviderId::new([0x41; 32]), 8, 1);
    let payload_bytes = norito::to_bytes(&payload).expect("encode canonical completion payload");
    let decoded_payload = norito::decode_from_bytes::<TransactionPayload>(&payload_bytes)
        .expect("decode canonical completion payload");
    assert_eq!(decoded_payload, payload);
    assert_eq!(
        norito::to_bytes(&decoded_payload).expect("re-encode canonical completion payload"),
        payload_bytes
    );
    let signed = TransactionBuilder::from_payload(payload.clone())
        .expect("rebuild canonical completion transaction")
        .try_sign(key.private_key())
        .expect("sign canonical completion transaction");
    let signed_bytes =
        norito::to_bytes(&signed).expect("encode canonical signed completion transaction");
    let decoded_signed = norito::decode_from_bytes::<SignedTransaction>(&signed_bytes)
        .expect("decode canonical signed completion transaction");
    assert_eq!(decoded_signed, signed);
    assert_eq!(
        norito::to_bytes(&decoded_signed)
            .expect("re-encode canonical signed completion transaction"),
        signed_bytes
    );
    let repeated_signed = TransactionBuilder::from_payload(payload.clone())
        .expect("rebuild repeated canonical completion transaction")
        .try_sign(key.private_key())
        .expect("repeat canonical completion signature");
    assert_eq!(
        norito::to_bytes(&repeated_signed)
            .expect("encode repeated canonical signed completion transaction"),
        signed_bytes
    );
    let payload_with_envelope = u64::try_from(payload_bytes.len())
        .expect("payload length fits u64")
        .checked_add(provider_ingest_outbox_defaults::SIGNED_TRANSACTION_ENVELOPE_RESERVE_BYTES_V1)
        .expect("payload plus envelope reserve");
    assert!(
        payload_with_envelope <= provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
    );
    assert!(
        u64::try_from(signed_bytes.len()).expect("signed length fits u64")
            <= provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN
    );
}
fn test_governed_signer(
    policy: ProviderIngestCompletionSignerPolicyV1,
    mutation: Option<TestSignerMutationV1>,
) -> (
    Arc<TestGovernedCompletionSignerV1>,
    TestOwnerAuthorityV1,
    ProviderId,
    TransactionPayload,
) {
    let key =
        KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).expect("derive signer key");
    let authority = AccountId::new(key.public_key().clone());
    let owner_authority = TestOwnerAuthorityV1::new(authority.clone(), policy);
    let provider_id = ProviderId::new([0x41; 32]);
    let payload = test_completion_payload(&key, provider_id, 8, 1);
    let signer = Arc::new(TestGovernedCompletionSignerV1 {
        key,
        authority,
        policy: Mutex::new(policy),
        qualification_revision: AtomicU64::new(1),
        owner_authority: owner_authority.clone(),
        mutation: Mutex::new(mutation),
        sign_calls: AtomicU64::new(0),
    });
    (signer, owner_authority, provider_id, payload)
}
fn test_readiness_resolver(
    readiness: std::result::Result<(), ProviderIngestCompletionSignerResolverErrorV1>,
) -> Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> {
    let (signer, _, _, _) = test_governed_signer(test_signer_policy(1), None);
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver = Arc::new(TestGovernedSignerResolverV1::new(signer));
    *resolver.readiness.lock().expect("resolver readiness lock") = readiness;
    resolver
}
fn governed_signer_adapter(
    signer: Arc<TestGovernedCompletionSignerV1>,
    owner_authority: TestOwnerAuthorityV1,
    provider_id: ProviderId,
) -> GovernedSignerResolverAdapterV1 {
    let expected_signer_binding = ProviderIngestCompletionSignerBindingV1::new(
        signer.runtime_handle(),
        signer.qualification().expect("test signer qualification"),
    );
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> =
        Arc::new(TestGovernedSignerResolverV1::new(signer));
    let owner_authority: Arc<dyn ProviderIngestFinalizedCompletionAuthorityV1> =
        Arc::new(owner_authority);
    GovernedSignerResolverAdapterV1 {
        resolver,
        owner_authority,
        provider_id,
        expected_resolver_qualification: ProviderIngestRuntimeProviderQualificationV1::new(
            6, [0xB2; 32],
        ),
        expected_signer_binding,
    }
}
fn signer_test_cursor() -> ProviderIngestFinalizedCursorV1 {
    ProviderIngestFinalizedCursorV1 {
        height: 8,
        block_hash: [0xB2; 32],
    }
}
fn signer_resolution_context(
    provider_owner: AccountId,
) -> ProviderIngestCompletionSignerResolutionContextV1 {
    ProviderIngestCompletionSignerResolutionContextV1::new(
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionAuthorityV1::new(
            (provider_owner).clone(),
            provider_owner,
            test_signer_policy(1),
        ),
        1,
        signer_test_cursor(),
    )
}
#[test]
fn governed_signer_resolver_rejects_stale_advertised_binding() {
    let (signer, _owner_authority, _provider_id, _payload) =
        test_governed_signer(test_signer_policy(1), None);
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver = TestGovernedSignerResolverV1::new(Arc::clone(&signer));
    let mut expected = resolver.signer_binding().expect("signer binding");
    expected.qualification.adapter_revision = 2;
    assert_eq!(
        validate_resolver_signer_binding(&resolver, &expected),
        Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)
    );
}
#[test]
fn governed_signer_resolver_rejects_qualification_drift_across_readiness() {
    let (signer, _owner_authority, _provider_id, _payload) =
        test_governed_signer(test_signer_policy(1), None);
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver = TestGovernedSignerResolverV1::new(signer);
    let expected = ProviderIngestRuntimeProviderQualificationV1::new(6, [0xB2; 32]);
    assert!(validate_resolver_qualification(&resolver, expected).is_ok());
    *resolver
        .qualification_after_readiness
        .lock()
        .expect("resolver readiness mutation lock") = Some(
        ProviderIngestRuntimeProviderQualificationV1::new(7, [0xB3; 32]),
    );
    resolver.check_readiness().expect("readiness probe");
    assert_eq!(
        validate_resolver_qualification(&resolver, expected),
        Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)
    );
}
#[tokio::test]
async fn governed_signer_resolver_rechecks_qualification_after_resolution() {
    let (signer, owner_authority, provider_id, _payload) =
        test_governed_signer(test_signer_policy(1), None);
    let provider_owner = signer.authority().clone();
    let expected_signer_binding = ProviderIngestCompletionSignerBindingV1::new(
        signer.runtime_handle(),
        signer.qualification().expect("test signer qualification"),
    );
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver = Arc::new(TestGovernedSignerResolverV1::new(signer));
    let observed_resolver = Arc::clone(&resolver);
    *resolver
        .qualification_after_resolve
        .lock()
        .expect("resolver resolution mutation lock") = Some(
        ProviderIngestRuntimeProviderQualificationV1::new(7, [0xB3; 32]),
    );
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> = resolver;
    let adapter = GovernedSignerResolverAdapterV1 {
        resolver,
        owner_authority: Arc::new(owner_authority),
        provider_id,
        expected_resolver_qualification: ProviderIngestRuntimeProviderQualificationV1::new(
            6, [0xB2; 32],
        ),
        expected_signer_binding,
    };
    let expected_context = signer_resolution_context(provider_owner);
    assert!(matches!(
        adapter.resolve(expected_context.clone()).await,
        Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)
    ));
    assert_eq!(
        *observed_resolver
            .last_resolution_context
            .lock()
            .expect("resolver context lock"),
        Some(expected_context)
    );
}
#[tokio::test]
async fn governed_signer_resolver_rejects_invalid_initial_policy() {
    let (signer, owner_authority, provider_id, _payload) = test_governed_signer(
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0; 32],
            revision: 0,
            predecessor_digest: None,
            policy_digest: [0; 32],
        },
        None,
    );
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(signer, owner_authority, provider_id);
    assert!(matches!(
        adapter
            .resolve(signer_resolution_context(provider_owner))
            .await,
        Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)
    ));
}
#[tokio::test]
async fn governed_signer_pins_assignment_revision_before_runtime_signing() {
    let (signer, owner_authority, provider_id, exact_payload) =
        test_governed_signer(test_signer_policy(1), None);
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(Arc::clone(&signer), owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    let signed_payload = governed
        .sign(exact_payload.clone())
        .await
        .expect("sign exact assignment revision");
    assert_eq!(signed_payload.payload(), &exact_payload);
    assert_eq!(signer.sign_calls.load(Ordering::SeqCst), 1);
    let substituted_payload = test_completion_payload(&signer.key, provider_id, 8, 2);
    assert_eq!(
        governed.sign(substituted_payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Rejected)
    );
    assert_eq!(
        signer.sign_calls.load(Ordering::SeqCst),
        1,
        "substituted assignment revision must not reach the runtime signer"
    );
}
#[tokio::test]
async fn governed_signer_rejects_provider_substitution_before_runtime_signing() {
    let (signer, owner_authority, provider_id, _exact_payload) =
        test_governed_signer(test_signer_policy(1), None);
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(Arc::clone(&signer), owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    let substituted_payload =
        test_completion_payload(&signer.key, ProviderId::new([0x42; 32]), 8, 1);
    assert_eq!(
        governed.sign(substituted_payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Rejected)
    );
    assert_eq!(
        signer.sign_calls.load(Ordering::SeqCst),
        0,
        "a completion for another provider must not reach the runtime signer"
    );
}
#[tokio::test]
async fn governed_signer_rechecks_policy_after_signing() {
    let (signer, owner_authority, provider_id, payload) = test_governed_signer(
        test_signer_policy(1),
        Some(TestSignerMutationV1::Policy(test_signer_policy(2))),
    );
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(signer, owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    assert_eq!(
        governed.sign(payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_signer_rechecks_qualification_after_signing() {
    let (signer, owner_authority, provider_id, payload) = test_governed_signer(
        test_signer_policy(1),
        Some(TestSignerMutationV1::QualificationRevision(2)),
    );
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(signer, owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    assert_eq!(
        governed.sign(payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_signer_surfaces_policy_rotation_before_authorization() {
    let (signer, owner_authority, provider_id, _payload) =
        test_governed_signer(test_signer_policy(1), None);
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(Arc::clone(&signer), owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    *signer.policy.lock().expect("signer policy lock") = test_signer_policy(2);
    assert_eq!(governed.signer_policy(), test_signer_policy(2));
    assert_eq!(
        governed.current_eligibility(),
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_signer_reports_owner_rotation_before_authorization() {
    let replacement_key = KeyPair::try_from_seed(vec![0x33; 32], Algorithm::Ed25519)
        .expect("derive replacement owner");
    let replacement_owner = AccountId::new(replacement_key.public_key().clone());
    let (signer, owner_authority, provider_id, _payload) =
        test_governed_signer(test_signer_policy(1), None);
    let provider_owner = signer.authority().clone();
    let adapter =
        governed_signer_adapter(Arc::clone(&signer), owner_authority.clone(), provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    owner_authority.replace(replacement_owner);
    assert_eq!(
        governed.current_eligibility(),
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_signer_rechecks_owner_after_signing() {
    let replacement_key = KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519)
        .expect("derive replacement owner");
    let replacement_owner = AccountId::new(replacement_key.public_key().clone());
    let (signer, owner_authority, provider_id, payload) = test_governed_signer(
        test_signer_policy(1),
        Some(TestSignerMutationV1::Owner(replacement_owner)),
    );
    let provider_owner = signer.authority().clone();
    let adapter = governed_signer_adapter(signer, owner_authority, provider_id);
    let governed = adapter
        .resolve(signer_resolution_context(provider_owner))
        .await
        .expect("resolve governed signer")
        .expect("governed signer");
    assert_eq!(
        governed.sign(payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_musubi_signer_rejects_each_configured_binding_mismatch() {
    let mut mismatches = Vec::new();
    let mut handle = test_musubi_signer_binding();
    handle.handle = "provider://sorafs/musubi/provider-attestation/secondary".to_owned();
    mismatches.push(handle);
    let mut revision = test_musubi_signer_binding();
    revision.revision += 1;
    mismatches.push(revision);
    let mut policy_digest = test_musubi_signer_binding();
    policy_digest.policy_digest = [0xA8; 32];
    mismatches.push(policy_digest);
    for configured_binding in mismatches {
        let (signer, owner_authority, payload) = test_musubi_signer_fixture();
        let governed = test_governed_musubi_signer(
            Arc::clone(&signer),
            configured_binding,
            owner_authority,
            &payload,
        );
        assert_eq!(
            governed.qualification(),
            Err(MusubiProviderAttestationSignerErrorV1::Rejected)
        );
        assert!(
            governed
                .approve_bound(test_musubi_request_binding(&payload), || {
                    signer.approve_payload(&payload)
                })
                .await
                .is_err()
        );
        assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn governed_musubi_signer_rejects_foreign_deployment_context_before_approval() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    let mut foreign_network = payload.clone();
    foreign_network.binding.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0xB0; 32])),
    );
    let mut same_label_foreign_genesis = payload.clone();
    same_label_foreign_genesis.binding.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0xB1; 32])),
    );
    let mut foreign_provider = payload.clone();
    foreign_provider.binding.provider_id = ProviderId::new([0xB2; 32]);
    for foreign in [
        foreign_network,
        same_label_foreign_genesis,
        foreign_provider,
    ] {
        foreign
            .validate()
            .expect("foreign deployment payload remains structurally valid");
        assert_eq!(
            governed
                .approve_bound(test_musubi_request_binding(&foreign), || {
                    signer.approve_payload(&foreign)
                })
                .await,
            Err(MusubiProviderAttestationSignerErrorV1::Rejected)
        );
    }
    assert_eq!(signer.qualification_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.eligibility_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn governed_musubi_signer_rejects_revoked_owner_before_any_signer_effect() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    let replacement_key = KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519)
        .expect("derive replacement owner");
    owner_authority.replace(AccountId::new(replacement_key.public_key().clone()));
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    let request = test_musubi_request_binding(&payload);
    assert_eq!(
        governed
            .approve_bound(request, || signer.approve_payload(&payload))
            .await,
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable)
    );
    assert_eq!(signer.qualification_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.eligibility_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn governed_musubi_signer_rejects_owner_rotation_after_external_approval() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    let replacement_key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
        .expect("derive replacement owner");
    *signer.mutation.lock().expect("Musubi signer mutation lock") = Some(
        TestMusubiSignerMutationV1::Owner(AccountId::new(replacement_key.public_key().clone())),
    );
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    assert_eq!(
        governed
            .approve_bound(test_musubi_request_binding(&payload), || {
                signer.approve_payload(&payload)
            })
            .await,
        Err(MusubiProviderAttestationSignerErrorV1::Unavailable)
    );
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn governed_musubi_signer_rejects_adapter_drift_after_external_approval() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    *signer.mutation.lock().expect("Musubi signer mutation lock") =
        Some(TestMusubiSignerMutationV1::AdapterRevision(8));
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    assert!(
        governed
            .approve_bound(test_musubi_request_binding(&payload), || {
                signer.approve_payload(&payload)
            })
            .await
            .is_err()
    );
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn governed_musubi_signer_rejects_substituted_attestation() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    let mut substituted = payload.clone();
    substituted.binding.source_tree_digest = MusubiContentDigestV1::new([0xAA; 32]);
    substituted
        .validate()
        .expect("substituted payload remains structurally valid");
    assert_eq!(
        governed
            .approve_bound(test_musubi_request_binding(&payload), || {
                signer.approve_payload(&substituted)
            })
            .await,
        Err(MusubiProviderAttestationSignerErrorV1::Rejected)
    );
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn governed_musubi_signer_accepts_exact_binding_and_preserves_replay() {
    let (signer, owner_authority, payload) = test_musubi_signer_fixture();
    let governed = test_governed_musubi_signer(
        Arc::clone(&signer),
        test_musubi_signer_binding(),
        owner_authority,
        &payload,
    );
    let request = test_musubi_request_binding(&payload);
    let first = governed
        .approve_bound(request, || signer.approve_payload(&payload))
        .await
        .expect("approve exact Musubi attestation binding");
    let replay = governed
        .approve_bound(request, || signer.approve_payload(&payload))
        .await
        .expect("replay exact Musubi attestation binding");
    assert_eq!(first, replay);
    assert_eq!(&first.payload, request.payload);
    first
        .verify(&request.payload.binding)
        .expect("exact governed attestation verifies");
    assert_eq!(signer.approval_calls.load(Ordering::SeqCst), 2);
}
#[test]
fn governed_musubi_inventory_rejects_each_configured_binding_mismatch() {
    let item = exact_test_musubi_inventory_item();
    let mut mismatches = Vec::new();
    let mut handle = test_musubi_inventory_binding();
    handle.handle = "inventory://sorafs/musubi/provider-attestation/secondary".to_owned();
    mismatches.push(handle);
    let mut revision = test_musubi_inventory_binding();
    revision.revision += 1;
    mismatches.push(revision);
    let mut policy_digest = test_musubi_inventory_binding();
    policy_digest.policy_digest = [0xD2; 32];
    mismatches.push(policy_digest);
    for configured_binding in mismatches {
        let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
        let governed =
            test_governed_musubi_inventory(Arc::clone(&inventory), configured_binding, &item);
        assert_eq!(
            governed.qualification(),
            Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected)
        );
        assert_eq!(inventory.put_calls.load(Ordering::SeqCst), 0);
        assert_eq!(inventory.get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(inventory.inventory_calls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn governed_musubi_inventory_rejects_foreign_context_before_adapter_calls() {
    let item = exact_test_musubi_inventory_item();
    let scope = item.scope().clone();
    let key = item.key();
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    let foreign_network_item = test_musubi_inventory_item(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xE0; 32]),
        )),
        key.provider_id,
        scope.archive_id,
        scope.replication_order,
    );
    let second_foreign_network_item = test_musubi_inventory_item(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xE1; 32]),
        )),
        key.provider_id,
        scope.archive_id,
        scope.replication_order,
    );
    let foreign_provider_item = test_musubi_inventory_item(
        scope.network_id,
        ProviderId::new([0xE2; 32]),
        scope.archive_id,
        scope.replication_order,
    );
    for foreign in [
        foreign_network_item,
        second_foreign_network_item,
        foreign_provider_item,
    ] {
        assert_eq!(
            governed.put(foreign).await,
            Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
        );
    }
    let mut foreign_network_scope = scope.clone();
    foreign_network_scope.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0xE2; 32])),
    );
    assert_eq!(
        governed.get(&foreign_network_scope, key).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    let mut same_label_foreign_genesis_scope = scope.clone();
    same_label_foreign_genesis_scope.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0xE3; 32])),
    );
    assert_eq!(
        governed.inventory(&same_label_foreign_genesis_scope).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    let mut foreign_provider_key = key;
    foreign_provider_key.provider_id = ProviderId::new([0xE4; 32]);
    assert_eq!(
        governed.get(&scope, foreign_provider_key).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    assert_eq!(inventory.external_call_count(), 0);
}
#[tokio::test]
async fn governed_musubi_inventory_rejects_qualification_drift_after_put() {
    let item = exact_test_musubi_inventory_item();
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    inventory.drift_after_put.store(true, Ordering::SeqCst);
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    assert_eq!(
        governed.put(item).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    assert_eq!(inventory.put_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn governed_musubi_inventory_rejects_substituted_get_and_inventory_outputs() {
    let item = exact_test_musubi_inventory_item();
    let scope = item.scope().clone();
    let key = item.key();
    let substituted_provider_item = test_musubi_inventory_item(
        scope.network_id,
        ProviderId::new([0xE5; 32]),
        scope.archive_id,
        scope.replication_order,
    );
    let substituted_scope_item = test_musubi_inventory_item(
        scope.network_id,
        key.provider_id,
        ArchiveId::new([0xE6; 32]),
        ReplicationOrderId::new([0x67; 32]),
    );
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    *inventory
        .get_result
        .lock()
        .expect("test inventory get lock") = Ok(Some(
        MusubiProviderAttestationInventoryReadbackV1::try_new(substituted_provider_item, 29)
            .expect("structurally valid substituted readback"),
    ));
    *inventory
        .inventory_result
        .lock()
        .expect("test inventory list lock") = Ok(Some(
        MusubiProviderAttestationInventoryV1::new(
            substituted_scope_item.scope().clone(),
            vec![substituted_scope_item],
        )
        .expect("structurally valid substituted inventory"),
    ));
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    assert_eq!(
        governed.get(&scope, key).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    assert_eq!(
        governed.inventory(&scope).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Rejected)
    );
    assert_eq!(inventory.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inventory.inventory_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn governed_musubi_inventory_fences_and_preserves_readiness_errors() {
    let item = exact_test_musubi_inventory_item();
    for expected in [
        MusubiProviderAttestationInventoryRuntimeErrorV1::Unavailable,
        MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected,
    ] {
        let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
        *inventory
            .readiness_result
            .lock()
            .expect("test inventory readiness lock") = Err(expected);
        let governed = test_governed_musubi_inventory(
            Arc::clone(&inventory),
            test_musubi_inventory_binding(),
            &item,
        );
        assert_eq!(governed.check_readiness().await, Err(expected));
        assert_eq!(inventory.readiness_calls.load(Ordering::SeqCst), 1);
    }
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    inventory
        .drift_after_readiness
        .store(true, Ordering::SeqCst);
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    assert_eq!(
        governed.check_readiness().await,
        Err(MusubiProviderAttestationInventoryRuntimeErrorV1::Rejected)
    );
}
#[tokio::test]
async fn governed_musubi_inventory_preserves_stable_transient_operation_failures() {
    let item = exact_test_musubi_inventory_item();
    let scope = item.scope().clone();
    let key = item.key();
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    *inventory
        .put_result
        .lock()
        .expect("test inventory put lock") =
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable);
    *inventory
        .get_result
        .lock()
        .expect("test inventory get lock") =
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable);
    *inventory
        .inventory_result
        .lock()
        .expect("test inventory list lock") =
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable);
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    assert_eq!(
        governed.put(item).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable)
    );
    assert_eq!(
        governed.get(&scope, key).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable)
    );
    assert_eq!(
        governed.inventory(&scope).await,
        Err(MusubiProviderAttestationInventoryErrorV1::Unavailable)
    );
}
#[tokio::test]
async fn governed_musubi_inventory_accepts_exact_qualified_operations() {
    let item = exact_test_musubi_inventory_item();
    let scope = item.scope().clone();
    let key = item.key();
    let inventory = Arc::new(TestMusubiAttestationInventoryV1::new(item.clone()));
    let governed = test_governed_musubi_inventory(
        Arc::clone(&inventory),
        test_musubi_inventory_binding(),
        &item,
    );
    assert_eq!(
        governed.qualification(),
        Ok(MusubiProviderAttestationInventoryQualificationV1::new(
            13, [0xD1; 32]
        ))
    );
    assert_eq!(governed.check_readiness().await, Ok(()));
    assert_eq!(governed.put(item.clone()).await, Ok(29));
    let readback = governed
        .get(&scope, key)
        .await
        .expect("read exact inventory item")
        .expect("exact inventory item exists");
    assert_eq!(readback.item(), &item);
    assert_eq!(readback.inventory_revision(), 29);
    let listed = governed
        .inventory(&scope)
        .await
        .expect("read exact inventory")
        .expect("exact inventory exists");
    assert_eq!(listed.scope(), &scope);
    assert_eq!(listed.items(), &[item]);
    assert_eq!(inventory.readiness_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inventory.put_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inventory.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inventory.inventory_calls.load(Ordering::SeqCst), 1);
}
#[test]
fn production_handle_validation_rejects_placeholders_and_whitespace() {
    for handle in [
        "",
        "pkcs11 test",
        "source-mock-primary",
        "fake",
        "dummy",
        "kms-placeholder",
        "source\nprimary",
        "https://operator:secret@host",
        "https://host/source?token=secret",
        "https://host/source#fragment",
    ] {
        assert!(!is_production_runtime_handle(handle), "{handle:?}");
    }
    assert!(is_production_runtime_handle(
        "provider://sorafs/provider-ingest/primary"
    ));
    assert!(is_production_runtime_handle(
        "https-pinned-source-pool:eu-1"
    ));
}
#[test]
fn dependency_identity_rejects_runtime_substitution() {
    assert!(validate_dependency_identity("source", "source:eu-1", "source:eu-2").is_err());
    assert!(validate_dependency_identity("source", "source:eu-1", "source:eu-1").is_ok());
}
struct TestPoolProviderSourceV1 {
    provider_id: [u8; 32],
    runtime_handle: &'static str,
    readiness: std::result::Result<(), ProviderIngestSourceFetchErrorV1>,
}
impl ProviderIngestAuthenticatedProviderSourceV1 for TestPoolProviderSourceV1 {
    type Fetched = VerifiedProviderIngestPayloadV1;
    fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
    fn runtime_handle(&self) -> &str {
        self.runtime_handle
    }
    fn qualification(
        &self,
    ) -> std::result::Result<ProviderIngestSourceQualificationV1, ProviderIngestSourceFetchErrorV1>
    {
        Ok(ProviderIngestSourceQualificationV1::new(
            1,
            self.provider_id,
        ))
    }
    fn check_readiness(&self) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1> {
        self.readiness
    }
    fn fetch_provider(
        &self,
        _authorization: FinalizedProviderIngestAuthorizationV1,
        _musubi_archive: Option<ProviderIngestMusubiArchiveFetchBindingV1>,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>,
    > {
        Box::pin(async { Err(ProviderIngestSourceFetchErrorV1::Unavailable) })
    }
}
fn test_runtime_source_pool(
    first_readiness: std::result::Result<(), ProviderIngestSourceFetchErrorV1>,
    second_readiness: std::result::Result<(), ProviderIngestSourceFetchErrorV1>,
) -> ProviderIngestAuthenticatedSourcePoolV1<VerifiedProviderIngestPayloadV1> {
    let registrations = [
        ([0x22; 32], "https-pinned:provider-a", first_readiness),
        ([0x33; 32], "https-pinned:provider-b", second_readiness),
    ]
    .into_iter()
    .map(|(provider_id, runtime_handle, readiness)| {
        let source: Arc<
            dyn ProviderIngestAuthenticatedProviderSourceV1<
                Fetched = VerifiedProviderIngestPayloadV1,
            >,
        > = Arc::new(TestPoolProviderSourceV1 {
            provider_id,
            runtime_handle,
            readiness,
        });
        ProviderIngestAuthenticatedSourceRegistrationV1::new(
            ProviderIngestAuthenticatedSourceBindingV1 {
                provider_id,
                runtime_handle: runtime_handle.to_owned(),
                revision: 1,
                policy_digest: provider_id,
            },
            source,
        )
    })
    .collect();
    ProviderIngestAuthenticatedSourcePoolV1::new(
        "https-pinned-source-pool:region-a",
        ProviderIngestRuntimeProviderQualificationV1::new(5, [0xB1; 32]),
        4,
        registrations,
    )
    .expect("test source pool")
}
struct TestAuthenticatedSourceInventoryV1 {
    provider_ids: Vec<[u8; 32]>,
    qualification: Mutex<ProviderIngestRuntimeProviderQualificationV1>,
    qualification_after_readiness: Mutex<Option<ProviderIngestRuntimeProviderQualificationV1>>,
    qualification_after_fetch: Mutex<Option<ProviderIngestRuntimeProviderQualificationV1>>,
    readiness: Mutex<std::result::Result<(), ProviderIngestSourceFetchErrorV1>>,
}
impl TestAuthenticatedSourceInventoryV1 {
    fn new(provider_ids: Vec<[u8; 32]>) -> Self {
        Self {
            provider_ids,
            qualification: Mutex::new(ProviderIngestRuntimeProviderQualificationV1::new(
                5, [0xB1; 32],
            )),
            qualification_after_readiness: Mutex::new(None),
            qualification_after_fetch: Mutex::new(None),
            readiness: Mutex::new(Ok(())),
        }
    }
}
fn test_readiness_source(
    readiness: std::result::Result<(), ProviderIngestSourceFetchErrorV1>,
) -> Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> {
    let source = Arc::new(TestAuthenticatedSourceInventoryV1::new(vec![
        [0x22; 32], [0x33; 32],
    ]));
    *source.readiness.lock().expect("source readiness lock") = readiness;
    source
}
#[derive(Debug)]
struct TestStateFreeCheckpointRuntimeV1 {
    qualification: Mutex<ProviderIngestCheckpointProviderQualificationV1>,
    qualification_calls: AtomicU64,
    load_calls: AtomicU64,
    compare_and_swap_calls: AtomicU64,
}
impl TestStateFreeCheckpointRuntimeV1 {
    fn new() -> Self {
        Self {
            qualification: Mutex::new(ProviderIngestCheckpointProviderQualificationV1::new(
                7, [0xA7; 32],
            )),
            qualification_calls: AtomicU64::new(0),
            load_calls: AtomicU64::new(0),
            compare_and_swap_calls: AtomicU64::new(0),
        }
    }
}
impl ProviderIngestCheckpointRuntimeV1 for TestStateFreeCheckpointRuntimeV1 {
    fn handle(&self) -> &'static str {
        "sealed:sorafs-provider-ingest-primary"
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestCheckpointProviderQualificationV1,
        ProviderIngestCheckpointExternalErrorV1,
    > {
        self.qualification_calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self
            .qualification
            .lock()
            .expect("checkpoint qualification lock"))
    }
    fn load_latest(
        &self,
    ) -> std::result::Result<
        Option<sorafs_node::ProviderIngestSealedCheckpointRecordV1>,
        ProviderIngestCheckpointExternalErrorV1,
    > {
        self.load_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    fn compare_and_swap_latest(
        &self,
        _expected_revision: Option<[u8; 32]>,
        _next: &sorafs_node::ProviderIngestSealedCheckpointRecordV1,
    ) -> std::result::Result<(), ProviderIngestCheckpointExternalErrorV1> {
        self.compare_and_swap_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn state_free_preflight_fixture() -> (
    SorafsProviderIngestRuntime,
    ProviderId,
    Arc<TestAuthenticatedSourceInventoryV1>,
    Arc<TestGovernedSignerResolverV1>,
    Arc<TestStateFreeCheckpointRuntimeV1>,
) {
    let (signer, _, _, _) = test_governed_signer(test_signer_policy(1), None);
    let config = SorafsProviderIngestRuntime {
        native_source_origins: std::collections::BTreeMap::default(),
        native_completion_credential: None,
        authenticated_source_fetch_handle: "https-pinned-source-pool:region-a".to_owned(),
        authenticated_source_fetch_revision: 5,
        authenticated_source_fetch_policy_digest: [0xB1; 32],
        completion_signer_resolver_handle: "provider:sorafs-provider-ingest-resolver".to_owned(),
        completion_signer_resolver_revision: 6,
        completion_signer_resolver_policy_digest: [0xB2; 32],
        completion_signer_handle: signer.runtime_handle().to_owned(),
        completion_signer_adapter_revision: 1,
        completion_signer_policy: test_signer_policy(1),
        completion_signer_algorithm: Algorithm::Ed25519,
        completion_signer_public_key: signer.key.public_key().clone(),
        checkpoint_store_handle: "sealed:sorafs-provider-ingest-primary".to_owned(),
        checkpoint_store_revision: 7,
        checkpoint_store_policy_digest: [0xA7; 32],
        scan_interval_ms: 1_000,
        max_page_rows: 64,
        max_pages_per_tick: 4,
        max_source_jobs_per_tick: 32,
        max_source_providers: 1_024,
        source_operation_timeout_ms: 30_000,
        source_lease_renew_interval_ms: 5_000,
        signer_timeout_ms: 10_000,
        ingress_timeout_ms: 10_000,
        completion_transaction_ttl_ms: 30_000,
        finalized_archive: iroha_config::parameters::actual::SorafsProviderIngestFinalizedArchive {
            relative_root: "provider-ingest-finalized-archive-v1".into(),
            max_record_bytes: 128 * 1024 * 1024,
            max_archive_entries: 1_000_000,
            max_total_bytes: 64 * 1024 * 1024 * 1024,
            max_providers_per_anchor: 1_024,
            max_orders_per_provider: 256,
            max_total_orders_per_anchor: 256,
            max_page_rows: 64,
            max_kura_tip_lag_blocks: 2,
            retention_authority: None,
        },
        outbox: iroha_config::parameters::actual::SorafsProviderIngestOutbox {
            max_active_entries: 32,
            max_terminal_entries: 4_096,
            max_attempts: 8,
            // Retained completion identities and both transaction copies must fit
            // the native worst-case checkpoint bound before adapter checks run.
            checkpoint_max_bytes: provider_ingest_outbox_defaults::CHECKPOINT_MAX_BYTES,
            checkpoint_operation_timeout_ms: 30_000,
            source_lease_ttl_ms: 30_000,
            retry_base_delay_ms: 1_000,
            retry_max_delay_ms: 60_000,
            terminal_retention_blocks: 100_000,
            max_signed_transaction_bytes: Bytes(1024 * 1024),
            max_status_page_size: 256,
        },
        provider_attestation_journal: None,
    };
    validate_config(&config).expect("valid state-free adapter preflight configuration");
    let source = Arc::new(TestAuthenticatedSourceInventoryV1::new(vec![
        [0x22; 32], [0x33; 32],
    ]));
    let signer: Arc<dyn ProviderIngestCompletionSignerV1> = signer;
    let resolver = Arc::new(TestGovernedSignerResolverV1::new(signer));
    (
        config,
        ProviderId::new([0x11; 32]),
        source,
        resolver,
        Arc::new(TestStateFreeCheckpointRuntimeV1::new()),
    )
}
#[tokio::test]
async fn state_free_preflight_accepts_exact_adapters_without_creating_outbox_state() {
    let (config, provider_id, source, resolver, checkpoint) = state_free_preflight_fixture();
    let sentinel_parent = tempfile::tempdir().expect("preflight sentinel parent");
    let state_root = sentinel_parent.path().join("provider-ingest-outbox");
    let source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> = source;
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> = resolver;
    let checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1> = checkpoint.clone();
    let _preflight = preflight_runtime_adapters(
        &config,
        provider_id,
        ProviderIngestRuntimeAdaptersV1::new(source, resolver),
        checkpoint_runtime,
    )
    .await
    .expect("qualify exact state-free provider-ingest adapters");
    assert!(
        !state_root.exists(),
        "state-free preflight must not create local outbox state"
    );
    assert_eq!(checkpoint.qualification_calls.load(Ordering::SeqCst), 2);
    assert_eq!(checkpoint.load_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.compare_and_swap_calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn state_free_preflight_rejects_stale_source_without_creating_outbox_state() {
    let (config, provider_id, source, resolver, checkpoint) = state_free_preflight_fixture();
    *source
        .qualification
        .lock()
        .expect("source qualification lock") =
        ProviderIngestRuntimeProviderQualificationV1::new(6, [0xB1; 32]);
    let sentinel_parent = tempfile::tempdir().expect("preflight sentinel parent");
    let state_root = sentinel_parent.path().join("provider-ingest-outbox");
    let source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> = source;
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> = resolver;
    let checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1> = checkpoint.clone();
    let result = preflight_runtime_adapters(
        &config,
        provider_id,
        ProviderIngestRuntimeAdaptersV1::new(source, resolver),
        checkpoint_runtime,
    )
    .await;
    let error = result.err().expect("stale source qualification must fail");
    assert!(
        error
            .to_string()
            .contains("authenticated source-fetch qualification"),
        "unexpected preflight failure: {error:#}"
    );
    assert!(
        !state_root.exists(),
        "state-free preflight must not create local outbox state"
    );
    assert_eq!(checkpoint.qualification_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.load_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.compare_and_swap_calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn state_free_preflight_rejects_stale_resolver_without_creating_outbox_state() {
    let (config, provider_id, source, resolver, checkpoint) = state_free_preflight_fixture();
    *resolver
        .qualification
        .lock()
        .expect("resolver qualification lock") =
        ProviderIngestRuntimeProviderQualificationV1::new(7, [0xB2; 32]);
    let sentinel_parent = tempfile::tempdir().expect("preflight sentinel parent");
    let state_root = sentinel_parent.path().join("provider-ingest-outbox");
    let source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> = source;
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> = resolver;
    let checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1> = checkpoint.clone();
    let result = preflight_runtime_adapters(
        &config,
        provider_id,
        ProviderIngestRuntimeAdaptersV1::new(source, resolver),
        checkpoint_runtime,
    )
    .await;
    let error = result
        .err()
        .expect("stale resolver qualification must fail");
    assert!(
        error
            .to_string()
            .contains("completion signer-resolver qualification"),
        "unexpected preflight failure: {error:#}"
    );
    assert!(
        !state_root.exists(),
        "state-free preflight must not create local outbox state"
    );
    assert_eq!(checkpoint.qualification_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.load_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.compare_and_swap_calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn state_free_preflight_rejects_stale_checkpoint_without_load_cas_or_local_state() {
    let (config, provider_id, source, resolver, checkpoint) = state_free_preflight_fixture();
    *checkpoint
        .qualification
        .lock()
        .expect("checkpoint qualification lock") =
        ProviderIngestCheckpointProviderQualificationV1::new(8, [0xA7; 32]);
    let sentinel_parent = tempfile::tempdir().expect("preflight sentinel parent");
    let state_root = sentinel_parent.path().join("provider-ingest-outbox");
    let source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> = source;
    let resolver: Arc<dyn ProviderIngestGovernedSignerResolverRuntimeV1> = resolver;
    let checkpoint_runtime: Arc<dyn ProviderIngestCheckpointRuntimeV1> = checkpoint.clone();
    let result = preflight_runtime_adapters(
        &config,
        provider_id,
        ProviderIngestRuntimeAdaptersV1::new(source, resolver),
        checkpoint_runtime,
    )
    .await;
    let error = result
        .err()
        .expect("stale checkpoint qualification must fail");
    assert!(
        error
            .to_string()
            .contains("checkpoint runtime is substituted"),
        "unexpected preflight failure: {error:#}"
    );
    assert!(
        !state_root.exists(),
        "state-free preflight must not create local outbox state"
    );
    assert_eq!(checkpoint.qualification_calls.load(Ordering::SeqCst), 1);
    assert_eq!(checkpoint.load_calls.load(Ordering::SeqCst), 0);
    assert_eq!(checkpoint.compare_and_swap_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn opaque_preflight_is_consumed_and_revalidated_before_worker_assembly() {
    let source = include_str!("../sorafs_provider_ingest_runtime.rs");
    let start = source
        .find("pub(crate) async fn start(")
        .expect("provider-ingest launcher");
    let launch = &source[start..];
    let consume = launch
        .find("let QualifiedProviderIngestRuntimeAdaptersV1")
        .expect("opaque preflight consumption");
    let revalidate = launch
        .find("qualify_provider_ingest_startup")
        .expect("preflight revalidation");
    let assemble = launch
        .find("assemble_native_provider_ingest_runtime")
        .expect("provider-ingest worker assembly");
    assert!(
        consume < revalidate && revalidate < assemble,
        "the opaque token must be consumed and all adapter pins revalidated before state-backed worker assembly"
    );
}
impl ProviderIngestAuthenticatedSourceFetchV1 for TestAuthenticatedSourceInventoryV1 {
    type Fetched = VerifiedProviderIngestPayloadV1;
    fn fetch(
        &self,
        _request: ProviderIngestSourceRequestV1,
    ) -> ProviderIngestFutureV1<
        '_,
        std::result::Result<Self::Fetched, ProviderIngestSourceFetchErrorV1>,
    > {
        if let Some(qualification) = self
            .qualification_after_fetch
            .lock()
            .expect("source fetch mutation lock")
            .take()
        {
            *self
                .qualification
                .lock()
                .expect("source qualification lock") = qualification;
        }
        Box::pin(async { Err(ProviderIngestSourceFetchErrorV1::Unavailable) })
    }
}
impl ProviderIngestAuthenticatedSourceRuntimeV1 for TestAuthenticatedSourceInventoryV1 {
    fn runtime_handle(&self) -> &'static str {
        "https-pinned-source-pool:region-a"
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        ProviderIngestRuntimeProviderQualificationV1,
        ProviderIngestSourceFetchErrorV1,
    > {
        Ok(*self
            .qualification
            .lock()
            .expect("source qualification lock"))
    }
    fn source_provider_ids(&self) -> &[[u8; 32]] {
        &self.provider_ids
    }
    fn check_readiness(&self) -> std::result::Result<(), ProviderIngestSourceFetchErrorV1> {
        if let Some(qualification) = self
            .qualification_after_readiness
            .lock()
            .expect("source readiness mutation lock")
            .take()
        {
            *self
                .qualification
                .lock()
                .expect("source qualification lock") = qualification;
        }
        *self.readiness.lock().expect("source readiness lock")
    }
}
#[test]
fn authenticated_source_inventory_is_multi_provider_canonical_and_identity_stable() {
    let local_provider_id = [0x11; 32];
    let valid = TestAuthenticatedSourceInventoryV1::new(vec![[0x22; 32], [0x33; 32]]);
    assert!(
        validate_authenticated_source_inventory(
            &valid,
            local_provider_id,
            Some(&[[0x22; 32], [0x33; 32]]),
            false,
        )
        .is_ok()
    );
    for invalid in [
        vec![[0x22; 32]],
        vec![[0; 32], [0x22; 32]],
        vec![local_provider_id, [0x22; 32]],
        vec![[0x22; 32], [0x22; 32]],
        vec![[0x33; 32], [0x22; 32]],
    ] {
        let source = TestAuthenticatedSourceInventoryV1::new(invalid);
        assert!(
            validate_authenticated_source_inventory(&source, local_provider_id, None, false)
                .is_err()
        );
    }
    assert!(
        validate_authenticated_source_inventory(
            &valid,
            local_provider_id,
            Some(&[[0x22; 32], [0x44; 32]]),
            false,
        )
        .is_err()
    );
    let oversized = TestAuthenticatedSourceInventoryV1::new(
        (0..=MAX_REPLICATION_ORDER_ASSIGNMENTS)
            .map(|index| {
                let mut provider_id = [0x55; 32];
                provider_id[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("provider index fits u64")
                        .to_be_bytes(),
                );
                provider_id
            })
            .collect(),
    );
    assert!(
        validate_authenticated_source_inventory(&oversized, local_provider_id, None, false)
            .is_err()
    );
}
#[test]
fn authenticated_source_rejects_qualification_drift_across_readiness() {
    let source = TestAuthenticatedSourceInventoryV1::new(vec![[0x22; 32], [0x33; 32]]);
    let expected = ProviderIngestRuntimeProviderQualificationV1::new(5, [0xB1; 32]);
    assert!(validate_authenticated_source_qualification(&source, expected).is_ok());
    *source
        .qualification_after_readiness
        .lock()
        .expect("source readiness mutation lock") = Some(
        ProviderIngestRuntimeProviderQualificationV1::new(6, [0xB4; 32]),
    );
    source.check_readiness().expect("readiness probe");
    assert_eq!(
        validate_authenticated_source_qualification(&source, expected),
        Err(ProviderIngestSourceFetchErrorV1::Rejected)
    );
}
#[test]
fn source_and_resolver_qualifications_remain_independent() {
    let source = ProviderIngestRuntimeProviderQualificationV1::new(5, [0xB1; 32]);
    let resolver = ProviderIngestRuntimeProviderQualificationV1::new(6, [0xB2; 32]);
    assert!(source.is_valid());
    assert!(resolver.is_valid());
    assert_ne!(source, resolver);
}
#[test]
fn worker_liveness_guard_fails_readiness_closed_on_every_exit() {
    let running = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicBool::new(true));
    {
        let _guard = ProviderIngestWorkerLivenessGuardV1::new(running.clone(), in_flight.clone());
        assert!(running.load(Ordering::Acquire));
        assert!(in_flight.load(Ordering::Acquire));
    }
    assert!(!running.load(Ordering::Acquire));
    assert!(!in_flight.load(Ordering::Acquire));
}
#[test]
fn completed_cursor_consistency_rejects_historical_and_head_forks() {
    let committed_hashes = (1_u8..=10)
        .map(|byte| HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([byte; 32])))
        .collect::<Vec<_>>();
    let cursor_hash = *committed_hashes[8].as_ref();
    let head_hash = *committed_hashes[9].as_ref();
    let journal = iroha_core::state::BlockHashes::new(committed_hashes);
    let committed_hashes = journal.view();
    let cursor = ProviderIngestFinalizedCursorV1 {
        height: 9,
        block_hash: cursor_hash,
    };
    assert!(!completed_cursor_matches_committed_chain(
        None,
        10,
        head_hash,
        &committed_hashes
    ));
    assert!(completed_cursor_matches_committed_chain(
        Some(cursor),
        10,
        head_hash,
        &committed_hashes
    ));
    assert!(!completed_cursor_matches_committed_chain(
        Some(ProviderIngestFinalizedCursorV1 {
            height: 9,
            block_hash: [0xA9; 32],
        }),
        10,
        head_hash,
        &committed_hashes
    ));
    assert!(!completed_cursor_matches_committed_chain(
        Some(cursor),
        10,
        [0xAA; 32],
        &committed_hashes
    ));
    assert!(!completed_cursor_matches_committed_chain(
        Some(cursor),
        9,
        cursor_hash,
        &committed_hashes
    ));
}
#[test]
fn completion_payload_anchor_accepts_an_authenticated_committed_prefix() {
    let committed_hashes = (1_u8..=10)
        .map(|byte| HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([byte; 32])))
        .collect::<Vec<_>>();
    let cursor = ProviderIngestFinalizedCursorV1 {
        height: 9,
        block_hash: *committed_hashes[8].as_ref(),
    };
    let head_hash = *committed_hashes[9].as_ref();
    let journal = iroha_core::state::BlockHashes::new(committed_hashes);
    let committed_hashes = journal.view();
    let finalized_at_unix_ms = 1_700_000_009_999;
    let completion_epoch = 1_700_000_009;
    let head_at_unix_ms = 1_700_000_010_123;
    assert!(completion_payload_anchor_matches_committed_chain(
        cursor,
        completion_epoch,
        finalized_at_unix_ms,
        10,
        head_hash,
        head_at_unix_ms,
        &committed_hashes,
    ));
    assert!(!completion_payload_anchor_matches_committed_chain(
        ProviderIngestFinalizedCursorV1 {
            block_hash: [0xA9; 32],
            ..cursor
        },
        completion_epoch,
        finalized_at_unix_ms,
        10,
        head_hash,
        head_at_unix_ms,
        &committed_hashes,
    ));
    assert!(!completion_payload_anchor_matches_committed_chain(
        cursor,
        completion_epoch + 1,
        finalized_at_unix_ms,
        10,
        head_hash,
        head_at_unix_ms,
        &committed_hashes,
    ));
    assert!(!completion_payload_anchor_matches_committed_chain(
        cursor,
        completion_epoch,
        finalized_at_unix_ms,
        10,
        [0xAA; 32],
        head_at_unix_ms,
        &committed_hashes,
    ));
    assert!(!completion_payload_anchor_matches_committed_chain(
        cursor,
        cursor.height,
        finalized_at_unix_ms,
        10,
        head_hash,
        head_at_unix_ms,
        &committed_hashes,
    ));
    assert!(!completion_payload_anchor_matches_committed_chain(
        cursor,
        completion_epoch,
        finalized_at_unix_ms,
        10,
        head_hash,
        finalized_at_unix_ms - 1_000,
        &committed_hashes,
    ));
}
#[test]
fn cancelling_store_wait_joins_late_writer() {
    let completed = Arc::new(AtomicBool::new(false));
    let late = Arc::clone(&completed);
    let thread =
        crate::panic_recovery::spawn_thread_recoverable(std::thread::Builder::new(), move || {
            std::thread::sleep(Duration::from_millis(10));
            late.store(true, Ordering::Release);
        })
        .expect("spawn late store writer");
    drop(BlockingStoreJoinGuardV1(Some(thread)));
    assert!(completed.load(Ordering::Acquire));
}
#[test]
fn newly_admitted_manifest_verification_enters_logical_quarantine() {
    let exact = ProviderIngestLocalStoredV1::generic("exact-manifest".to_owned());
    assert_eq!(
        finish_newly_admitted_manifest_verification("exact-manifest", Ok(Some(exact.clone()))),
        Ok(exact)
    );
    for rejected in [
        Ok(Some(ProviderIngestLocalStoredV1::generic(
            "substituted-manifest".to_owned(),
        ))),
        Ok(None),
        Err(ProviderIngestLocalStorageErrorV1::Permanent),
        Err(ProviderIngestLocalStorageErrorV1::Quarantined),
    ] {
        assert_eq!(
            finish_newly_admitted_manifest_verification("exact-manifest", rejected),
            Err(ProviderIngestLocalStorageErrorV1::Quarantined),
            "a permanent post-admission rejection must retain shared storage and quarantine the job"
        );
    }
    assert_eq!(
        finish_newly_admitted_manifest_verification(
            "exact-manifest",
            Err(ProviderIngestLocalStorageErrorV1::Retryable),
        ),
        Err(ProviderIngestLocalStorageErrorV1::Retryable),
        "a transient post-admission read failure remains retryable"
    );
}
#[test]
fn deadline_bounded_reader_authenticates_terminal_eof_once() {
    let payload = b"authenticated provider payload".to_vec();
    let expected_len = u64::try_from(payload.len()).expect("payload length fits u64");
    let (inner, terminal_probe_count, terminal_probe_width) =
        TestTerminalReaderV1::new(payload.clone(), TestTerminalBehaviorV1::Eof);
    let mut reader =
        DeadlineBoundedReaderV1::new(Box::new(inner), Duration::from_secs(1), expected_len);
    let mut observed = Vec::new();
    reader
        .read_to_end(&mut observed)
        .expect("authenticate terminal EOF");
    assert_eq!(observed, payload);
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
    assert_eq!(terminal_probe_width.load(Ordering::SeqCst), 1);
    let mut trailing = [0_u8; 8];
    assert_eq!(reader.read(&mut trailing).expect("cached EOF"), 0);
    assert_eq!(
        terminal_probe_count.load(Ordering::SeqCst),
        1,
        "authenticated EOF must not re-enter the underlying transport"
    );
}
#[test]
fn deadline_bounded_reader_rejects_premature_eof() {
    let payload = b"short".to_vec();
    let expected_len = u64::try_from(payload.len() + 1).expect("payload length fits u64");
    let (inner, terminal_probe_count, _) =
        TestTerminalReaderV1::new(payload.clone(), TestTerminalBehaviorV1::Eof);
    let mut reader =
        DeadlineBoundedReaderV1::new(Box::new(inner), Duration::from_secs(1), expected_len);
    let mut observed = Vec::new();
    let error = reader
        .read_to_end(&mut observed)
        .expect_err("premature EOF must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(observed, payload);
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
    let mut trailing = [0_u8; 1];
    assert_eq!(
        reader
            .read(&mut trailing)
            .expect_err("premature EOF failure is sticky")
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
}
#[test]
fn deadline_bounded_reader_propagates_terminal_verification_failures() {
    for (kind, message) in [
        (
            io::ErrorKind::InvalidData,
            "authenticated source trailer rejected",
        ),
        (
            io::ErrorKind::PermissionDenied,
            "authenticated source qualification drifted",
        ),
    ] {
        let payload = b"exact bytes".to_vec();
        let expected_len = u64::try_from(payload.len()).expect("payload length fits u64");
        let (inner, terminal_probe_count, terminal_probe_width) = TestTerminalReaderV1::new(
            payload.clone(),
            TestTerminalBehaviorV1::Error { kind, message },
        );
        let mut reader =
            DeadlineBoundedReaderV1::new(Box::new(inner), Duration::from_secs(1), expected_len);
        let mut observed = vec![0_u8; payload.len()];
        reader
            .read_exact(&mut observed)
            .expect("read exact authorized bytes");
        assert_eq!(observed, payload);
        let mut trailing = [0_u8; 8];
        let error = reader
            .read(&mut trailing)
            .expect_err("terminal source verification must propagate");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), message);
        assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
        assert_eq!(terminal_probe_width.load(Ordering::SeqCst), 1);
        assert_eq!(
            reader
                .read(&mut trailing)
                .expect_err("terminal verification failure is sticky")
                .kind(),
            kind
        );
        assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn deadline_bounded_reader_rejects_extra_bytes_at_terminal_probe() {
    let payload = b"exact bytes".to_vec();
    let expected_len = u64::try_from(payload.len()).expect("payload length fits u64");
    let (inner, terminal_probe_count, terminal_probe_width) =
        TestTerminalReaderV1::new(payload.clone(), TestTerminalBehaviorV1::ExtraByte(0xA5));
    let mut reader =
        DeadlineBoundedReaderV1::new(Box::new(inner), Duration::from_secs(1), expected_len);
    let mut observed = vec![0_u8; payload.len()];
    reader
        .read_exact(&mut observed)
        .expect("read exact authorized bytes");
    let mut trailing = [0_u8; 8];
    assert_eq!(
        reader
            .read(&mut trailing)
            .expect_err("extra byte must fail closed")
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
    assert_eq!(terminal_probe_width.load(Ordering::SeqCst), 1);
    assert_eq!(
        reader
            .read(&mut trailing)
            .expect_err("extra-byte failure is sticky")
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
}
#[test]
fn deadline_bounded_reader_checks_deadline_after_terminal_probe() {
    let payload = b"exact bytes".to_vec();
    let expected_len = u64::try_from(payload.len()).expect("payload length fits u64");
    let clock = Arc::new(TestClockV1::new());
    let (inner, terminal_probe_count, terminal_probe_width) = TestTerminalReaderV1::new(
        payload.clone(),
        TestTerminalBehaviorV1::AdvancingEof {
            clock: Arc::clone(&clock),
            advance: Duration::from_secs(2),
        },
    );
    let reader_clock = Arc::clone(&clock);
    let mut reader = DeadlineBoundedReaderV1::new_with_clock(
        Box::new(inner),
        Duration::from_secs(1),
        expected_len,
        Arc::new(move || reader_clock.now()),
    );
    let mut observed = vec![0_u8; payload.len()];
    reader
        .read_exact(&mut observed)
        .expect("read exact authorized bytes before deadline");
    let mut trailing = [0_u8; 8];
    assert_eq!(
        reader
            .read(&mut trailing)
            .expect_err("late terminal EOF must fail closed")
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(terminal_probe_count.load(Ordering::SeqCst), 1);
    assert_eq!(terminal_probe_width.load(Ordering::SeqCst), 1);
    assert_eq!(
        reader
            .read(&mut trailing)
            .expect_err("post-probe deadline failure is sticky")
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        terminal_probe_count.load(Ordering::SeqCst),
        1,
        "sticky timeout must not re-enter the underlying transport"
    );
}
#[test]
fn archive_binding_storage_failures_are_permanent() {
    for error in [
        StorageError::ManifestChunkPlanDigestMismatch,
        StorageError::CarArchiveReconstruction {
            reason: "staged chunk is corrupt".to_owned(),
        },
        StorageError::ManifestCarArchiveDigestMismatch,
        StorageError::ManifestCarSizeMismatch {
            expected: 128,
            actual: 127,
        },
        StorageError::ManifestDagCodecMismatch {
            expected: 0x71,
            actual: 0x55,
        },
    ] {
        assert_eq!(
            classify_storage_error(&NodeStorageError::Storage(error)),
            ProviderIngestLocalStorageErrorV1::Permanent
        );
    }
    for error in [
        ChunkStoreError::UnexpectedEof {
            chunk_index: 0,
            expected: 64,
        },
        ChunkStoreError::DigestMismatch { chunk_index: 0 },
        ChunkStoreError::LengthMismatch {
            expected: 64,
            actual: 65,
        },
        ChunkStoreError::PayloadDigestMismatch,
    ] {
        assert_eq!(
            classify_storage_error(&NodeStorageError::Storage(StorageError::ChunkStore(error))),
            ProviderIngestLocalStorageErrorV1::Permanent
        );
    }
}
#[test]
fn admitted_musubi_verification_classifies_storage_failures() {
    assert_eq!(
        classify_completed_attestation_manifest_lookup_error(&NodeStorageError::Disabled),
        ProviderIngestLocalStorageErrorV1::Permanent,
        "statically disabled storage cannot become available on retry"
    );
    assert_eq!(
        classify_completed_attestation_manifest_lookup_error(&NodeStorageError::Storage(
            StorageError::ManifestNotFound {
                manifest_id: "temporarily-absent-completed-bundle".to_owned(),
            },
        )),
        ProviderIngestLocalStorageErrorV1::Retryable,
        "an admitted bundle may be reconciled back into storage"
    );
    assert_eq!(
        classify_admitted_payload_lease_error(AdmittedPayloadReadLeaseErrorV1::StorageUnavailable,),
        ProviderIngestLocalStorageErrorV1::Retryable
    );
    assert_eq!(
        classify_admitted_payload_lease_error(AdmittedPayloadReadLeaseErrorV1::NotAdmitted),
        ProviderIngestLocalStorageErrorV1::Retryable
    );
    assert_eq!(
        classify_admitted_payload_lease_error(AdmittedPayloadReadLeaseErrorV1::Disabled),
        ProviderIngestLocalStorageErrorV1::Permanent
    );
    assert!(admitted_payload_read_error_is_retryable(
        io::ErrorKind::Interrupted
    ));
    assert!(admitted_payload_read_error_is_retryable(
        io::ErrorKind::WouldBlock
    ));
    assert!(admitted_payload_read_error_is_retryable(
        io::ErrorKind::TimedOut
    ));
    assert!(admitted_payload_read_error_is_retryable(
        io::ErrorKind::NotFound
    ));
    assert!(admitted_payload_read_error_is_retryable(
        io::ErrorKind::Other
    ));
    assert!(!admitted_payload_read_error_is_retryable(
        io::ErrorKind::InvalidData
    ));
    assert!(!admitted_payload_read_error_is_retryable(
        io::ErrorKind::UnexpectedEof
    ));
    assert!(!admitted_payload_read_error_is_retryable(
        io::ErrorKind::PermissionDenied
    ));
    let transient = StorageError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "injected transient storage read",
    ));
    assert_eq!(
        classify_storage_backend_error(&transient),
        ProviderIngestLocalStorageErrorV1::Retryable
    );
}
#[tokio::test]
async fn daemon_dependency_probe_allows_one_ready_source_for_request_failover() {
    let source: Arc<dyn ProviderIngestAuthenticatedSourceRuntimeV1> = Arc::new(
        test_runtime_source_pool(Err(ProviderIngestSourceFetchErrorV1::Unavailable), Ok(())),
    );
    let result = probe_runtime_dependencies(
        source,
        test_readiness_resolver(Ok(())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result, RuntimeDependencyProbeV1::Ready);
}
#[tokio::test]
async fn daemon_dependency_probe_preserves_rejected_and_unavailable_outcomes() {
    let unavailable = probe_runtime_dependencies(
        test_readiness_source(Err(ProviderIngestSourceFetchErrorV1::Unavailable)),
        test_readiness_resolver(Ok(())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(unavailable, RuntimeDependencyProbeV1::Unavailable);
    let source_rejected = probe_runtime_dependencies(
        test_readiness_source(Err(ProviderIngestSourceFetchErrorV1::Rejected)),
        test_readiness_resolver(Ok(())),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(source_rejected, RuntimeDependencyProbeV1::Rejected);
    let signer_unavailable = probe_runtime_dependencies(
        test_readiness_source(Ok(())),
        test_readiness_resolver(Err(
            ProviderIngestCompletionSignerResolverErrorV1::Unavailable,
        )),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(signer_unavailable, RuntimeDependencyProbeV1::Unavailable);
    let signer_rejected = probe_runtime_dependencies(
        test_readiness_source(Ok(())),
        test_readiness_resolver(Err(ProviderIngestCompletionSignerResolverErrorV1::Rejected)),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(signer_rejected, RuntimeDependencyProbeV1::Rejected);
}
#[tokio::test]
async fn hung_readiness_probe_fails_at_explicit_deadline() {
    let result = bounded_blocking_readiness_probe(Duration::from_millis(1), || {
        std::thread::sleep(Duration::from_millis(25));
        RuntimeDependencyProbeV1::Ready
    })
    .await;
    assert_eq!(result, RuntimeDependencyProbeV1::TimedOut);
}
#[tokio::test]
async fn panicked_readiness_probe_is_distinct_from_transient_timeout() {
    let result = bounded_blocking_readiness_probe(Duration::from_secs(1), || {
        panic!("synthetic readiness probe panic");
    })
    .await;
    assert_eq!(result, RuntimeDependencyProbeV1::Panicked);
}
#[test]
fn provider_attestation_journal_policy_maps_exactly_and_revalidates_actual_config() {
    let configured = SorafsProviderAttestationJournal {
        clock: SorafsProviderAttestationRuntimeBinding {
            handle: "provider://musubi/provider-attestation/clock-seal".to_owned(),
            revision: 1,
            policy_digest: [0xA1; 32],
        },
        approval_signer: SorafsProviderAttestationRuntimeBinding {
            handle: "provider://musubi/provider-attestation/approval-signer".to_owned(),
            revision: 2,
            policy_digest: [0xA2; 32],
        },
        inventory: SorafsProviderAttestationRuntimeBinding {
            handle: "service://musubi/provider-attestation/inventory".to_owned(),
            revision: 3,
            policy_digest: [0xA3; 32],
        },
        max_entries: 8,
        max_attempts: 3,
        lease_ttl_ms: 30_000,
        approval_timeout_ms: 5_000,
        handoff_timeout_ms: 6_000,
        retry_delay_ms: 1_000,
        checkpoint_max_bytes: 4 * 1024 * 1024,
        max_cas_retries: 5,
    };
    let policy = provider_attestation_journal_policy(&configured)
        .expect("valid direct actual policy must map");
    assert_eq!(
        policy,
        MusubiProviderAttestationJournalPolicyV1 {
            max_entries: configured.max_entries,
            max_attempts: configured.max_attempts,
            lease_ttl_ms: configured.lease_ttl_ms,
            approval_timeout_ms: configured.approval_timeout_ms,
            handoff_timeout_ms: configured.handoff_timeout_ms,
            retry_delay_ms: configured.retry_delay_ms,
            checkpoint_max_bytes: configured.checkpoint_max_bytes,
            max_cas_retries: configured.max_cas_retries,
        }
    );
    let mut invalid = configured;
    invalid.max_entries = 0;
    assert!(
        provider_attestation_journal_policy(&invalid).is_err(),
        "programmatically constructed actual config must not bypass policy validation"
    );
    invalid.max_entries = 8;
    invalid.inventory.policy_digest = [0; 32];
    assert!(
        provider_attestation_journal_policy(&invalid).is_err(),
        "programmatically constructed actual config must not bypass binding validation"
    );
}
#[test]
fn only_temporary_finalized_ledger_loss_is_a_retryable_tick_error() {
    assert!(provider_ingest_tick_error_is_transient(
        &ProviderIngestRuntimeErrorV1::FinalizedLedgerUnavailable
    ));
    assert!(!provider_ingest_tick_error_is_transient(
        &ProviderIngestRuntimeErrorV1::InvalidFinalizedPage
    ));
}

#[test]
fn committed_provider_observation_uses_only_the_matching_network_output() {
    use iroha_data_model::{
        block::{
            builder::BlockBuilder,
            execution_output::{
                ExecutionOutputV1, NetworkExecutionOutputV1, TimeExecutionOutputV1,
                TimeInvocationV1, TriggerUseV1,
            },
            output_budget::ExecutionOutputLimits,
        },
        events::time::{TimeEvent, TimeInterval},
        transaction::{
            error::{TransactionLimitError, TransactionRejectionReason},
            signed::TransactionResult,
        },
        trigger::DataTriggerStep,
    };
    let key = KeyPair::try_from_seed(vec![0x53; 32], Algorithm::Ed25519).unwrap();
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"provider observation fixture network",
    )));
    let transaction = |time| {
        let mut builder = TransactionBuilder::new(
            network_id,
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(time));
        builder.sign(key.private_key())
    };
    let rejected = transaction(10);
    let accepted = transaction(11);
    let unknown = transaction(12);
    let mut builder = BlockBuilder::new(BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        Some(HashOf::from_untyped_unchecked(Hash::new(
            b"provider parent",
        ))),
        None,
        20,
        0,
    ));
    builder.push_transaction(rejected.clone());
    builder.push_transaction(accepted.clone());
    let mut block = builder.build_with_signature(0, key.private_key());
    assert_eq!(
        observe_committed_provider_transaction(&block, accepted.hash()),
        ProviderIngestTransactionObservationV1::Unavailable,
        "a signed proposal has no committed output",
    );
    let trigger_id: iroha_data_model::trigger::TriggerId =
        "provider_observation_time".parse().unwrap();
    let outputs = vec![
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result: TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
                TransactionLimitError {
                    reason: "fixture rejection".to_owned(),
                },
            ))),
            completions: Vec::new(),
        }),
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 1,
            result: TransactionResult::new(Ok(Vec::new())),
            completions: Vec::new(),
        }),
        ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: TimeInvocationV1 {
                schedule_index: 0,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 19,
                        length_ms: 1,
                    },
                },
                trigger: TriggerUseV1 {
                    trigger_id: trigger_id.clone(),
                    registered_at_height: 1,
                    action_hash: Hash::new(b"structural provider fixture action"),
                },
            },
            result: TransactionResult::new(Ok(vec![DataTriggerStep {
                id: trigger_id,
                instructions: iroha_data_model::transaction::signed::ExecutionStep(
                    Vec::new().into(),
                ),
            }])),
            failure_root: None,
            completions: Vec::new(),
        }),
    ];
    // A finite structural model fixture grants no execution or finality authority.
    let limits = ExecutionOutputLimits {
        max_outputs: 3,
        max_output_bytes: 1024 * 1024,
        max_total_output_bytes: 3 * 1024 * 1024,
        max_executed_wire_bytes: 4 * 1024 * 1024,
    };
    block
        .set_execution_outputs(
            outputs,
            0,
            std::collections::BTreeMap::default(),
            Vec::new(),
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &limits,
        )
        .unwrap();
    assert_eq!(block.network_entrypoint_count(), 2);
    assert_eq!(block.execution_outputs().len(), 3);
    assert_eq!(
        observe_committed_provider_transaction(&block, rejected.hash()),
        ProviderIngestTransactionObservationV1::CommittedRejected,
    );
    assert_eq!(
        observe_committed_provider_transaction(&block, accepted.hash()),
        ProviderIngestTransactionObservationV1::CommittedSuccess,
    );
    assert_eq!(
        observe_committed_provider_transaction(&block, unknown.hash()),
        ProviderIngestTransactionObservationV1::Unavailable,
        "a successful Time output cannot stand in for an absent Network input",
    );
}

/// Component adapter control: the current-row test owner is explicit, not native finality evidence.
#[tokio::test]
async fn governed_signer_keeps_dedicated_completion_key_separate_from_current_owner() {
    let (signer, current, provider, _) = test_governed_signer(test_signer_policy(1), None);
    let owner_key = KeyPair::try_from_seed(vec![0x7A; 32], Algorithm::Ed25519).unwrap();
    let expected = ProviderIngestCompletionAuthorityV1::new(
        AccountId::new(owner_key.public_key().clone()),
        signer.authority().clone(),
        test_signer_policy(1),
    );
    *current.authority.lock().unwrap() = expected.clone();
    let context = ProviderIngestCompletionSignerResolutionContextV1::new(
        expected.clone(),
        1,
        signer_test_cursor(),
    );
    let adapter = governed_signer_adapter(Arc::clone(&signer), current.clone(), provider);
    let governed = adapter.resolve(context.clone()).await.unwrap().unwrap();
    let mut builder = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x15; Hash::LENGTH]),
        )),
        expected.completion_signer.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([InstructionBox::from(CompleteReplicationOrder {
        order_id: ReplicationOrderId::new([0x31; 32]),
        provider_id: provider,
        completion_epoch: 8,
        expected_authority: expected.clone(),
        expected_assignment_revision: 1,
        finalized_anchor: ProviderIngestFinalizedAnchorV1 {
            height: 8,
            block_hash: [0xB2; 32],
        },
    })]);
    builder.set_creation_time(Duration::from_secs(1));
    builder.set_ttl(Duration::from_secs(30));
    let payload = builder.into_payload().unwrap();
    let transaction = governed.sign(payload.clone()).await.unwrap();
    assert_eq!(transaction.authority(), &expected.completion_signer);
    assert_ne!(transaction.authority(), &expected.provider_owner);
    assert_eq!(signer.sign_calls.load(Ordering::SeqCst), 1);
    // Same policy bytes do not make a changed native completion account equivalent.
    current.authority.lock().unwrap().completion_signer = expected.provider_owner.clone();
    assert_eq!(
        governed.sign(payload).await,
        Err(ProviderIngestCompletionSignerErrorV1::Unavailable)
    );
    assert_eq!(signer.sign_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        adapter.resolve(context).await,
        Err(ProviderIngestCompletionSignerResolverErrorV1::Unavailable)
    ));
}

/// Configuration specimen for native custody tests; it is not native current-state evidence.
pub(super) fn native_attestation_test_config() -> SorafsProviderIngestRuntime {
    state_free_preflight_fixture().0
}
