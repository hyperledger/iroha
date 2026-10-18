//! Permission-proof and durable-resume gates; synthetic World cuts do not execute payments.

use super::*;
use iroha::workflow::{
    BuiltStepPayload, DriverIdentityV1, FileWorkflowStorage, StepContext, StepDescriptorV1,
    WorkflowClock, WorkflowDriver, WorkflowEngine, WorkflowKindV1, WorkflowPlanV1,
    WorkflowRunOptions,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::Account,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetId},
    isi::sumeragi_amx::PrepareAmxV1,
    permission::Permissions,
    sumeragi_amx::{
        AmxBeginV1, AmxCertifiedBlockV1, AmxDebitApprovalProofV1, AmxLegV1, AmxRecordProofV1,
        AmxRecordV1, AmxTransactionV1, AmxTransferLegV1, AmxWriteProofV1,
    },
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
        test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
    transaction::TransactionBuilder,
};
use iroha_model_base::topology::DataSpaceId;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicU64},
    time::Duration,
};

// These are source failures only; no synthetic success or consensus branch is added.
#[derive(Clone, Copy, Debug)]
enum ApprovalFailure {
    Capacity,
    CutChanged,
    Unclassified,
    Permission,
    Signing,
    Proof,
    FinalityProof,
    MalformedProof,
    ResponseBinding,
    Listener,
}
impl ApprovalFailure {
    fn report(self, approval: &AmxDebitApprovalV1, relay: &AccountId, height: u64) -> eyre::Report {
        match self {
            Self::Capacity => iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1::new(
                approval,
                relay,
                height,
                iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::Capacity,
                None,
            )
            .unwrap()
            .into(),
            Self::CutChanged => {
                iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1::new(
                    approval,
                    relay,
                    height,
                    iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::CutChanged,
                    Some(height + 1),
                )
                .unwrap()
                .into()
            }
            Self::Unclassified => iroha::Error::Http {
                operation: "amx.debit_approval",
                status: 503,
                retry_after: None,
                body: vec![],
            }
            .into(),
            Self::Permission => iroha::Error::Http {
                operation: "amx.debit_approval",
                status: 403,
                retry_after: None,
                body: vec![],
            }
            .into(),
            Self::Signing => iroha::Error::RequestSigning {
                operation: "amx.debit_approval",
                details: "fixture signing custody unavailable".into(),
            }
            .into(),
            Self::Proof => iroha_data_model::sumeragi_finality::FinalityError(
                "approval proof substituted its certified root".into(),
            )
            .into(),
            Self::FinalityProof => iroha_data_model::sumeragi_finality::FinalityReadError::Invalid(
                iroha_data_model::sumeragi_finality::FinalityError(
                    "original finality trust binding failed".into(),
                ),
            )
            .into(),
            Self::MalformedProof => {
                iroha::Error::CanonicalDecode(Box::new(iroha::CanonicalDecodeFailure {
                    operation: "amx.debit_approval",
                    source: norito::core::classify_decode_attempt(|| {
                        AmxDebitApprovalProofV1::decode_frame(b"malformed canonical AMX proof")
                    })
                    .unwrap_err(),
                }))
                .into()
            }
            Self::ResponseBinding => iroha::Error::ResponseBinding {
                operation: "amx.debit_approval",
                field: "independently selected relay and bank root",
            }
            .into(),
            Self::Listener => iroha::Error::Http {
                operation: "amx.debit_approval",
                status: 404,
                retry_after: None,
                body: vec![],
            }
            .into(),
        }
    }
    fn code(self) -> WorkflowErrorCode {
        match self {
            Self::Capacity => WorkflowErrorCode::LocalResourceUnavailable,
            Self::CutChanged | Self::Unclassified => WorkflowErrorCode::EvidenceUnavailable,
            Self::Permission | Self::Signing => WorkflowErrorCode::AuthorizationDenied,
            Self::Proof | Self::FinalityProof => WorkflowErrorCode::ProofInvalid,
            Self::MalformedProof => WorkflowErrorCode::NonCanonicalEncoding,
            Self::ResponseBinding => WorkflowErrorCode::BindingMismatch,
            Self::Listener => WorkflowErrorCode::UnsupportedOperation,
        }
    }
}

struct ApprovalSource {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    proof: AmxDebitApprovalProofV1,
    available: Arc<AtomicBool>,
    reported_height: AtomicU64,
    approval_heights: Mutex<Vec<u64>>,
    failure: Mutex<ApprovalFailure>,
}
impl Source for ApprovalSource {
    fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>> {
        Box::pin(async { Ok(self.reported_height.load(Ordering::Relaxed)) })
    }
    fn locate(&self, _: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
        Box::pin(async { Ok(Location::Absent) })
    }
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
        Box::pin(async move {
            self.proofs
                .get(&height.get())
                .cloned()
                .ok_or_else(|| eyre!("proof unavailable"))
        })
    }
    fn approval<'a>(
        &'a self,
        approval: &'a AmxDebitApprovalV1,
        relay: &'a AccountId,
        schema: Hash,
        block: &'a VerifiedSumeragiBlock,
    ) -> WorkflowFuture<'a, Result<VerifiedAmxDebitApprovalV1>> {
        Box::pin(async move {
            self.approval_heights.lock().unwrap().push(block.height());
            if !self.available.load(Ordering::Relaxed) {
                return Err(self
                    .failure
                    .lock()
                    .unwrap()
                    .report(approval, relay, block.height()));
            }
            Ok(self.proof.verify(approval, relay, schema, block)?)
        })
    }
}
struct Custody {
    signed: SignedTransaction,
    signs: AtomicUsize,
    sends: AtomicUsize,
    available: Arc<AtomicBool>,
}
impl Custody {
    fn identity(&self) -> TransactionIdentityV1 {
        TransactionIdentityV1 {
            signed_transaction_hash: *Hash::from(self.signed.hash()).as_ref(),
            entrypoint_hash: *Hash::from(self.signed.hash_as_entrypoint()).as_ref(),
        }
    }
}
impl WorkflowAccount for Custody {
    fn binding(&self) -> WorkflowBindingV1 {
        WorkflowBindingV1 {
            network: "approval-bank-fixture".into(),
            authority: "separate-relay-fixture".into(),
        }
    }
    fn sign<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            assert_eq!(
                bytes,
                norito::encode_canonical(self.signed.payload()).unwrap()
            );
            self.signs.fetch_add(1, Ordering::Relaxed);
            // A revoke/cut change between signing and dispatch must be observed by the second gate.
            self.available.store(false, Ordering::Relaxed);
            Ok(SignedStepTransaction {
                signed_transaction: self.signed.encode_wire_v1().unwrap(),
                identity: self.identity(),
            })
        })
    }
    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        if bytes != self.signed.encode_wire_v1().unwrap() {
            return Err(StepFailure::new(
                WorkflowErrorCode::BindingMismatch,
                "fixture bytes changed",
            ));
        }
        Ok(self.identity())
    }
}
impl WorkflowLedger for Custody {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            assert_eq!(self.identify(bytes).unwrap(), *identity);
            self.sends.fetch_add(1, Ordering::Relaxed);
            DispatchOutcome::Ambiguous {
                detail: "fixture keeps carrier unresolved".into(),
            }
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        panic!("only original proof owner observes outcomes")
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
fn fixture() -> (
    Arc<RelayLedger>,
    Arc<Custody>,
    AmxDebitApprovalV1,
    Arc<ApprovalSource>,
) {
    let parent = NativeFinalityFixture::new().network_id();
    let ds = DataSpaceId::new(7);
    let mut native = NativeFinalityFixture::start_with_scope(
        "amx-relay-approved-bank",
        SumeragiRootScope::Dataspace {
            parent_network_id: parent,
            dataspace_id: ds,
        },
    );
    let verifier = native.verifier();
    let key = KeyPair::from_seed(vec![82; 32], Algorithm::Ed25519);
    let relay = AccountId::new(key.public_key().clone());
    let owner = AccountId::new(
        KeyPair::from_seed(vec![81; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let asset = AssetId::with_scope(
        "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
        owner.clone(),
        AssetBalanceScope::Dataspace(ds),
    );
    let transaction = AmxTransactionV1 {
        legs: [ds, DataSpaceId::new(8)]
            .into_iter()
            .map(|dataspace| AmxLegV1 {
                dataspace,
                payload: norito::encode_canonical(&AmxTransferLegV1 {
                    source: AssetId::with_scope(
                        asset.definition().clone(),
                        owner.clone(),
                        AssetBalanceScope::Dataspace(dataspace),
                    ),
                    destination: relay.clone(),
                    amount: 7_u32.into(),
                })
                .unwrap(),
            })
            .collect(),
        deadline: 10,
        expires_at_ms: 1_000_000,
        nonce: [81; 32],
    };
    let approval = AmxDebitApprovalV1 {
        global_network: parent,
        participant_network: native.network_id(),
        participant_instance: verifier.instance().0,
        dataspace: ds,
        transaction_id: transaction.id().unwrap(),
        debited_asset: asset,
    };
    // Only the service gate is under test here; native tests independently authenticate Begin.
    let begin = AmxRecordProofV1 {
        block: AmxCertifiedBlockV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        },
        record: AmxRecordV1::Begin(AmxBeginV1 {
            tx: approval.transaction_id,
            participants: vec![ds, DataSpaceId::new(8)],
            deadline: 10,
            expires_at_ms: 1_000_000,
        }),
        write: AmxWriteProofV1 {
            present: [0; 32],
            siblings: vec![],
        },
    };
    let instruction: InstructionBox = PrepareAmxV1 {
        dataspace: ds,
        transaction,
        begin,
    }
    .into();
    let digest = instruction_digest(&instruction).unwrap();
    let fee = FeePaymentIntent::authority(vec![], None);
    let signed = TransactionBuilder::new(native.network_id(), relay.clone(), fee.clone())
        .with_instructions([instruction])
        .sign(key.private_key());
    let permissions = Permissions::from([approval.permission().unwrap()]);
    let mut entries = vec![];
    for id in [&owner, &relay] {
        let (_, account) = Account::new(id.clone()).build(&owner).into_key_value();
        entries.push(row("world.accounts", id, &account));
    }
    let definition = AssetDefinition::numeric(
        approval.debited_asset.definition().clone(),
        "approval fixture",
        AssetBalancePolicy::DataspaceRestricted,
        None,
    )
    .build(&owner);
    entries.push(row(
        "world.asset_definitions",
        approval.debited_asset.definition(),
        &definition,
    ));
    entries.push(row("world.account_permissions", &relay, &permissions));
    entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
    let proof = AmxDebitApprovalProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
            entries,
        },
        relay_permissions: permissions,
    };
    let block = native.block_with_submitted_work(native.next_header());
    let h2 = native.certify_with_world_root(block, proof.world.root().unwrap());
    let block = native.block_with_submitted_work(native.next_header());
    let h3 = native.certify_with_world_root(block, Hash::new(b"later revoked permission cut"));
    let available = Arc::new(AtomicBool::new(false));
    let custody = Arc::new(Custody {
        signed,
        signs: AtomicUsize::new(0),
        sends: AtomicUsize::new(0),
        available: available.clone(),
    });
    let source = Arc::new(ApprovalSource {
        proofs: [(1, native.genesis_proof().clone()), (2, h2), (3, h3)].into(),
        proof,
        available,
        reported_height: AtomicU64::new(2),
        approval_heights: Mutex::new(vec![]),
        failure: Mutex::new(ApprovalFailure::Capacity),
    });
    let ledger = Arc::new(RelayLedger {
        source: source.clone(),
        dispatch: custody.clone(),
        verifier: Mutex::new(verifier),
        network: native.network_id(),
        authority: relay,
        fee_payment: fee,
        instruction: Mutex::new(Some(digest)),
        approval: Mutex::new(Some(approval.clone())),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads: 8,
        reads: AtomicUsize::new(8),
    });
    (ledger, custody, approval, source)
}
struct Driver(Vec<u8>);
impl WorkflowDriver for Driver {
    fn identity(&self) -> DriverIdentityV1 {
        super::super::driver_identity()
    }
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            Ok(BuiltStepPayload {
                unsigned_payload: self.0.clone(),
                intent_digest: context.descriptor.intent_digest,
            })
        })
    }
}
#[derive(Default)]
struct Clock(AtomicU64);
impl WorkflowClock for Clock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn sleep(&self, duration: Duration) -> WorkflowFuture<'_, ()> {
        Box::pin(async move {
            self.0
                .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        })
    }
}
#[tokio::test]
async fn unapproved_prepare_never_signs_or_dispatches_and_resumes_exact_signed_identity() {
    let (ledger, custody, approval, _) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("approval")).unwrap());
    let engine = WorkflowEngine::new(
        storage,
        Arc::new(RelayAccount {
            account: custody.clone(),
            ledger: ledger.clone(),
        }),
        ledger.clone(),
        Arc::new(Clock::default()),
    );
    let handle = engine
        .workflow(WorkflowPlanV1 {
            kind: WorkflowKindV1::AmxRelay,
            instance: "original-approval-request".into(),
            driver: super::super::driver_identity(),
            request_context_digest: [7; 32],
            steps: vec![StepDescriptorV1::transaction("relay", [7; 32])],
        })
        .unwrap();
    let driver = Driver(norito::encode_canonical(custody.signed.payload()).unwrap());
    let options = WorkflowRunOptions {
        observation_timeout: Duration::from_millis(1),
        poll_interval: Duration::from_millis(1),
        retransmit_identical_bytes: false,
        retry_rejected_step: false,
    };
    assert_eq!(
        handle.run(&driver, &options).await.unwrap_err().code,
        WorkflowErrorCode::LocalResourceUnavailable,
    );
    assert_eq!(
        custody.signs.load(Ordering::Relaxed),
        0,
        "an authenticated Begin must not sign without a separately authenticated owner grant"
    );
    assert_eq!(custody.sends.load(Ordering::Relaxed), 0);
    let digest = ledger.instruction.lock().unwrap().unwrap();
    ledger
        .begin_observation(digest, Some(approval.clone()))
        .unwrap();
    custody.available.store(true, Ordering::Relaxed);
    assert!(handle.run(&driver, &options).await.is_err());
    assert_eq!(custody.signs.load(Ordering::Relaxed), 1);
    assert_eq!(
        custody.sends.load(Ordering::Relaxed),
        0,
        "a signed resumed payload must recheck debit consent before transport"
    );
    ledger
        .begin_observation(digest, Some(approval.clone()))
        .unwrap();
    assert!(handle.run(&driver, &options).await.is_err());
    assert_eq!(
        custody.signs.load(Ordering::Relaxed),
        1,
        "revocation cannot manufacture a replacement identity"
    );
    assert_eq!(custody.sends.load(Ordering::Relaxed), 0);
    custody.available.store(true, Ordering::Relaxed);
    ledger.begin_observation(digest, Some(approval)).unwrap();
    assert!(handle.run(&driver, &options).await.is_err());
    assert_eq!(custody.signs.load(Ordering::Relaxed), 1);
    assert_eq!(
        custody.sends.load(Ordering::Relaxed),
        1,
        "reauthenticated consent resumes the exact already signed carrier"
    );
}

#[tokio::test]
async fn approval_status_cannot_roll_back_an_authenticated_revoke_cut() {
    let (ledger, custody, _, source) = fixture();
    source.available.store(true, Ordering::Relaxed);
    ledger
        .authorize_debit(custody.signed.payload())
        .await
        .unwrap();
    ledger.verified_block(3).await.unwrap();
    // The route has authenticated H3. A stale status and genuine old H2 grant proof
    // must not authorize signing at H2 again, even though both original signatures verify.
    source.reported_height.store(2, Ordering::Relaxed);
    let account = RelayAccount {
        account: custody.clone(),
        ledger,
    };
    let payload = norito::encode_canonical(custody.signed.payload()).unwrap();
    let error = account.sign(&payload).await.unwrap_err();
    assert_eq!(error.code, WorkflowErrorCode::ProofInvalid);
    assert_eq!(
        source.approval_heights.lock().unwrap().as_slice(),
        [2, 3],
        "stale status must not roll approval back below the retained authenticated cut"
    );
    assert_eq!(custody.signs.load(Ordering::Relaxed), 0);
    assert_eq!(custody.sends.load(Ordering::Relaxed), 0);
}

// A restart discards the HTTP workflow handle, storage handle and destination
// verifier cursor. Only configured trust and the file-backed exact payload remain.
fn restart_ledger(original: &RelayLedger, trust: &SumeragiFinalityVerifier) -> Arc<RelayLedger> {
    Arc::new(RelayLedger {
        source: original.source.clone(),
        dispatch: original.dispatch.clone(),
        verifier: Mutex::new(trust.clone()),
        network: original.network,
        authority: original.authority.clone(),
        fee_payment: original.fee_payment.clone(),
        instruction: Mutex::new(*original.instruction.lock().unwrap()),
        approval: Mutex::new(original.approval.lock().unwrap().clone()),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads: original.max_reads,
        reads: AtomicUsize::new(original.max_reads),
    })
}

#[tokio::test]
async fn approval_gate_failures_preserve_exact_reservations_across_file_restart() {
    use iroha::workflow::{TransactionStateV1, WorkflowJournalV1, WorkflowStage, WorkflowStorage};
    for cause in [
        ApprovalFailure::Capacity,
        ApprovalFailure::CutChanged,
        ApprovalFailure::Unclassified,
        ApprovalFailure::Permission,
        ApprovalFailure::Signing,
        ApprovalFailure::Proof,
        ApprovalFailure::FinalityProof,
        ApprovalFailure::MalformedProof,
        ApprovalFailure::ResponseBinding,
        ApprovalFailure::Listener,
    ] {
        for before_sign in [true, false] {
            let (original, custody, _, source) = fixture();
            let trust = original.verifier.lock().unwrap().clone();
            *source.failure.lock().unwrap() = cause;
            source.available.store(!before_sign, Ordering::Relaxed);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("classified-approval");
            let plan = WorkflowPlanV1 {
                kind: WorkflowKindV1::AmxRelay,
                instance: "classified-original-approval".into(),
                driver: super::super::driver_identity(),
                request_context_digest: [71; 32],
                steps: vec![StepDescriptorV1::transaction("relay", [71; 32])],
            };
            let unsigned = norito::encode_canonical(custody.signed.payload()).unwrap();
            let signed = custody.signed.encode_wire_v1().unwrap();
            let driver = Driver(unsigned.clone());
            let options = WorkflowRunOptions {
                observation_timeout: Duration::from_millis(1),
                poll_interval: Duration::from_millis(1),
                retransmit_identical_bytes: false,
                retry_rejected_step: false,
            };
            let mut retained = None;
            for restarted in [false, true] {
                let ledger = restart_ledger(&original, &trust);
                let storage = Arc::new(FileWorkflowStorage::open_or_create(&path).unwrap());
                let engine = WorkflowEngine::new(
                    storage.clone(),
                    Arc::new(RelayAccount {
                        account: custody.clone(),
                        ledger: ledger.clone(),
                    }),
                    ledger,
                    Arc::new(Clock::default()),
                );
                let handle = engine.workflow(plan.clone()).unwrap();
                let failure = handle.run(&driver, &options).await.unwrap_err();
                assert_eq!(
                    failure.code,
                    cause.code(),
                    "cause {cause:?}, before_sign {before_sign}, restarted {restarted}"
                );
                assert_eq!(
                    failure.stage,
                    if before_sign {
                        WorkflowStage::Sign
                    } else {
                        WorkflowStage::Submit
                    }
                );
                assert_eq!(
                    custody.signs.load(Ordering::Relaxed),
                    usize::from(!before_sign)
                );
                assert_eq!(
                    custody.sends.load(Ordering::Relaxed),
                    0,
                    "failed evidence cannot reach transport"
                );
                let record = storage.load(&handle.id()).unwrap().unwrap();
                let journal = WorkflowJournalV1::decode_record(&record).unwrap();
                let operation = journal.steps[0].transaction.as_ref().unwrap();
                assert_eq!(
                    operation.state,
                    if before_sign {
                        TransactionStateV1::ReadyToSign
                    } else {
                        TransactionStateV1::Signed
                    }
                );
                assert_eq!(
                    operation.attempts.len(),
                    1,
                    "refusal cannot open replacement authority"
                );
                let attempt = &operation.attempts[0];
                assert_eq!(attempt.dispatch_ordinal, 0);
                assert_eq!(attempt.possible_admissions, 0);
                assert!(
                    attempt.evidence.is_none(),
                    "a read failure cannot close monetary evidence"
                );
                if before_sign {
                    assert_eq!(operation.unsigned_payload.as_ref(), Some(&unsigned));
                    assert!(operation.signed_transaction.is_none());
                    assert!(operation.current_identity().is_none());
                } else {
                    assert!(operation.unsigned_payload.is_none());
                    assert_eq!(operation.signed_transaction.as_ref(), Some(&signed));
                    assert_eq!(operation.current_identity(), Some(custody.identity()));
                }
                if let Some(previous) = &retained {
                    assert_eq!(
                        operation, previous,
                        "restart must preserve the exact reservation"
                    );
                }
                retained = Some(operation.clone());
                drop(handle);
                drop(engine);
                drop(storage);
            }
        }
    }
}

#[test]
fn original_finality_errors_keep_completed_invalid_and_resource_categories() {
    use iroha_data_model::sumeragi_finality::{FinalityError, FinalityReadError, GenesisReadError};
    let errors = [
        FinalityReadError::Invalid(FinalityError("original certified root mismatch".into())),
        FinalityReadError::Genesis(GenesisReadError::Invalid("invalid signed genesis".into())),
        FinalityReadError::Genesis(GenesisReadError::Json(norito::json::Error::InvalidUtf8)),
    ];
    for error in errors {
        assert_eq!(
            approval_evidence_failure(error.into()).code,
            WorkflowErrorCode::ProofInvalid
        );
    }
    let resource = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || norito::core::classify_decode_attempt(|| norito::core::reserve_decode_allocation(1)),
    )
    .unwrap_err();
    assert_eq!(
        resource.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        approval_evidence_failure(FinalityReadError::from(resource).into()).code,
        WorkflowErrorCode::LocalResourceUnavailable
    );
    // These typed transport controls test classification without inducing physical OOM.
    let local_refusals = [
        FinalityReadError::ScratchLimit(iroha_allocation::AllocationRefusal::ExceedsLimit {
            requested_bytes: 2,
            limit_bytes: 1,
        }),
        FinalityReadError::Allocator(
            iroha_allocation::AllocatorRefusal::try_from(
                iroha_allocation::ChargedBufferError::Allocator { requested_bytes: 2 },
            )
            .unwrap(),
        ),
    ];
    for refusal in local_refusals {
        assert_eq!(
            approval_evidence_failure(refusal.into()).code,
            WorkflowErrorCode::LocalResourceUnavailable,
            "an unfinished local allocation is not an invalid proof"
        );
    }
    let json_limit = FinalityReadError::Genesis(GenesisReadError::Json(
        norito::json::Error::DecodeResourceLimit,
    ));
    assert_eq!(
        approval_evidence_failure(json_limit.into()).code,
        WorkflowErrorCode::EvidenceUnavailable,
        "an unscoped JSON bound is not an authenticated local-capacity witness"
    );
}
