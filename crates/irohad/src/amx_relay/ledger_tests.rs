//! Exact-quorum proof controls for relay outcomes; synthetic outputs do not qualify payments.

use super::*;
use iroha_data_model::{
    executor::ValidationFail, sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::error::TransactionRejectionReason,
};
use std::collections::BTreeMap;

struct FixtureSource {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    height: Option<u64>,
    absent: bool,
}
impl Source for FixtureSource {
    fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>> {
        Box::pin(async { Ok(self.proofs.keys().next_back().copied().unwrap_or(0)) })
    }
    fn locate(&self, _: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
        Box::pin(async {
            Ok(if self.absent {
                Location::Absent
            } else {
                Location::Observed(self.height)
            })
        })
    }
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
        Box::pin(async move {
            self.proofs
                .get(&height.get())
                .cloned()
                .ok_or_else(|| eyre!("fixture has no unrelated later block"))
        })
    }
}
struct NoDispatch;
impl WorkflowLedger for NoDispatch {
    fn dispatch<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        panic!("proof observation cannot dispatch")
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        panic!("proof observation cannot delegate status finality")
    }
}
pub(super) fn fixture(
    rejected: bool,
) -> (RelayLedger, TransactionIdentityV1, SumeragiFinalityVerifier) {
    let mut fixture = NativeFinalityFixture::start("amx-relay-proof");
    let root = fixture.verifier();
    let mut block = fixture.block_with_submitted_work(fixture.next_header());
    let transaction = block.external_transactions().next().unwrap();
    let identity = TransactionIdentityV1 {
        signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
        entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
    };
    let authority = transaction.authority().clone();
    let fee_payment = transaction.fee_payment_intent().clone();
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("fixture is native")
    };
    let digest = instruction_digest(&instructions[0]).unwrap();
    if rejected {
        NativeFinalityFixture::install_network_results(
            &mut block,
            vec![Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("synthetic AMX rejection".into()),
            ))],
        );
    }
    let proof = fixture.certify(block);
    let source = FixtureSource {
        proofs: [(1, fixture.genesis_proof().clone()), (2, proof)].into(),
        height: Some(2),
        absent: false,
    };
    let ledger = RelayLedger {
        source: Arc::new(source),
        dispatch: Arc::new(NoDispatch),
        verifier: Mutex::new(root.clone()),
        network: fixture.network_id(),
        authority,
        fee_payment,
        instruction: Mutex::new(Some(digest)),
        approval: Mutex::new(None),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads: 4,
        reads: AtomicUsize::new(4),
    };
    (ledger, identity, root)
}

#[tokio::test]
async fn relay_authenticates_last_payment_without_successor_and_after_restart() {
    let (ledger, identity, root) = fixture(false);
    assert_eq!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::Applied {
            block_height: Some(2)
        }
    );
    // Restart discards verifier caches. The same original H2 is authenticated again.
    let restarted = RelayLedger {
        source: ledger.source.clone(),
        dispatch: Arc::new(NoDispatch),
        verifier: Mutex::new(root),
        network: ledger.network,
        authority: ledger.authority.clone(),
        fee_payment: ledger.fee_payment.clone(),
        instruction: Mutex::new(*ledger.instruction.lock().unwrap()),
        approval: Mutex::new(None),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads: 4,
        reads: AtomicUsize::new(4),
    };
    assert_eq!(
        restarted.committed_outcome(&identity).await,
        CommittedOutcome::Applied {
            block_height: Some(2)
        }
    );
}

#[tokio::test]
async fn relay_membership_does_not_turn_rejected_execution_into_delivery() {
    let (ledger, identity, _) = fixture(true);
    assert!(matches!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::Rejected { .. }
    ));
    let mut wrong = identity;
    wrong.entrypoint_hash[0] ^= 1;
    assert!(matches!(
        ledger.committed_outcome(&wrong).await,
        CommittedOutcome::ReadFailed { .. }
    ));
}

#[tokio::test]
async fn relay_refusal_preserves_verifier_progress_and_never_closes_identity() {
    let (ledger, identity, _) = fixture(false);
    ledger.reads.store(0, Ordering::Relaxed);
    assert!(matches!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::ReadFailed { .. }
    ));
    let digest = ledger.instruction.lock().unwrap().unwrap();
    ledger.begin_observation(digest, None).unwrap();
    assert!(matches!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::Applied { .. }
    ));
}

#[tokio::test]
async fn relay_rejects_substituted_history_and_locator_without_proof() {
    let (mut ledger, identity, _) = fixture(false);
    *ledger.verifier.get_mut().unwrap() =
        NativeFinalityFixture::start("different-amx-network").verifier();
    assert!(matches!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::ReadFailed { .. }
    ));
    ledger.source = Arc::new(FixtureSource {
        proofs: BTreeMap::new(),
        height: None,
        absent: false,
    });
    assert_eq!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::ObservedNotFinal
    );
}

#[tokio::test]
async fn relay_journal_identity_cannot_substitute_an_unrelated_successful_carrier() {
    let (ledger, identity, _) = fixture(false);
    ledger
        .begin_observation(Hash::new(b"different authenticated source intent"), None)
        .unwrap();
    assert!(matches!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::ReadFailed { .. }
    ));
}

#[tokio::test]
async fn relay_durable_restart_retransmits_identical_bytes_and_never_resigns_unknown() {
    use iroha::workflow::{
        BuiltStepPayload, DriverIdentityV1, FileWorkflowStorage, SignedStepTransaction,
        StepContext, StepDescriptorV1, StepFailure, WorkflowAccount, WorkflowBindingV1,
        WorkflowClock, WorkflowDriver, WorkflowEngine, WorkflowErrorCode, WorkflowKindV1,
        WorkflowPlanV1, WorkflowRunOptions, WorkflowStorage,
    };
    use std::{
        sync::atomic::{AtomicBool, AtomicU64},
        time::Duration,
    };

    struct GatedSource {
        original: Arc<dyn Source>,
        visible: Arc<AtomicBool>,
    }
    impl Source for GatedSource {
        fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>> {
            self.original.applied_height()
        }
        fn locate(&self, hash: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
            Box::pin(async move {
                if self.visible.load(Ordering::Relaxed) {
                    self.original.locate(hash).await
                } else {
                    Ok(Location::Absent)
                }
            })
        }
        fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
            self.original.proof(height)
        }
    }
    struct ExactAccount {
        signed: Vec<u8>,
        unsigned: Vec<u8>,
        identity: TransactionIdentityV1,
        signs: AtomicUsize,
        sent: Mutex<Vec<Vec<u8>>>,
        visible: Arc<AtomicBool>,
    }
    impl WorkflowAccount for ExactAccount {
        fn binding(&self) -> WorkflowBindingV1 {
            WorkflowBindingV1 {
                network: "fixture_network".into(),
                authority: "fixture_authority".into(),
            }
        }
        fn sign<'a>(
            &'a self,
            payload: &'a [u8],
        ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
            Box::pin(async move {
                assert_eq!(payload, self.unsigned);
                self.signs.fetch_add(1, Ordering::Relaxed);
                Ok(SignedStepTransaction {
                    signed_transaction: self.signed.clone(),
                    identity: self.identity,
                })
            })
        }
        fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
            if bytes != self.signed {
                return Err(StepFailure::new(
                    WorkflowErrorCode::BindingMismatch,
                    "substituted fixture transaction",
                ));
            }
            Ok(self.identity)
        }
    }
    impl WorkflowLedger for ExactAccount {
        fn dispatch<'a>(
            &'a self,
            bytes: &'a [u8],
            _: &'a TransactionIdentityV1,
        ) -> WorkflowFuture<'a, DispatchOutcome> {
            Box::pin(async move {
                let mut sent = self.sent.lock().unwrap();
                sent.push(bytes.to_vec());
                if sent.len() == 2 {
                    self.visible.store(true, Ordering::Relaxed);
                }
                DispatchOutcome::Ambiguous {
                    detail: "fixture response lost after sending".into(),
                }
            })
        }
        fn committed_outcome<'a>(
            &'a self,
            _: &'a TransactionIdentityV1,
        ) -> WorkflowFuture<'a, CommittedOutcome> {
            panic!("must use authenticated ledger")
        }
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
                    intent_digest: context.descriptor.intent_digest,
                    unsigned_payload: self.0.clone(),
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
                self.0.fetch_add(
                    u64::try_from(duration.as_millis()).expect("fixture duration fits u64"),
                    Ordering::Relaxed,
                );
            })
        }
    }
    let (mut ledger, identity, root) = fixture(false);
    let proof = ledger
        .source
        .proof(NonZeroU64::new(2).unwrap())
        .await
        .unwrap();
    let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
    let transaction = block.external_transactions().next().unwrap();
    let visible = Arc::new(AtomicBool::new(false));
    let account = Arc::new(ExactAccount {
        signed: transaction.encode_wire_v1().unwrap(),
        unsigned: norito::encode_canonical(transaction.payload()).unwrap(),
        identity,
        signs: AtomicUsize::new(0),
        sent: Mutex::new(Vec::new()),
        visible: visible.clone(),
    });
    ledger.source = Arc::new(GatedSource {
        original: ledger.source,
        visible,
    });
    ledger.dispatch = account.clone();
    let ledger = Arc::new(ledger);
    let plan = WorkflowPlanV1 {
        kind: WorkflowKindV1::AmxRelay,
        instance: "fixture_source_record".into(),
        driver: super::super::driver_identity(),
        request_context_digest: [7; 32],
        steps: vec![StepDescriptorV1::transaction("relay", [7; 32])],
    };
    let directory = tempfile::tempdir().unwrap();
    let storage: Arc<dyn WorkflowStorage> =
        Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("relay")).unwrap());
    let driver = Driver(account.unsigned.clone());
    let options = WorkflowRunOptions {
        observation_timeout: Duration::from_millis(2),
        poll_interval: Duration::from_millis(1),
        retransmit_identical_bytes: true,
        retry_rejected_step: false,
    };
    {
        let engine = WorkflowEngine::new(
            storage.clone(),
            account.clone(),
            ledger.clone(),
            Arc::new(Clock::default()),
        );
        let handle = engine.workflow(plan.clone()).unwrap();
        assert!(
            handle
                .run(
                    &driver,
                    &WorkflowRunOptions {
                        retransmit_identical_bytes: false,
                        ..options
                    }
                )
                .await
                .is_err()
        );
    }
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    assert_eq!(account.sent.lock().unwrap().len(), 1);
    // Fresh verifier and reopened file store reproduce an actual process boundary.
    let restarted = Arc::new(RelayLedger {
        source: ledger.source.clone(),
        dispatch: account.clone(),
        verifier: Mutex::new(root),
        network: ledger.network,
        authority: ledger.authority.clone(),
        fee_payment: ledger.fee_payment.clone(),
        instruction: Mutex::new(*ledger.instruction.lock().unwrap()),
        approval: Mutex::new(None),
        handoff_scan: Mutex::new(HandoffScan::default()),
        max_reads: 4,
        reads: AtomicUsize::new(4),
    });
    drop(storage);
    let reopened =
        Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("relay")).unwrap());
    let engine = WorkflowEngine::new(
        reopened,
        account.clone(),
        restarted,
        Arc::new(Clock::default()),
    );
    engine
        .workflow(plan)
        .unwrap()
        .run(&driver, &options)
        .await
        .unwrap();
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    let sent = account.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
}

#[tokio::test]
async fn relay_canonical_resumed_payload_cannot_cross_signing_or_dispatch_boundary() {
    use iroha::workflow::{
        DriverIdentityV1, FileWorkflowStorage, StepDescriptorV1, SystemWorkflowClock,
        TransactionInputV1, WorkflowDriver, WorkflowEngine, WorkflowJournalV1, WorkflowKindV1,
        WorkflowPlanV1, WorkflowRunOptions, WorkflowStorage,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        isi::Log,
        level::Level,
        transaction::{TransactionBuilder, TransactionDomain},
    };
    use iroha_primitives::json::Json;

    struct OriginalDriver;
    impl WorkflowDriver for OriginalDriver {
        fn identity(&self) -> DriverIdentityV1 {
            super::super::driver_identity()
        }
    }
    struct Counter {
        transaction: SignedTransaction,
        signs: AtomicUsize,
        sends: AtomicUsize,
    }
    impl WorkflowAccount for Counter {
        fn binding(&self) -> WorkflowBindingV1 {
            WorkflowBindingV1 {
                network: "fixture".into(),
                authority: "fixture".into(),
            }
        }
        fn sign<'a>(
            &'a self,
            _: &'a [u8],
        ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
            Box::pin(async {
                self.signs.fetch_add(1, Ordering::Relaxed);
                Ok(SignedStepTransaction {
                    signed_transaction: self.transaction.encode_wire_v1().unwrap(),
                    identity: self.identify(&self.transaction.encode_wire_v1().unwrap())?,
                })
            })
        }
        fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
            let tx = SignedTransaction::decode_all_versioned(bytes).unwrap();
            Ok(TransactionIdentityV1 {
                signed_transaction_hash: *Hash::from(tx.hash()).as_ref(),
                entrypoint_hash: *Hash::from(tx.hash_as_entrypoint()).as_ref(),
            })
        }
    }
    impl WorkflowLedger for Counter {
        fn dispatch<'a>(
            &'a self,
            _: &'a [u8],
            _: &'a TransactionIdentityV1,
        ) -> WorkflowFuture<'a, DispatchOutcome> {
            Box::pin(async {
                self.sends.fetch_add(1, Ordering::Relaxed);
                DispatchOutcome::Accepted
            })
        }
        fn committed_outcome<'a>(
            &'a self,
            _: &'a TransactionIdentityV1,
        ) -> WorkflowFuture<'a, CommittedOutcome> {
            panic!("source-bound gate cannot delegate finality")
        }
    }
    let (mut ledger, identity, _) = fixture(false);
    let proof = ledger
        .source
        .proof(NonZeroU64::new(2).unwrap())
        .await
        .unwrap();
    let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
    let transaction = block.external_transactions().next().unwrap().clone();
    let counter = Arc::new(Counter {
        transaction: transaction.clone(),
        signs: AtomicUsize::new(0),
        sends: AtomicUsize::new(0),
    });
    ledger.dispatch = counter.clone();
    let ledger = Arc::new(ledger);
    let signer = Arc::new(RelayAccount {
        account: counter.clone(),
        ledger: ledger.clone(),
    });
    for mutation in ["instruction", "fee", "metadata", "network", "authority"] {
        let mut payload = transaction.payload().clone();
        match mutation {
            "instruction" => {
                payload.instructions = Executable::Instructions(
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        "substituted".into(),
                    ))]
                    .into(),
                )
            }
            "fee" => {
                payload.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(100))
            }
            "metadata" => {
                payload
                    .metadata
                    .insert("substituted".parse().unwrap(), Json::new(true));
            }
            "network" => {
                payload.domain = TransactionDomain::Network(NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"another network")),
                ))
            }
            "authority" => {
                payload.authority = AccountId::new(
                    KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            }
            _ => unreachable!(),
        }
        let bytes = norito::encode_canonical(&payload).unwrap();
        assert_eq!(
            signer.sign(&bytes).await.unwrap_err().code,
            WorkflowErrorCode::BindingMismatch,
            "{mutation}"
        );
        // Recompute every canonical record digest: file integrity is not request
        // authorization. Resume the ReadyToSign state through the real engine.
        let directory = tempfile::tempdir().unwrap();
        let storage =
            Arc::new(FileWorkflowStorage::open_or_create(directory.path().join("relay")).unwrap());
        let plan = WorkflowPlanV1 {
            kind: WorkflowKindV1::AmxRelay,
            instance: "source_bound_resume".into(),
            driver: super::super::driver_identity(),
            request_context_digest: [19; 32],
            steps: vec![StepDescriptorV1::transaction("relay", [19; 32])],
        };
        let engine = WorkflowEngine::new(
            storage.clone(),
            signer.clone(),
            ledger.clone(),
            Arc::new(SystemWorkflowClock::new()),
        );
        let handle = engine.workflow(plan.clone()).unwrap();
        let mut journal = WorkflowJournalV1::new(&plan, &signer.binding(), 0).unwrap();
        journal.sequence = 1;
        for input in [
            TransactionInputV1::OpenAttempt,
            TransactionInputV1::BuildStarted,
            TransactionInputV1::PayloadBuilt { payload: bytes },
        ] {
            journal.apply_transaction(0, input).unwrap();
        }
        let record = journal.encode_record().unwrap();
        assert_eq!(WorkflowJournalV1::decode_record(&record).unwrap(), journal);
        storage
            .compare_and_store(&handle.id(), None, &record)
            .unwrap();
        assert_eq!(
            handle
                .run(&OriginalDriver, &WorkflowRunOptions::default())
                .await
                .unwrap_err()
                .code,
            WorkflowErrorCode::BindingMismatch,
            "{mutation}"
        );
        let signing_seed = if mutation == "authority" { 42 } else { 41 };
        let substituted = TransactionBuilder::from_payload(payload)
            .unwrap()
            .sign(KeyPair::from_seed(vec![signing_seed; 32], Algorithm::Ed25519).private_key());
        let submission_wire = substituted.encode_wire_v1().unwrap();
        let substituted_identity = counter.identify(&submission_wire).unwrap();
        assert!(
            matches!(
                ledger
                    .dispatch(&submission_wire, &substituted_identity)
                    .await,
                DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::BindingMismatch,
                    ..
                }
            ),
            "{mutation}"
        );
        assert_eq!(counter.signs.load(Ordering::Relaxed), 0, "{mutation}");
        assert_eq!(counter.sends.load(Ordering::Relaxed), 0, "{mutation}");
    }
    let submission_wire = transaction.encode_wire_v1().unwrap();
    let mut wrong_identity = identity;
    wrong_identity.entrypoint_hash[0] ^= 1;
    assert!(matches!(
        ledger.dispatch(&submission_wire, &wrong_identity).await,
        DispatchOutcome::NotAdmitted {
            code: WorkflowErrorCode::BindingMismatch,
            ..
        }
    ));
    assert_eq!(counter.sends.load(Ordering::Relaxed), 0);
    signer
        .sign(&norito::encode_canonical(transaction.payload()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        ledger.dispatch(&submission_wire, &identity).await,
        DispatchOutcome::Accepted
    );
    assert_eq!(counter.signs.load(Ordering::Relaxed), 1);
    assert_eq!(counter.sends.load(Ordering::Relaxed), 1);
    *ledger.instruction.lock().unwrap() = None;
    assert_eq!(
        signer
            .sign(&norito::encode_canonical(transaction.payload()).unwrap())
            .await
            .unwrap_err()
            .code,
        WorkflowErrorCode::BindingMismatch
    );
    assert!(matches!(
        ledger.dispatch(&submission_wire, &identity).await,
        DispatchOutcome::NotAdmitted {
            code: WorkflowErrorCode::BindingMismatch,
            ..
        }
    ));
    assert_eq!(counter.signs.load(Ordering::Relaxed), 1);
    assert_eq!(counter.sends.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn relay_changed_fee_policy_preserves_authenticated_delivery_but_cannot_dispatch_old_bytes() {
    let (mut ledger, identity, _) = fixture(false);
    let proof = ledger
        .source
        .proof(NonZeroU64::new(2).unwrap())
        .await
        .unwrap();
    let block = iroha_data_model::block::decode_framed_signed_block(&proof.block_wire).unwrap();
    let transaction = block.external_transactions().next().unwrap();
    ledger.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(100));
    assert_ne!(transaction.fee_payment_intent(), &ledger.fee_payment);
    assert!(
        ledger
            .check_authorized_payload(transaction.payload())
            .is_err()
    );
    assert!(matches!(
        ledger
            .dispatch(&transaction.encode_wire_v1().unwrap(), &identity)
            .await,
        DispatchOutcome::NotAdmitted {
            code: WorkflowErrorCode::BindingMismatch,
            ..
        }
    ));
    assert_eq!(
        ledger.committed_outcome(&identity).await,
        CommittedOutcome::Applied {
            block_height: Some(2)
        }
    );
}
