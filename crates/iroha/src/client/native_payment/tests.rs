//! Durable SDK operation controls using genuine QCs over synthetic execution outputs.
//! World execution and live network qualification belong to the cross-component suite.

use super::observation::{CarrierLocation, PaymentLocator};
use super::*;
use crate::workflow::{
    CommittedOutcome, DispatchOutcome, FileWorkflowStorage, SignedStepTransaction,
    TransactionIdentityV1, WorkflowBindingV1, WorkflowLedger, WorkflowRunnerLease,
    WorkflowStatusV1, WorkflowStorageError, WorkflowStorageErrorKind,
};
use iroha_data_model::{
    sumeragi_finality::{SumeragiFinalityProof, test_fixtures::NativeFinalityFixture},
    transaction::TransactionBuilder,
};
use iroha_version::codec::DecodeVersioned;
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::atomic::{AtomicBool, AtomicU8},
    time::Duration,
};

struct Source {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    locator: PaymentLocator,
    visible: AtomicBool,
    carrier_height: Option<u64>,
    exact_absence: AtomicBool,
    fail_read: AtomicBool,
    proof_reads: AtomicUsize,
    submitted: AtomicBool,
}
impl PaymentSource for Source {
    fn settlement<'a>(
        &'a self,
        _: &'a iroha_data_model::isi::SettlementId,
    ) -> WorkflowFuture<'a, Result<Option<PaymentLocator>, NativePaymentObservationError>> {
        Box::pin(async { Ok(self.visible.load(Ordering::Relaxed).then_some(self.locator)) })
    }
    fn carrier(
        &self,
        _: HashOf<SignedTransaction>,
    ) -> WorkflowFuture<'_, Result<CarrierLocation, NativePaymentObservationError>> {
        Box::pin(async {
            Ok(if self.exact_absence.load(Ordering::Relaxed) {
                CarrierLocation::Absent
            } else {
                CarrierLocation::Observed(self.carrier_height)
            })
        })
    }
    fn proof(
        &self,
        height: NonZeroU64,
    ) -> WorkflowFuture<'_, Result<SumeragiFinalityProof, NativePaymentObservationError>> {
        Box::pin(async move {
            self.proof_reads.fetch_add(1, Ordering::Relaxed);
            if self.fail_read.load(Ordering::Relaxed) {
                return Err(NativePaymentObservationError::Encoding(
                    norito::Error::AllocationFailed { bytes: 17 },
                ));
            }
            self.proofs
                .get(&height.get())
                .cloned()
                .ok_or(NativePaymentObservationError::CandidateMismatch)
        })
    }
}
struct Account {
    transaction: SignedTransaction,
    signs: AtomicUsize,
    dispatches: AtomicUsize,
    source: Arc<Source>,
}
fn identity(transaction: &SignedTransaction) -> TransactionIdentityV1 {
    TransactionIdentityV1 {
        signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
        entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
    }
}
impl WorkflowAccount for Account {
    fn binding(&self) -> WorkflowBindingV1 {
        WorkflowBindingV1 {
            network: self.transaction.network_id().unwrap().to_string(),
            authority: "fixture_payer".into(),
        }
    }
    fn sign<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            assert_eq!(
                payload,
                norito::encode_canonical(self.transaction.payload()).unwrap()
            );
            self.signs.fetch_add(1, Ordering::Relaxed);
            Ok(SignedStepTransaction {
                signed_transaction: self.transaction.encode_wire_v1().unwrap(),
                identity: identity(&self.transaction),
            })
        })
    }
    fn identify(&self, bytes: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        Ok(identity(
            &SignedTransaction::decode_all_versioned(bytes).unwrap(),
        ))
    }
}
impl WorkflowLedger for Account {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        expected: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            assert_eq!(
                bytes,
                self.transaction.encode_wire_v1().unwrap(),
                "dispatch must retain the exact original signed carrier bytes"
            );
            assert_eq!(self.identify(bytes).unwrap(), *expected);
            self.dispatches.fetch_add(1, Ordering::Relaxed);
            self.source.submitted.store(true, Ordering::Relaxed);
            DispatchOutcome::Accepted
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async { panic!("payment must never use the status-only workflow ledger") })
    }
}
struct Driver {
    transaction: SignedTransaction,
    digest: Digest32,
}
impl WorkflowDriver for Driver {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn build_transaction<'a>(
        &'a self,
        _: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async {
            Ok(BuiltStepPayload {
                intent_digest: self.digest,
                unsigned_payload: norito::encode_canonical(self.transaction.payload()).unwrap(),
            })
        })
    }
}
fn fixture(
    rejected: bool,
) -> (
    NativeFinalityFixture,
    NativePaymentRequest,
    SignedTransaction,
    Arc<Source>,
) {
    let (native, intent, transaction) =
        super::super::verified_payment::payment_operation_fixture_for_testing(rejected);
    let request =
        NativePaymentRequest::new(intent, transaction.fee_payment_intent().clone()).unwrap();
    let source = Arc::new(Source {
        proofs: BTreeMap::from([
            (1, native.genesis_proof().clone()),
            (2, native.latest().clone()),
        ]),
        locator: PaymentLocator {
            height: 2,
            block_hash: native
                .verifier()
                .verify_retained_decision(native.latest())
                .unwrap()
                .header()
                .hash(),
        },
        visible: AtomicBool::new(false),
        carrier_height: Some(2),
        exact_absence: AtomicBool::new(false),
        fail_read: AtomicBool::new(false),
        proof_reads: AtomicUsize::new(0),
        submitted: AtomicBool::new(false),
    });
    (native, request, transaction, source)
}
fn operation(
    request: NativePaymentRequest,
    transaction: SignedTransaction,
    source: Arc<Source>,
    native: &NativeFinalityFixture,
    storage: Arc<dyn WorkflowStorage>,
) -> (NativePaymentOperation, Arc<Account>) {
    let driver = Arc::new(Driver {
        transaction: transaction.clone(),
        digest: request.digest,
    });
    let account = Arc::new(Account {
        transaction,
        signs: AtomicUsize::new(0),
        dispatches: AtomicUsize::new(0),
        source: source.clone(),
    });
    let handle = NativePaymentOperation::create(
        request,
        storage,
        native.verifier(),
        account.clone(),
        account.clone(),
        source,
        driver,
    )
    .unwrap();
    (handle, account)
}
fn options() -> NativePaymentRunOptions {
    NativePaymentRunOptions {
        workflow: WorkflowRunOptions {
            observation_timeout: Duration::from_millis(2),
            poll_interval: Duration::from_millis(1),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn store_carrier_journal(
    storage: &dyn WorkflowStorage,
    operation: &NativePaymentOperation,
    account: &Account,
    request: &NativePaymentRequest,
    payload: Vec<u8>,
    signed: Option<&SignedTransaction>,
) {
    use crate::workflow::{TransactionInputV1, WorkflowJournalV1};

    let mut journal =
        WorkflowJournalV1::new(&request.plan().unwrap(), &account.binding(), 0).unwrap();
    journal.sequence = 1;
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::BuildStarted,
        TransactionInputV1::PayloadBuilt { payload },
    ] {
        journal.apply_transaction(0, input).unwrap();
    }
    if let Some(transaction) = signed {
        journal
            .apply_transaction(
                0,
                TransactionInputV1::Signed {
                    signed_transaction: transaction.encode_wire_v1().unwrap(),
                    identity: identity(transaction),
                },
            )
            .unwrap();
    }
    // This is a fully canonical, digest-consistent replacement. Structural journal
    // integrity alone must not authorize its substituted monetary instructions.
    let bytes = journal.encode_record().unwrap();
    assert_eq!(WorkflowJournalV1::decode_record(&bytes).unwrap(), journal);
    storage
        .compare_and_store(&operation.id(), None, &bytes)
        .unwrap();
}

#[test]
fn native_payment_canonical_journal_substitution_never_reaches_the_signer() {
    use iroha_data_model::{
        isi::{InstructionBox, Log},
        level::Level,
        transaction::{Executable, TransactionDomain},
    };
    use iroha_primitives::json::Json;

    let rt = tokio::runtime::Runtime::new().unwrap();
    for mutation in [
        "instruction",
        "amount",
        "fee",
        "metadata",
        "network",
        "authority",
    ] {
        let (native, request, transaction, source) = fixture(false);
        let mut payload = transaction.payload().clone();
        match mutation {
            "instruction" => {
                payload.instructions = Executable::Instructions(
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        "unrelated".into(),
                    ))]
                    .into(),
                );
            }
            "amount" => {
                let mut intent = request.intent.clone();
                let mut movements = intent.movements.as_slice().to_vec();
                movements[0].quantity = 250_001_u32.into();
                intent.movements = movements.try_into().unwrap();
                payload.instructions = Executable::Instructions(
                    vec![InstructionBox::from(SettlementInstructionBox::Atomic(
                        intent,
                    ))]
                    .into(),
                );
            }
            "fee" => payload.fee_payment = FeePaymentIntent::authority(Vec::new(), None),
            "metadata" => {
                payload
                    .metadata
                    .insert("unexpected".parse().unwrap(), Json::new(true));
            }
            "network" => {
                payload.domain =
                    TransactionDomain::Network(iroha_data_model::NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"substituted carrier network")),
                    ));
            }
            "authority" => {
                payload.authority = request.intent.movements.as_slice()[0].recipient.clone()
            }
            _ => unreachable!(),
        }
        let bytes = norito::encode_canonical(&payload).unwrap();
        let decoded: iroha_data_model::transaction::TransactionPayload =
            norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, payload);
        let root = tempfile::tempdir().unwrap();
        let storage =
            Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap());
        let (operation, account) = operation(
            request.clone(),
            transaction,
            source,
            &native,
            storage.clone(),
        );
        store_carrier_journal(
            storage.as_ref(),
            &operation,
            &account,
            &request,
            bytes,
            None,
        );
        assert!(
            matches!(rt.block_on(operation.submit(&options())), Err(NativePaymentError::Workflow(error))
            if error.code == WorkflowErrorCode::BindingMismatch),
            "{mutation}"
        );
        assert_eq!(account.signs.load(Ordering::Relaxed), 0, "{mutation}");
        assert_eq!(account.dispatches.load(Ordering::Relaxed), 0, "{mutation}");
    }
}

#[test]
fn native_payment_canonical_signed_substitution_never_reaches_transport() {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::isi::InstructionBox;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (native, request, transaction, source) = fixture(false);
    let mut intent = request.intent.clone();
    let mut movements = intent.movements.as_slice().to_vec();
    movements[0].quantity = 250_001_u32.into();
    intent.movements = movements.try_into().unwrap();
    let substituted = TransactionBuilder::new(
        native.network_id(),
        request.intent.settlement_id.owner().clone(),
        request.fee_payment.clone(),
    )
    .with_instructions([InstructionBox::from(SettlementInstructionBox::Atomic(
        intent,
    ))])
    .sign(KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519).private_key());
    substituted.verify_signature().unwrap();
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap());
    let (operation, account) = operation(
        request.clone(),
        transaction,
        source,
        &native,
        storage.clone(),
    );
    store_carrier_journal(
        storage.as_ref(),
        &operation,
        &account,
        &request,
        norito::encode_canonical(substituted.payload()).unwrap(),
        Some(&substituted),
    );
    assert!(
        matches!(rt.block_on(operation.resume(&options())), Err(NativePaymentError::Workflow(error))
        if error.code == WorkflowErrorCode::StorageCorrupted)
    );
    assert!(matches!(
        rt.block_on(operation.ledger.dispatch(
            &substituted.encode_wire_v1().unwrap(),
            &identity(&substituted)
        )),
        DispatchOutcome::NotAdmitted {
            code: WorkflowErrorCode::BindingMismatch,
            ..
        }
    ));
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}

#[test]
fn native_payment_request_requires_one_global_movement_from_its_namespace_owner() {
    use iroha_data_model::{
        NetworkId,
        asset::{AssetDefinitionId, AssetId},
        block::BlockHeader,
        isi::{AtomicSettlementMovement, AtomicSettlementMovements, SettlementId},
    };
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    let asset = AssetDefinitionId::from_uuid_bytes([
        1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
    ])
    .unwrap();
    let movement = AtomicSettlementMovement {
        source: AssetId::with_scope(asset.clone(), ALICE_ID.clone(), AssetBalanceScope::Global),
        recipient: BOB_ID.clone(),
        quantity: Quantity::one(),
    };
    let intent = SettleAtomic::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"native-payment-request-constructor",
        ))),
        SettlementId::new(ALICE_ID.clone(), "constructor".parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![movement.clone()]).unwrap(),
        NonZeroU64::new(100).unwrap(),
        Metadata::default(),
    );
    let fees = FeePaymentIntent::authority(Vec::new(), None);
    let accepted = NativePaymentRequest::new(intent.clone(), fees.clone()).unwrap();
    assert_eq!(accepted.intent(), &intent);
    assert_eq!(accepted.fee_payment(), &fees);

    let mut multiple = intent.clone();
    let mut movements = vec![
        movement.clone(),
        AtomicSettlementMovement {
            source: AssetId::with_scope(asset.clone(), BOB_ID.clone(), AssetBalanceScope::Global),
            recipient: ALICE_ID.clone(),
            quantity: Quantity::one(),
        },
    ];
    movements.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
    multiple.movements = AtomicSettlementMovements::try_from(movements).unwrap();
    multiple.validate().unwrap();
    assert!(matches!(
        NativePaymentRequest::new(multiple, fees.clone()),
        Err(NativePaymentError::InvalidRequest(
            "native payment requires one Global movement owned by the payment namespace"
        ))
    ));

    let mut scoped = intent.clone();
    let mut movement = movement;
    movement.source = AssetId::with_scope(
        asset,
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(1)),
    );
    scoped.movements = AtomicSettlementMovements::try_from(vec![movement]).unwrap();
    scoped.validate().unwrap();
    assert!(matches!(
        NativePaymentRequest::new(scoped, fees.clone()),
        Err(NativePaymentError::InvalidRequest(
            "native payment requires one Global movement owned by the payment namespace"
        ))
    ));

    let mut foreign_owner = intent;
    foreign_owner.settlement_id = SettlementId::new(BOB_ID.clone(), "constructor".parse().unwrap());
    assert!(matches!(
        NativePaymentRequest::new(foreign_owner, fees),
        Err(NativePaymentError::InvalidRequest(
            "settlement id owner must participate as an authorized debit owner"
        ))
    ));
}

#[tokio::test]
async fn native_payment_final_tip_receipt_survives_restart_without_dispatch() {
    let (native, request, transaction, source) = fixture(false);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap());
    let (operation, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    let result = operation.submit(&options()).await.unwrap();
    assert_eq!(result.receipt.transaction_hash(), transaction.hash());
    assert_eq!(result.carrier.status, WorkflowStatusV1::Completed);
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    assert_eq!(
        source.proofs.keys().copied().collect::<Vec<_>>(),
        [1, 2],
        "no later block exists"
    );
    let before = source.proof_reads.load(Ordering::Relaxed);
    drop(operation);
    let (resumed, account) =
        operation_for_restart(request, transaction, source.clone(), &native, storage);
    let recovered = resumed.recover(&options()).await.unwrap();
    assert!(recovered.receipt.is_some());
    assert!(
        source.proof_reads.load(Ordering::Relaxed) > before,
        "decoded completion must trigger fresh proof verification"
    );
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}
fn operation_for_restart(
    request: NativePaymentRequest,
    transaction: SignedTransaction,
    source: Arc<Source>,
    native: &NativeFinalityFixture,
    storage: Arc<dyn WorkflowStorage>,
) -> (NativePaymentOperation, Arc<Account>) {
    operation(request, transaction, source, native, storage)
}

#[tokio::test]
async fn native_payment_rejected_inclusion_and_status_only_expiry_never_complete_business() {
    let (native, request, transaction, source) = fixture(true);
    let root = tempfile::tempdir().unwrap();
    let (operation, _) = operation(
        request,
        transaction,
        source,
        &native,
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap()),
    );
    assert!(operation.submit(&options()).await.is_err());
    let journal = operation.handle.journal_snapshot().unwrap().unwrap();
    assert_eq!(journal.status, WorkflowStatusV1::Failed);
    assert!(journal.native_payment_completion.is_none());

    let (native, request, transaction, source) = fixture(false);
    let mut source = Arc::try_unwrap(source).ok().unwrap();
    source.carrier_height = None; // Includes a status-only Expired response with no certified output.
    let source = Arc::new(source);
    let root = tempfile::tempdir().unwrap();
    let (operation, account) = operation_for_restart(
        request,
        transaction,
        source.clone(),
        &native,
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap()),
    );
    assert!(operation.submit(&options()).await.is_err());
    assert!(
        operation
            .recover(&options())
            .await
            .unwrap()
            .receipt
            .is_none()
    );
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    assert_eq!(source.proof_reads.load(Ordering::Relaxed), 0);
    assert!(
        operation.handle.journal_snapshot().unwrap().unwrap().steps[0]
            .transaction
            .as_ref()
            .unwrap()
            .state
            .may_still_commit()
    );
}

#[tokio::test]
async fn native_payment_preserves_resource_error_and_resumes_exact_carrier() {
    let (native, request, transaction, source) = fixture(false);
    source.fail_read.store(true, Ordering::Relaxed);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap());
    let (operation, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    let error = operation.submit(&options()).await.unwrap_err();
    assert!(matches!(
        error,
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::Encoding(norito::Error::AllocationFailed { .. }))
    ));
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    assert!(matches!(
        operation.recover(&options()).await.unwrap_err(),
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::Encoding(norito::Error::AllocationFailed {
                bytes: 17
            }))
    ));
    drop(operation);
    source.fail_read.store(false, Ordering::Relaxed);
    let (resumed, account) = operation_for_restart(request, transaction, source, &native, storage);
    assert!(resumed.recover(&options()).await.unwrap().receipt.is_some());
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_payment_original_recovery_binds_intent_fees_and_stored_completion() {
    let (native, request, transaction, source) = fixture(false);
    source.visible.store(true, Ordering::Relaxed);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap());
    let (operation, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    let recovered = operation.resume(&options()).await.unwrap();
    assert_eq!(recovered.receipt.transaction_hash(), transaction.hash());
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
    assert_eq!(
        recovered.carrier.status,
        WorkflowStatusV1::InProgress,
        "original business success is not this unsubmitted carrier"
    );
    assert!(
        operation
            .handle
            .run(operation.driver.as_ref(), &options().workflow)
            .await
            .is_err(),
        "generic engine must refuse dispatch after completion marker"
    );
    let journal = operation.handle.journal_snapshot().unwrap().unwrap();
    let stored = storage.load(&operation.id()).unwrap().unwrap();
    let mut altered = journal;
    altered
        .native_payment_completion
        .as_mut()
        .unwrap()
        .transaction_hash[0] ^= 1;
    storage
        .compare_and_store(
            &operation.id(),
            Some(&crate::workflow::record_digest(&stored)),
            &altered.encode_record().unwrap(),
        )
        .unwrap();
    assert!(matches!(
        operation.recover(&options()).await.unwrap_err(),
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::CompletionMismatch)
    ));
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);

    let changed = NativePaymentRequest::new(
        request.intent.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let (operation, account) = operation_for_restart(
        changed,
        transaction,
        source,
        &native,
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap()),
    );
    assert!(matches!(
        operation.resume(&options()).await.unwrap_err(),
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::FeeAuthorizationMismatch)
    ));
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}

struct CompletionInterruptedStorage {
    inner: FileWorkflowStorage,
    fail: AtomicU8,
}
impl WorkflowStorage for CompletionInterruptedStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        self.inner.durability()
    }
    fn load(&self, id: &WorkflowId) -> Result<Option<Vec<u8>>, WorkflowStorageError> {
        self.inner.load(id)
    }
    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        self.inner.acquire_runner(id)
    }
    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> Result<(), WorkflowStorageError> {
        let journal = crate::workflow::WorkflowJournalV1::decode_record(record).unwrap();
        if journal.native_payment_completion.is_some() && self.fail.swap(0, Ordering::Relaxed) == 1
        {
            self.inner.compare_and_store(id, expected, record)?;
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "interrupted after verified completion publication",
            ));
        }
        self.inner.compare_and_store(id, expected, record)
    }
}

#[tokio::test]
async fn native_payment_recovers_uncertain_completion_write_without_second_dispatch() {
    let (native, request, transaction, source) = fixture(false);
    let root = tempfile::tempdir().unwrap();
    let storage = Arc::new(CompletionInterruptedStorage {
        inner: FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap(),
        fail: AtomicU8::new(1),
    });
    let (handle, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    assert!(matches!(
        handle.submit(&options()).await.unwrap_err(),
        NativePaymentError::Workflow(WorkflowError {
            code: WorkflowErrorCode::LocalResourceUnavailable,
            ..
        })
    ));
    assert!(
        handle
            .handle
            .journal_snapshot()
            .unwrap()
            .unwrap()
            .native_payment_completion
            .is_some()
    );
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    drop(handle);
    let (resumed, account) = operation(request, transaction, source, &native, storage);
    assert!(resumed.recover(&options()).await.unwrap().receipt.is_some());
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_payment_rejected_retry_recovers_original_without_relabeling_carrier() {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::{BlockSignatures, builder::BlockBuilder},
        executor::{SettlementReplayDispositionV1, SettlementReplayV1, ValidationFail},
        transaction::error::TransactionRejectionReason,
    };
    let (mut native, request, original, source) = fixture(false);
    let mut source = Arc::try_unwrap(source).ok().unwrap();
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let header = native.next_header();
    let mut builder = TransactionBuilder::new(
        request.intent.network_id,
        original.authority().clone(),
        request.fee_payment.clone(),
    )
    .with_instructions([SettlementInstructionBox::Atomic(request.intent.clone())]);
    builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let retry = builder.sign(key.private_key());
    assert_ne!(retry.hash(), original.hash());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(retry.clone());
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(
        &mut block,
        vec![Err(TransactionRejectionReason::Validation(
            ValidationFail::SettlementReplay(Box::new(SettlementReplayV1 {
                settlement_id: request.intent.settlement_id.clone(),
                disposition: SettlementReplayDispositionV1::AlreadySettled,
                committed_block_height: source.locator.height,
                committed_block_hash: source.locator.block_hash,
            })),
        ))],
    );
    source.proofs.insert(3, native.certify(block));
    source.carrier_height = Some(3);
    let source = Arc::new(source);
    let root = tempfile::tempdir().unwrap();
    let (handle, account) = operation(
        request,
        retry,
        source.clone(),
        &native,
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap()),
    );
    let limited = NativePaymentRunOptions {
        max_finality_proof_reads: NonZeroU16::new(1).unwrap(),
        ..options()
    };
    assert!(matches!(
        handle.submit(&limited).await.unwrap_err(),
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::ReadBudgetExhausted)
    ));
    let settled = handle.resume(&options()).await.unwrap();
    assert_eq!(settled.receipt.transaction_hash(), original.hash());
    assert_eq!(
        settled.carrier.status,
        WorkflowStatusV1::Failed,
        "rejected retry remains rejected"
    );
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    assert!(
        !source.visible.load(Ordering::Relaxed),
        "recovery used authenticated rejection's original locator"
    );
    assert_eq!(
        source.proofs.keys().copied().collect::<Vec<_>>(),
        [1, 2, 3],
        "no block follows final retry"
    );
}

#[tokio::test]
async fn native_payment_changed_terms_never_dispatch() {
    let (native, request, transaction, source) = fixture(false);
    source.visible.store(true, Ordering::Relaxed);
    let mut changed = request.intent.clone();
    changed.metadata.insert(
        "changed".parse().unwrap(),
        iroha_primitives::json::Json::new("terms"),
    );
    let changed = NativePaymentRequest::new(changed, request.fee_payment.clone()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let (handle, account) = operation(
        changed,
        transaction,
        source,
        &native,
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("payment")).unwrap()),
    );
    assert!(matches!(
        handle.submit(&options()).await.unwrap_err(),
        NativePaymentError::Observation { cause, .. } if matches!(cause.as_ref(), NativePaymentObservationError::Receipt(
                super::super::PaymentReceiptVerificationError::IntentMismatch
            ))
    ));
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_payment_fresh_gateway_unknown_resume_requires_submission_authorization() {
    assert_fresh_gateway_requires_submission_authorization(false).await;
}

#[tokio::test]
async fn native_payment_fresh_gateway_rejected_resume_requires_submission_authorization() {
    assert_fresh_gateway_requires_submission_authorization(true).await;
}

async fn assert_fresh_gateway_requires_submission_authorization(rejected: bool) {
    let (native, request, transaction, source) = fixture(rejected);
    let source = if rejected {
        source
    } else {
        let mut source = Arc::try_unwrap(source).ok().unwrap();
        source.carrier_height = None;
        Arc::new(source)
    };
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("fresh_gateway")).unwrap());
    let (fresh, account) = operation(request, transaction, source, &native, storage);
    let mut resume_options = options();
    resume_options.workflow.retry_rejected_step = true;
    resume_options.workflow.retransmit_identical_bytes = true;
    let result = fresh.resume(&resume_options).await;
    assert!(matches!(
        result,
        Err(NativePaymentError::NewAttemptAuthorizationRequired { progress: None })
    ));
    assert_eq!(
        account.signs.load(Ordering::Relaxed),
        0,
        "fresh-gateway resume cannot sign another paid carrier without new submission authorization"
    );
    assert_eq!(
        account.dispatches.load(Ordering::Relaxed),
        0,
        "fresh-gateway resume cannot dispatch another potentially paid carrier"
    );
    assert!(
        fresh.handle.journal_snapshot().unwrap().is_none(),
        "absence of business success does not authorize creation of a new carrier journal"
    );
}

#[tokio::test]
async fn native_payment_unsigned_resume_preserves_journal_without_signing_or_building() {
    let (native, request, transaction, source) = fixture(false);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("unsigned")).unwrap());
    let (payment, account) = operation(
        request.clone(),
        transaction.clone(),
        source,
        &native,
        storage.clone(),
    );
    store_carrier_journal(
        storage.as_ref(),
        &payment,
        &account,
        &request,
        norito::encode_canonical(transaction.payload()).unwrap(),
        None,
    );
    let original = storage.load(&payment.id()).unwrap().unwrap();
    let mut resume_options = options();
    resume_options.workflow.retry_rejected_step = true;
    assert!(matches!(
        payment.resume(&resume_options).await,
        Err(NativePaymentError::NewAttemptAuthorizationRequired { progress: Some(_) })
    ));
    assert_eq!(storage.load(&payment.id()).unwrap().unwrap(), original);
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
    // Both resume capabilities refuse construction, even if a future engine path asks.
    assert!(matches!(payment.resume_handle.progress().unwrap(), Some(_)));
    let journal = payment.handle.journal_snapshot().unwrap().unwrap();
    let plan = request.plan().unwrap();
    let context = StepContext {
        workflow_id: payment.id(),
        step_index: 0,
        descriptor: &plan.steps[0],
        identity_ordinal: 1,
        journal: &journal,
    };
    assert_eq!(
        payment
            .resume_driver
            .build_transaction(context)
            .await
            .unwrap_err()
            .code,
        WorkflowErrorCode::UnsupportedOperation
    );
    let resume_account = carrier::ResumePaymentAccount::new(account.binding(), request);
    assert_eq!(
        resume_account
            .sign(&norito::encode_canonical(transaction.payload()).unwrap())
            .await
            .unwrap_err()
            .code,
        WorkflowErrorCode::UnsupportedOperation
    );
}

#[tokio::test]
async fn native_payment_signed_resume_dispatches_only_original_bytes_without_signing() {
    let (native, request, transaction, source) = fixture(false);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("signed")).unwrap());
    let (payment, account) = operation(
        request.clone(),
        transaction.clone(),
        source,
        &native,
        storage.clone(),
    );
    store_carrier_journal(
        storage.as_ref(),
        &payment,
        &account,
        &request,
        norito::encode_canonical(transaction.payload()).unwrap(),
        Some(&transaction),
    );
    let settled = payment.resume(&options()).await.unwrap();
    assert_eq!(settled.receipt.transaction_hash(), transaction.hash());
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    let journal = payment.handle.journal_snapshot().unwrap().unwrap();
    let attempts = &journal.steps[0].transaction.as_ref().unwrap().attempts;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].identity.as_ref(), Some(&identity(&transaction)));
}

#[tokio::test]
async fn native_payment_unknown_resume_reconciles_before_exact_byte_retransmission() {
    let (native, request, transaction, source) = fixture(false);
    let mut source = Arc::try_unwrap(source).ok().unwrap();
    source.carrier_height = None;
    let source = Arc::new(source);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("unknown")).unwrap());
    let (payment, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    assert!(payment.submit(&options()).await.is_err());
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    let original = payment.handle.journal_snapshot().unwrap().unwrap();
    let original_transaction = original.steps[0].transaction.as_ref().unwrap();
    let original_bytes = original_transaction.signed_transaction.clone();
    assert_eq!(original_transaction.attempts.len(), 1);
    drop(payment);
    let (resumed, account) = operation(
        request,
        transaction.clone(),
        source.clone(),
        &native,
        storage,
    );
    let mut resume_options = options();
    resume_options.workflow.retry_rejected_step = true;
    resume_options.workflow.retransmit_identical_bytes = true;
    assert!(resumed.resume(&resume_options).await.is_err());
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(
        account.dispatches.load(Ordering::Relaxed),
        0,
        "unknown status is not exact absence and cannot authorize even identical retransmission"
    );
    source.exact_absence.store(true, Ordering::Relaxed);
    assert!(resumed.resume(&resume_options).await.is_err());
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    let journal = resumed.handle.journal_snapshot().unwrap().unwrap();
    let retained = journal.steps[0].transaction.as_ref().unwrap();
    assert_eq!(retained.attempts.len(), 1);
    assert_eq!(retained.signed_transaction, original_bytes);
    assert_eq!(
        retained.attempts[0].identity.as_ref(),
        Some(&identity(&transaction))
    );
    assert_eq!(retained.attempts[0].dispatch_ordinal, 2);
}

#[tokio::test]
async fn native_payment_rejected_resume_ignores_new_identity_authorization_options() {
    let (native, request, transaction, source) = fixture(true);
    let root = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(FileWorkflowStorage::open_or_create(root.path().join("rejected")).unwrap());
    let (payment, account) = operation(
        request.clone(),
        transaction.clone(),
        source.clone(),
        &native,
        storage.clone(),
    );
    assert!(matches!(
        payment.submit(&options()).await,
        Err(NativePaymentError::Workflow(WorkflowError {
            code: WorkflowErrorCode::Rejected,
            ..
        }))
    ));
    assert_eq!(account.signs.load(Ordering::Relaxed), 1);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 1);
    let original = storage.load(&payment.id()).unwrap().unwrap();
    drop(payment);
    let (resumed, account) = operation(
        request,
        transaction.clone(),
        source,
        &native,
        storage.clone(),
    );
    let mut resume_options = options();
    resume_options.workflow.retry_rejected_step = true;
    resume_options.workflow.retransmit_identical_bytes = true;
    assert!(matches!(
        resumed.resume(&resume_options).await,
        Err(NativePaymentError::Workflow(WorkflowError {
            code: WorkflowErrorCode::Rejected,
            ..
        }))
    ));
    assert_eq!(storage.load(&resumed.id()).unwrap().unwrap(), original);
    assert_eq!(account.signs.load(Ordering::Relaxed), 0);
    assert_eq!(account.dispatches.load(Ordering::Relaxed), 0);
    let journal = resumed.handle.journal_snapshot().unwrap().unwrap();
    let attempts = &journal.steps[0].transaction.as_ref().unwrap().attempts;
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].identity.as_ref(), Some(&identity(&transaction)));
}

#[test]
fn native_payment_error_retains_typed_cause_without_inline_progress_graph() {
    use std::error::Error as _;
    let cause =
        NativePaymentObservationError::Encoding(norito::Error::AllocationFailed { bytes: 17 });
    let expected = cause.to_string();
    let error = NativePaymentError::from(cause);
    assert!(std::mem::size_of::<NativePaymentError>() <= 128);
    assert_eq!(error.source().unwrap().to_string(), expected);
    let NativePaymentError::Observation { cause, progress } = error else {
        panic!("observation conversion retains its original typed cause");
    };
    assert!(matches!(
        cause.as_ref(),
        NativePaymentObservationError::Encoding(norito::Error::AllocationFailed { bytes: 17 })
    ));
    assert!(progress.is_none());
}
