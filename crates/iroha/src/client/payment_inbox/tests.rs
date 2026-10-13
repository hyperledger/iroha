//! Durable credit, uncertain publication and idempotent notification controls.

use std::sync::atomic::{AtomicU8, Ordering};

use super::*;
use crate::workflow::{
    Digest32, FileWorkflowStorage, MemoryWorkflowStorage, WorkflowRunnerLease,
    WorkflowStorageErrorKind,
};

fn receipt() -> VerifiedPaymentReceipt {
    super::super::verified_payment::payment_receipt_for_testing()
}

fn destination(receipt: &VerifiedPaymentReceipt) -> AssetId {
    let SettlementDetails::Atomic(details) = &receipt.settlement().details else {
        panic!("atomic receipt fixture");
    };
    details.movements.as_slice()[0].destination.clone()
}

fn customer() -> Name {
    "customer-250000".parse().unwrap()
}

struct InterruptedStorage {
    inner: FileWorkflowStorage,
    failure: AtomicU8,
}

impl WorkflowStorage for InterruptedStorage {
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
        match self.failure.swap(0, Ordering::SeqCst) {
            1 => Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::Unavailable,
                "interrupted before publication",
            )),
            2 => {
                self.inner.compare_and_store(id, expected, record)?;
                Err(WorkflowStorageError::new(
                    WorkflowStorageErrorKind::WriteUncertain,
                    "interrupted after publication",
                ))
            }
            _ => self.inner.compare_and_store(id, expected, record),
        }
    }
}

#[test]
fn customer_credit_and_outbox_survive_restart_without_a_second_credit() {
    let root = tempfile::tempdir().unwrap();
    let proof = receipt();
    let bucket = destination(&proof);
    let inbox = PaymentInbox::new(Arc::new(
        FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
    ))
    .unwrap();
    assert!(
        inbox
            .pending_notification(&proof, &customer(), &bucket)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        inbox.acknowledge_notification(&proof, &customer(), &bucket),
        Err(PaymentInboxError::CreditNotRecorded)
    ));
    assert_eq!(
        inbox.credit(&proof, &customer(), &bucket).unwrap(),
        PaymentCreditStatus::Recorded
    );
    let pending = inbox
        .pending_notification(&proof, &customer(), &bucket)
        .unwrap()
        .unwrap();
    assert_eq!(pending.quantity, 250_000_u32.into());
    assert_eq!(pending.settlement_id, *proof.settlement_id());
    assert_eq!(pending.transaction_hash, proof.transaction_hash());
    drop(inbox);

    let inbox = PaymentInbox::new(Arc::new(
        FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
    ))
    .unwrap();
    // A new process obtains this type only by verifying the original evidence again.
    let reverified = receipt();
    assert_eq!(
        inbox.credit(&reverified, &customer(), &bucket).unwrap(),
        PaymentCreditStatus::AlreadyRecorded {
            notification_pending: true
        }
    );
    assert_eq!(
        inbox
            .pending_notification(&reverified, &customer(), &bucket)
            .unwrap(),
        Some(pending)
    );
    inbox
        .acknowledge_notification(&reverified, &customer(), &bucket)
        .unwrap();
    inbox
        .acknowledge_notification(&reverified, &customer(), &bucket)
        .unwrap();
    assert!(
        inbox
            .pending_notification(&reverified, &customer(), &bucket)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        inbox.credit(&reverified, &customer(), &bucket).unwrap(),
        PaymentCreditStatus::AlreadyRecorded {
            notification_pending: false
        }
    );
}

#[test]
fn customer_credit_reconciles_uncertain_write_and_notification_acknowledgement() {
    for failure in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let storage = Arc::new(InterruptedStorage {
            inner: FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
            failure: AtomicU8::new(failure),
        });
        let inbox = PaymentInbox::new(storage.clone()).unwrap();
        let proof = receipt();
        let bucket = destination(&proof);
        let error = inbox.credit(&proof, &customer(), &bucket).unwrap_err();
        assert!(matches!(error, PaymentInboxError::Storage(_)));
        assert_eq!(
            inbox.credit(&proof, &customer(), &bucket).unwrap(),
            if failure == 1 {
                PaymentCreditStatus::Recorded
            } else {
                PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true,
                }
            }
        );
        let pending = inbox
            .pending_notification(&proof, &customer(), &bucket)
            .unwrap()
            .unwrap();
        storage.failure.store(failure, Ordering::SeqCst);
        assert!(matches!(
            inbox.acknowledge_notification(&proof, &customer(), &bucket),
            Err(PaymentInboxError::Storage(_))
        ));
        let after_interruption = inbox
            .pending_notification(&proof, &customer(), &bucket)
            .unwrap();
        assert_eq!(after_interruption, (failure == 1).then_some(pending));
        inbox
            .acknowledge_notification(&proof, &customer(), &bucket)
            .unwrap();
        assert_eq!(
            inbox.credit(&proof, &customer(), &bucket).unwrap(),
            PaymentCreditStatus::AlreadyRecorded {
                notification_pending: false
            }
        );
    }
}

#[test]
fn customer_credit_rejects_changed_mapping_wrong_bucket_and_corrupt_storage() {
    assert!(matches!(
        PaymentInbox::new(Arc::new(MemoryWorkflowStorage::default())),
        Err(PaymentInboxError::NonDurableStorage)
    ));
    let root = tempfile::tempdir().unwrap();
    let storage = Arc::new(FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap());
    let inbox = PaymentInbox::new(storage.clone()).unwrap();
    let proof = receipt();
    let bucket = destination(&proof);
    let wrong_bucket = AssetId::of(
        bucket.definition().clone(),
        proof.settlement_id().owner().clone(),
    );
    assert!(matches!(
        inbox.credit(&proof, &customer(), &wrong_bucket),
        Err(PaymentInboxError::DestinationMismatch)
    ));
    inbox.credit(&proof, &customer(), &bucket).unwrap();
    let other_customer = "another-customer".parse().unwrap();
    assert!(matches!(
        inbox.credit(&proof, &other_customer, &bucket),
        Err(PaymentInboxError::CreditConflict)
    ));
    assert!(matches!(
        inbox.acknowledge_notification(&proof, &other_customer, &bucket),
        Err(PaymentInboxError::CreditConflict)
    ));
    let entry = credit_entry(&proof, &customer(), &bucket).unwrap();
    let key = credit_key(&entry).unwrap();
    let mut remapped = entry.clone();
    remapped.customer = other_customer;
    assert_eq!(
        credit_key(&remapped).unwrap(),
        key,
        "mapping cannot mint a new business identity"
    );
    let mut foreign_network = entry.clone();
    foreign_network.network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"independently selected other network"),
    ));
    assert_ne!(credit_key(&foreign_network).unwrap(), key);
    let mut foreign_payer = entry.clone();
    foreign_payer.settlement_id = SettlementId::new(
        bucket.account().clone(),
        entry.settlement_id.reference().clone(),
    );
    assert_ne!(credit_key(&foreign_payer).unwrap(), key);
    let bytes = storage.load(&key).unwrap().unwrap();
    let mut substituted: CreditRecord = norito::decode_canonical(&bytes).unwrap();
    substituted.credit.receipt_digest = Hash::new(b"different successful receipt");
    let substituted = norito::encode_canonical(&substituted).unwrap();
    storage
        .compare_and_store(&key, Some(&record_digest(&bytes)), &substituted)
        .unwrap();
    assert!(matches!(
        inbox.credit(&proof, &customer(), &bucket),
        Err(PaymentInboxError::CreditConflict)
    ));
    storage
        .compare_and_store(&key, Some(&record_digest(&substituted)), b"corrupt")
        .unwrap();
    assert!(matches!(
        inbox.credit(&proof, &customer(), &bucket),
        Err(PaymentInboxError::Codec(_))
    ));
    assert!(matches!(
        inbox.pending_notification(&proof, &customer(), &bucket),
        Err(PaymentInboxError::Codec(_))
    ));
}

#[test]
fn independent_inbox_instances_publish_one_credit_under_concurrent_delivery() {
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(receipt());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let inbox = PaymentInbox::new(Arc::new(
            FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
        ))
        .unwrap();
        let proof = Arc::clone(&proof);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let bucket = destination(&proof);
            barrier.wait();
            match inbox.credit(&proof, &customer(), &bucket) {
                Ok(PaymentCreditStatus::Recorded) => 1,
                Ok(PaymentCreditStatus::AlreadyRecorded {
                    notification_pending: true,
                }) => 0,
                Err(PaymentInboxError::Storage(error))
                    if error.kind == WorkflowStorageErrorKind::Conflict =>
                {
                    assert_eq!(
                        inbox.credit(&proof, &customer(), &bucket).unwrap(),
                        PaymentCreditStatus::AlreadyRecorded {
                            notification_pending: true
                        }
                    );
                    0
                }
                outcome => panic!("unexpected concurrent delivery: {outcome:?}"),
            }
        }));
    }
    // Keep the directory alive until every worker finishes, even if one panics.
    // Otherwise unwinding the first join can manufacture missing-path errors in
    // the remaining workers and hide the original storage refusal.
    let outcomes = workers
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect::<Vec<_>>();
    assert_eq!(outcomes.into_iter().map(Result::unwrap).sum::<u32>(), 1);
}
