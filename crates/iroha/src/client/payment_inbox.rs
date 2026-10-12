//! Durable customer-credit entries and an outbox admitted only by verified payment receipts.

use std::sync::Arc;

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::AssetId,
    block::BlockHeader,
    isi::{SettlementDetails, SettlementId},
    transaction::SignedTransaction,
};
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use norito::codec::{Decode, Encode};

use super::VerifiedPaymentReceipt;
use crate::workflow::{
    WorkflowId, WorkflowStorage, WorkflowStorageDurability, WorkflowStorageError, record_digest,
};

/// Why a customer credit or its notification could not be recorded.
#[derive(Debug, thiserror::Error)]
pub enum PaymentInboxError {
    /// Customer credits require persistence across processes and power loss.
    #[error("payment inbox requires durable storage")]
    NonDurableStorage,
    /// This inbox handles exactly one movement to the independently selected asset bucket.
    #[error("payment does not contain exactly one movement to the expected destination")]
    DestinationMismatch,
    /// The existing business identity has a different customer mapping or verified receipt.
    #[error("payment identity is already bound to a different customer credit")]
    CreditConflict,
    /// A notification cannot be acknowledged before its credit exists.
    #[error("payment credit has not been recorded")]
    CreditNotRecorded,
    /// Canonical journal encoding or decoding failed.
    #[error("payment inbox journal: {0}")]
    Codec(#[from] norito::Error),
    /// Original storage failure, including a conflicting or uncertain write.
    #[error(transparent)]
    Storage(#[from] WorkflowStorageError),
}

/// Informational bank ledger entry and notification payload.
///
/// Decoding this entry does not verify a payment. Only [`VerifiedPaymentReceipt`]
/// authorizes [`PaymentInbox::credit`]. The notification's idempotency key is the
/// pair `(network, settlement_id)`; delivery may repeat until acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::client::PaymentCreditEntry")]
pub struct PaymentCreditEntry {
    /// Independently verified settlement network.
    pub network: NetworkId,
    /// Payer-scoped business identity; unrelated carrier hashes cannot create another credit.
    pub settlement_id: SettlementId,
    /// Independently selected bank customer, immutable once credited.
    pub customer: Name,
    /// Exact credited bank asset bucket, including balance scope.
    pub destination: AssetId,
    /// Successfully settled principal; fees never reduce this projection silently.
    pub quantity: Quantity,
    /// Exact original successful signed transaction.
    pub transaction_hash: HashOf<SignedTransaction>,
    /// Original successful certified height.
    pub block_height: u64,
    /// Original successful block.
    pub block_hash: HashOf<BlockHeader>,
    /// Commitment to the complete verified settlement, native context and fee outcome.
    pub receipt_digest: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::client::PaymentCreditRecord")]
struct CreditRecord {
    credit: PaymentCreditEntry,
    notification_pending: bool,
}

/// Result of atomically recording a credit and its pending notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentCreditStatus {
    /// A new immutable ledger entry and pending notification were published together.
    Recorded,
    /// The identical credit already exists; no second credit was created.
    AlreadyRecorded {
        /// Whether notification delivery still needs acknowledgement.
        notification_pending: bool,
    },
}

/// A minimal durable bank ledger with an inbox and outbox in the same atomic record.
///
/// One record is one customer-credit ledger entry. Derive balances from those entries
/// or implement this same unique-key transaction in the bank's database. Never call
/// a separate non-idempotent balance increment after this journal returns.
///
/// [`crate::workflow::FileWorkflowStorage`] supplies interprocess compare-and-store,
/// synced publication and interrupted-write recovery. Use a dedicated storage root.
/// A conflicting or uncertain write must be retried with the same verified receipt
/// and mapping. A restart must reverify persisted payment evidence before calling
/// this API; stored entries cannot reconstruct a verified receipt.
pub struct PaymentInbox {
    storage: Arc<dyn WorkflowStorage>,
}

impl PaymentInbox {
    /// Bind the bank inbox to durable atomic storage.
    ///
    /// # Errors
    /// Refuses process-local storage that cannot preserve customer credits.
    pub fn new(storage: Arc<dyn WorkflowStorage>) -> Result<Self, PaymentInboxError> {
        if storage.durability() != WorkflowStorageDurability::Durable {
            return Err(PaymentInboxError::NonDurableStorage);
        }
        Ok(Self { storage })
    }

    /// Record one customer credit and its pending notification in one atomic publication.
    ///
    /// `customer` and `destination` come from the bank's authenticated customer mapping,
    /// independently of the payment response. Exactly one movement must credit that bucket.
    ///
    /// # Errors
    /// Refuses a different destination, changed mapping/receipt, or storage/codec failure.
    /// An uncertain write may already have published the entry; retry the same identity.
    pub fn credit(
        &self,
        receipt: &VerifiedPaymentReceipt,
        customer: &Name,
        destination: &AssetId,
    ) -> Result<PaymentCreditStatus, PaymentInboxError> {
        let expected = credit_entry(receipt, customer, destination)?;
        let key = credit_key(&expected)?;
        if let Some((_, existing)) = self.load_matching(&key, &expected)? {
            return Ok(PaymentCreditStatus::AlreadyRecorded {
                notification_pending: existing.notification_pending,
            });
        }
        let bytes = norito::encode_canonical(&CreditRecord {
            credit: expected,
            notification_pending: true,
        })?;
        self.storage.compare_and_store(&key, None, &bytes)?;
        Ok(PaymentCreditStatus::Recorded)
    }

    /// Read an existing pending notification after revalidating its original payment.
    ///
    /// # Errors
    /// Refuses a changed mapping/receipt or failed journal read. Absence never credits funds.
    pub fn pending_notification(
        &self,
        receipt: &VerifiedPaymentReceipt,
        customer: &Name,
        destination: &AssetId,
    ) -> Result<Option<PaymentCreditEntry>, PaymentInboxError> {
        let expected = credit_entry(receipt, customer, destination)?;
        let key = credit_key(&expected)?;
        Ok(self
            .load_matching(&key, &expected)?
            .and_then(|(_, record)| record.notification_pending.then_some(record.credit)))
    }

    /// Acknowledge successful idempotent delivery without changing the credit entry.
    ///
    /// A delivery interrupted before this call is retried under the notification's same
    /// `(network, settlement_id)` key. This method does not send a notification or credit again.
    ///
    /// # Errors
    /// Refuses missing credit, changed mapping/receipt, or a storage/codec failure.
    pub fn acknowledge_notification(
        &self,
        receipt: &VerifiedPaymentReceipt,
        customer: &Name,
        destination: &AssetId,
    ) -> Result<(), PaymentInboxError> {
        let expected = credit_entry(receipt, customer, destination)?;
        let key = credit_key(&expected)?;
        let (bytes, mut record) = self
            .load_matching(&key, &expected)?
            .ok_or(PaymentInboxError::CreditNotRecorded)?;
        if record.notification_pending {
            record.notification_pending = false;
            self.storage.compare_and_store(
                &key,
                Some(&record_digest(&bytes)),
                &norito::encode_canonical(&record)?,
            )?;
        }
        Ok(())
    }

    fn load_matching(
        &self,
        key: &WorkflowId,
        expected: &PaymentCreditEntry,
    ) -> Result<Option<(Vec<u8>, CreditRecord)>, PaymentInboxError> {
        let Some(bytes) = self.storage.load(key)? else {
            return Ok(None);
        };
        let record: CreditRecord = norito::decode_canonical(&bytes)?;
        if &record.credit != expected {
            return Err(PaymentInboxError::CreditConflict);
        }
        Ok(Some((bytes, record)))
    }
}

fn credit_key(entry: &PaymentCreditEntry) -> Result<WorkflowId, norito::Error> {
    let bytes = norito::encode_canonical(&(entry.network, entry.settlement_id.clone()))?;
    let hash = Hash::new_from_chunks(&[b"iroha:bank-payment-inbox:v1\0", &bytes]);
    Ok(WorkflowId::from_bytes(*hash.as_ref()))
}

fn credit_entry(
    receipt: &VerifiedPaymentReceipt,
    customer: &Name,
    destination: &AssetId,
) -> Result<PaymentCreditEntry, PaymentInboxError> {
    let settlement = receipt.settlement();
    let SettlementDetails::Atomic(details) = &settlement.details else {
        return Err(PaymentInboxError::DestinationMismatch);
    };
    let [movement] = details.movements.as_slice() else {
        return Err(PaymentInboxError::DestinationMismatch);
    };
    if &movement.destination != destination {
        return Err(PaymentInboxError::DestinationMismatch);
    }
    let bytes = norito::encode_canonical(&(
        receipt.context_id(),
        settlement.clone(),
        receipt.nexus_fee_receipt().cloned(),
    ))?;
    Ok(PaymentCreditEntry {
        network: receipt.network(),
        settlement_id: receipt.settlement_id().clone(),
        customer: customer.clone(),
        destination: destination.clone(),
        quantity: movement.quantity.clone(),
        transaction_hash: receipt.transaction_hash(),
        block_height: settlement.block_height,
        block_hash: settlement.block_hash,
        receipt_digest: Hash::new_from_chunks(&[b"iroha:bank-payment-credit:v1\0", &bytes]),
    })
}

#[cfg(test)]
mod tests;
