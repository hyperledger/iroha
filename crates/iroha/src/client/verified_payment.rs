//! Successful native payment receipts joined to independently authenticated finality.

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    block::consensus::{NexusFeeReceipt, SumeragiRootScope},
    isi::{
        AtomicSettlementDetails, SettleAtomic, SettlementDetails, SettlementId,
        SettlementInstructionBox, SettlementReceipt,
    },
    query::CommittedTransaction,
    sumeragi_finality::{FinalityError, VerifiedSumeragiBlock},
    transaction::{Executable, FeeChargeKind, SignedTransaction, TransactionEntrypoint},
};

/// Why a native payment cannot be admitted as an independently verified receipt.
#[derive(Debug, thiserror::Error)]
pub enum PaymentReceiptVerificationError {
    /// The caller's network differs from the signed settlement intent.
    #[error("payment intent differs from the independently selected network")]
    NetworkMismatch,
    /// The authenticated root is not the selected Global settlement chain.
    #[error("payment receipt requires authenticated Global finality")]
    WrongRootScope,
    /// The supplied evidence does not name the caller's exact signed transaction.
    #[error("payment evidence differs from the expected signed transaction")]
    TransactionMismatch,
    /// This operation accepts exactly one direct native atomic settlement instruction.
    #[error("payment receipt requires one direct SettleAtomic instruction")]
    UnsupportedCarrier,
    /// Successful signed terms differ from the caller's independently retained intent.
    #[error("payment evidence differs from the expected complete settlement intent")]
    IntentMismatch,
    /// The expected movement vector is invalid.
    #[error("invalid expected payment intent: {0}")]
    InvalidIntent(&'static str),
    /// Exact successful transaction/output inclusion or signature validation failed.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// Pipeline gas lacks the typed authenticated fee outcome supported by this operation.
    #[error("payment receipt cannot authenticate PipelineGas charges")]
    UnsupportedFeeOutcome,
    /// The authenticated Nexus fee record is inconsistent with its original signed input.
    #[error("invalid authenticated Nexus fee outcome: {0}")]
    InvalidFeeOutcome(String),
    /// The complete native intent could not be canonically hashed.
    #[error("payment intent encoding failed: {0}")]
    IntentEncoding(#[from] norito::Error),
}

/// A successful native payment and its exact authenticated Nexus fee outcome.
///
/// Construction requires [`VerifiedSumeragiBlock`], issued by the existing finality
/// verifier rooted in the caller's independently authenticated signed genesis.
/// Raw certificates, inclusion proofs, query status and decoded receipt objects do
/// not construct this type. It deliberately implements no deserializer.
///
/// The supported carrier has one direct [`SettleAtomic`] instruction, including
/// a single movement. Its existing [`SettlementReceipt`] is projected from the
/// exact signed instruction and successful certified execution. This is not an
/// authenticated query of arbitrary current World state. Customer credit still
/// needs the application's durable uniqueness transaction keyed by settlement ID.
///
/// ```compile_fail
/// use iroha::client::VerifiedPaymentReceipt;
/// // Decoded receipt bytes never grant successful-payment verification.
/// let _ = norito::decode_canonical::<VerifiedPaymentReceipt>(&[]);
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedPaymentReceipt {
    network: NetworkId,
    transaction_hash: HashOf<SignedTransaction>,
    settlement_id: SettlementId,
    context_id: Hash,
    receipt: SettlementReceipt,
    evidence: CommittedTransaction,
}

impl VerifiedPaymentReceipt {
    /// Verify the caller's exact signed payment against a genesis-rooted certified block.
    ///
    /// Keep `expected_network`, `expected_transaction` and `expected_intent` from
    /// the caller's authorized request, independently of the response. The complete
    /// intent binds every payer bucket, asset/scope, recipient, quantity, reference
    /// metadata and expiry. The signed hash additionally binds authority and fee
    /// authorization. Verification needs no block after the payment's own carrier.
    ///
    /// # Errors
    /// Rejects foreign networks/roots, unsuccessful or substituted execution,
    /// different signed terms, composite/contract carriers and unsupported fees.
    pub fn verify(
        block: &VerifiedSumeragiBlock,
        expected_network: NetworkId,
        expected_transaction: HashOf<SignedTransaction>,
        expected_intent: &SettleAtomic,
        evidence: CommittedTransaction,
    ) -> Result<Self, PaymentReceiptVerificationError> {
        use PaymentReceiptVerificationError as Error;

        if expected_intent.network_id != expected_network
            || block.commitment().schedule.current.network_id != expected_network
        {
            return Err(Error::NetworkMismatch);
        }
        if block.root_scope() != SumeragiRootScope::Global {
            return Err(Error::WrongRootScope);
        }
        expected_intent.validate().map_err(Error::InvalidIntent)?;
        block.verify_committed_transaction(&expected_network, &evidence)?;
        let TransactionEntrypoint::External(transaction) = evidence.entrypoint() else {
            return Err(Error::UnsupportedCarrier);
        };
        if transaction.hash() != expected_transaction {
            return Err(Error::TransactionMismatch);
        }
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(Error::UnsupportedCarrier);
        };
        let [instruction] = instructions.as_ref() else {
            return Err(Error::UnsupportedCarrier);
        };
        let instruction = instruction.as_any();
        let intent = if let Some(intent) = instruction.downcast_ref::<SettleAtomic>() {
            intent
        } else if let Some(SettlementInstructionBox::Atomic(intent)) =
            instruction.downcast_ref::<SettlementInstructionBox>()
        {
            intent
        } else {
            return Err(Error::UnsupportedCarrier);
        };
        if intent != expected_intent {
            return Err(Error::IntentMismatch);
        }
        if transaction
            .fee_payment_intent()
            .charge_limits()
            .iter()
            .any(|limit| limit.kind == FeeChargeKind::PipelineGas)
        {
            return Err(Error::UnsupportedFeeOutcome);
        }
        if let Some(fee) = evidence.result().nexus_fee_receipt() {
            fee.validate_for_network_input(evidence.entrypoint(), block.height())
                .map_err(Error::InvalidFeeOutcome)?;
        }
        let receipt = SettlementReceipt {
            authority: transaction.authority().clone(),
            metadata: intent.metadata.clone(),
            block_height: block.height(),
            block_hash: block.header().hash(),
            executed_at_ms: block.header().creation_time_ms,
            details: SettlementDetails::Atomic(AtomicSettlementDetails {
                movements: intent.movements.resolve().map_err(Error::InvalidIntent)?,
                intent_hash: intent.intent_hash()?,
            }),
        };
        Ok(Self {
            network: expected_network,
            transaction_hash: expected_transaction,
            settlement_id: intent.settlement_id.clone(),
            context_id: block.context_id(),
            receipt,
            evidence,
        })
    }

    /// Independently selected genesis-derived network identity.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Exact successful signed carrier, including its authority and fee intent.
    #[must_use]
    pub const fn transaction_hash(&self) -> HashOf<SignedTransaction> {
        self.transaction_hash
    }

    /// Consensus-enforced business identifier of the successful native settlement.
    #[must_use]
    pub const fn settlement_id(&self) -> &SettlementId {
        &self.settlement_id
    }

    /// Original authenticated native header/result identity.
    #[must_use]
    pub const fn context_id(&self) -> Hash {
        self.context_id
    }

    /// Exact successful movements and metadata under the existing settlement schema.
    #[must_use]
    pub const fn settlement(&self) -> &SettlementReceipt {
        &self.receipt
    }

    /// Exact authenticated Nexus charge, or authenticated absence of that receipt.
    ///
    /// Absence remains distinct from a fabricated zero-valued fee record. Carriers
    /// authorizing PipelineGas are unsupported until its outcome can be authenticated.
    #[must_use]
    pub fn nexus_fee_receipt(&self) -> Option<&NexusFeeReceipt> {
        self.evidence.result().nexus_fee_receipt()
    }

    /// Original input/output evidence; persist it with the independent finality history.
    ///
    /// Decoding persisted evidence grants no verification status. Resume must pass
    /// it through this verifier again with the original expected payment intent.
    #[must_use]
    pub const fn evidence(&self) -> &CommittedTransaction {
        &self.evidence
    }
}

#[cfg(test)]
mod tests;
