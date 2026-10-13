//! Successful private settlement projected only from authenticated native execution.

use super::*;
use iroha_data_model::{
    block::consensus::{NexusFeeReceipt, SumeragiRootScope},
    nexus::PrivateSettlementReceiptV1,
    query::CommittedTransaction,
    sumeragi_finality::{FinalityError, VerifiedSumeragiBlock},
    transaction::{FeeChargeKind, TransactionEntrypoint},
};

/// Failure to authenticate the complete private settlement and its original carrier.
#[derive(Debug, thiserror::Error)]
pub enum PrivateSettlementReceiptError {
    /// Exact original input/output, signature or network authentication failed.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// Independent expected terms, root scope or original carrier differ.
    #[error("private settlement receipt binding mismatch")]
    BindingMismatch,
    /// The original execution did not succeed.
    #[error("private settlement execution was rejected")]
    Rejected,
    /// A malformed certificate, receipt or fee outcome was supplied.
    #[error("invalid private settlement public evidence")]
    InvalidEvidence,
    /// `PipelineGas` does not yet have the authenticated fee outcome this API requires.
    #[error("private settlement cannot authenticate PipelineGas charges")]
    UnsupportedFee,
}

/// An exact successful Finalize carrier rooted in independently authenticated genesis.
///
/// Committee certificates and decoded query receipts never construct this type. The
/// expected barrier must come from the caller's retained request and certificate
/// checkpoint. Any valid matching Prepare quorum is accepted; the original receipt
/// retains the actual certificate bytes executed by consensus. No successor block is
/// needed. This does not reveal, reconstruct or assert access to confidential amounts.
///
/// ```compile_fail
/// use iroha::client::VerifiedPrivateSettlementReceipt;
/// let _ = norito::decode_canonical::<VerifiedPrivateSettlementReceipt>(&[]);
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedPrivateSettlementReceipt {
    receipt: PrivateSettlementReceiptV1,
    context_id: Hash,
    evidence: CommittedTransaction,
}

impl VerifiedPrivateSettlementReceipt {
    /// Verify one known signed carrier against the caller's complete retained barrier.
    ///
    /// # Errors
    /// Refuses foreign roots/networks, rejection, substituted intent/fees, composite
    /// carriers and invalid committee certificates. The block must be issued by the
    /// existing verifier rooted in independently selected signed genesis.
    pub fn verify(
        block: &VerifiedSumeragiBlock,
        expected: &PrivateSettlementPrepareBarrierV1,
        hash: HashOf<SignedTransaction>,
        evidence: CommittedTransaction,
    ) -> std::result::Result<Self, PrivateSettlementReceiptError> {
        let receipt = Self::verify_recovered(block, expected, evidence)?;
        if receipt.transaction_hash() != hash {
            return Err(PrivateSettlementReceiptError::BindingMismatch);
        }
        Ok(receipt)
    }

    /// Recover the original successful carrier using independent terms, not a returned hash.
    ///
    /// # Errors
    /// The same authentication and complete-intent checks as [`Self::verify`].
    pub fn verify_recovered(
        block: &VerifiedSumeragiBlock,
        expected: &PrivateSettlementPrepareBarrierV1,
        evidence: CommittedTransaction,
    ) -> std::result::Result<Self, PrivateSettlementReceiptError> {
        use PrivateSettlementReceiptError as Error;
        validate_prepare_barrier_v1(expected).map_err(|_| Error::InvalidEvidence)?;
        if block.root_scope() != SumeragiRootScope::Global
            || block.commitment().schedule.current.network_id != expected.manifest.network_id
        {
            return Err(Error::BindingMismatch);
        }
        block.verify_transaction_execution(&expected.manifest.network_id, &evidence)?;
        if !evidence.result().is_ok() {
            return Err(Error::Rejected);
        }
        let TransactionEntrypoint::External(transaction) = evidence.entrypoint() else {
            return Err(Error::BindingMismatch);
        };
        check_carrier_context(transaction.payload(), &expected.manifest)?;
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(Error::BindingMismatch);
        };
        let [instruction] = instructions.as_ref() else {
            return Err(Error::BindingMismatch);
        };
        let instruction = instruction
            .as_any()
            .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
            .ok_or(Error::BindingMismatch)?;
        let actual = &instruction.commit_bundle;
        let commits = actual
            .legs
            .iter()
            .map(|leg| leg.commit.clone())
            .collect::<Vec<_>>();
        let reconstructed = build_private_settlement_commit_bundle_v1(expected, &commits)
            .map_err(|_| Error::InvalidEvidence)?;
        // Validate the original Prepare QCs, too; matching only their bodies is insufficient.
        let actual_barrier = Client::build_private_settlement_prepare_barrier_v1(
            actual.manifest.clone(),
            &(0..actual.legs.len())
                .map(|index| {
                    actual
                        .authority_catalog
                        .authority_for_leg(&actual.manifest, index)
                })
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::InvalidEvidence)?,
            actual.legs.iter().map(|leg| leg.delta.clone()).collect(),
            actual.legs.iter().map(|leg| leg.prepare.clone()).collect(),
        )
        .map_err(|_| Error::InvalidEvidence)?;
        if !actual_barrier.quorum_equivalent_to(expected)
            || actual.manifest != reconstructed.manifest
            || actual.authority_catalog != reconstructed.authority_catalog
            || actual.version != reconstructed.version
        {
            return Err(Error::BindingMismatch);
        }
        if let Some(fee) = evidence.result().nexus_fee_receipt() {
            fee.validate_for_network_input(evidence.entrypoint(), block.height())
                .map_err(|_| Error::InvalidEvidence)?;
        }
        let receipt = actual.clone().into_receipt(block.height());
        receipt
            .validate_shape()
            .map_err(|_| Error::InvalidEvidence)?;
        Ok(Self {
            receipt,
            context_id: block.context_id(),
            evidence,
        })
    }

    /// Complete original public receipt; all private values remain opaque commitments.
    #[must_use]
    pub const fn receipt(&self) -> &PrivateSettlementReceiptV1 {
        &self.receipt
    }
    /// Exact original successful signed transaction identity.
    #[must_use]
    pub fn transaction_hash(&self) -> HashOf<SignedTransaction> {
        let TransactionEntrypoint::External(transaction) = self.evidence.entrypoint() else {
            unreachable!("verified direct carrier")
        };
        transaction.hash()
    }
    /// Original authenticated consensus context.
    #[must_use]
    pub const fn context_id(&self) -> Hash {
        self.context_id
    }
    /// Authenticated Nexus charge; absence is preserved as absence, not fabricated zero.
    #[must_use]
    pub fn nexus_fee_receipt(&self) -> Option<&NexusFeeReceipt> {
        self.evidence.result().nexus_fee_receipt()
    }
    /// Exact original evidence; decoding it again grants no verification authority.
    #[must_use]
    pub const fn evidence(&self) -> &CommittedTransaction {
        &self.evidence
    }
}

pub(super) fn check_carrier_context(
    payload: &TransactionPayload,
    manifest: &AtomicPrivateSettlementV1,
) -> std::result::Result<(), PrivateSettlementReceiptError> {
    use PrivateSettlementReceiptError as Error;
    if payload.network_id() != Some(&manifest.network_id)
        || payload.authority() != &manifest.sponsor
        || payload.fee_payment != manifest.public_fee_intent
        || !payload.metadata.is_empty()
        || payload.attachments.is_some()
    {
        return Err(Error::BindingMismatch);
    }
    if payload
        .fee_payment
        .charge_limits()
        .iter()
        .any(|limit| limit.kind == FeeChargeKind::PipelineGas)
    {
        return Err(Error::UnsupportedFee);
    }
    Ok(())
}
