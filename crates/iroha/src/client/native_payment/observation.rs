//! Proof-gated carrier reads and original business receipt recovery.

use super::*;
use crate::{
    query::QueryError,
    workflow::{CommittedOutcome, DispatchOutcome, TransactionIdentityV1, WorkflowLedger},
};
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    executor::ValidationFail,
    query::{
        CommittedTransaction,
        error::{FindError, QueryExecutionFail},
        settlement::FindSettlementReceiptById,
    },
    sumeragi_finality::{
        FinalityError, FinalityReadError, SumeragiFinalityProof, VerifiedSumeragiBlock,
    },
    transaction::error::TransactionRejectionReason,
};
use std::num::NonZeroU64;

/// Original observation/verification failure. Local resource errors are not ledger rejection.
#[derive(Debug, thiserror::Error)]
pub enum NativePaymentObservationError {
    /// Existing typed singular-query failure.
    #[error(transparent)]
    Query(#[from] QueryError),
    /// Existing finality transport/codec failure, preserving the original error chain.
    #[error("finality/status transport failed: {0}")]
    Transport(#[source] eyre::Report),
    /// The native finality verifier's original typed error, including resource custody.
    #[error(transparent)]
    Finality(#[from] FinalityReadError),
    /// Exact transaction input/output membership authentication failed.
    #[error(transparent)]
    Execution(#[from] FinalityError),
    /// Complete payment, network or authenticated fee verification failed.
    #[error(transparent)]
    Receipt(#[from] super::super::PaymentReceiptVerificationError),
    /// Original canonical encoder failure.
    #[error("native payment encoding failed: {0}")]
    Encoding(#[source] norito::Error),
    /// Local bounded proof-read budget; retry with the retained verifier or a larger local budget.
    #[error("native payment proof-read budget exhausted; verification remains resumable")]
    ReadBudgetExhausted,
    /// No exact candidate is present at the selected locator.
    #[error("payment locator differs from its authenticated block or carrier")]
    CandidateMismatch,
    /// Authenticated original fees differ from the caller's exact independent authorization.
    #[error("original payment fee authorization differs from the retained request")]
    FeeAuthorizationMismatch,
    /// Stored completion changed or no longer matches the independently reverified original.
    #[error("stored payment completion differs from fresh verified evidence")]
    CompletionMismatch,
    /// A local worker or synchronization owner failed; no consensus conclusion was made.
    #[error("payment observation worker failed: {0}")]
    Worker(String),
}

#[derive(Clone, Copy)]
pub(super) struct PaymentLocator {
    pub height: u64,
    pub block_hash: HashOf<BlockHeader>,
}
pub(super) enum CarrierLocation {
    Absent,
    Observed(Option<u64>),
}

pub(super) trait PaymentSource: Send + Sync {
    fn settlement<'a>(
        &'a self,
        id: &'a iroha_data_model::isi::SettlementId,
    ) -> WorkflowFuture<'a, Result<Option<PaymentLocator>, NativePaymentObservationError>>;
    fn carrier(
        &self,
        hash: HashOf<SignedTransaction>,
    ) -> WorkflowFuture<'_, Result<CarrierLocation, NativePaymentObservationError>>;
    fn proof(
        &self,
        height: NonZeroU64,
    ) -> WorkflowFuture<'_, Result<SumeragiFinalityProof, NativePaymentObservationError>>;
}

pub(super) struct OnlinePaymentSource(pub AccountClient);
impl PaymentSource for OnlinePaymentSource {
    fn settlement<'a>(
        &'a self,
        id: &'a iroha_data_model::isi::SettlementId,
    ) -> WorkflowFuture<'a, Result<Option<PaymentLocator>, NativePaymentObservationError>> {
        Box::pin(async move {
            match self
                .0
                .query_single(FindSettlementReceiptById::new(id.clone()))
                .await
            {
                Ok(receipt) => Ok(Some(PaymentLocator {
                    height: receipt.block_height,
                    block_hash: receipt.block_hash,
                })),
                Err(QueryError::Validation(ValidationFail::QueryFailed(
                    QueryExecutionFail::Find(FindError::SettlementReceipt(missing)),
                ))) if &missing == id => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }
    fn carrier(
        &self,
        hash: HashOf<SignedTransaction>,
    ) -> WorkflowFuture<'_, Result<CarrierLocation, NativePaymentObservationError>> {
        Box::pin(async move {
            let response = self
                .0
                .client()
                .fetch_transaction_status_response_global(hash)
                .await
                .map_err(NativePaymentObservationError::Transport)?;
            let Some(response) = response else {
                return Ok(CarrierLocation::Absent);
            };
            super::super::validate_global_pipeline_status_response(&response, hash)
                .map_err(NativePaymentObservationError::Transport)?;
            // Every status, including Applied, Rejected and Expired, selects a candidate only.
            Ok(CarrierLocation::Observed(response.status.block_height))
        })
    }
    fn proof(
        &self,
        height: NonZeroU64,
    ) -> WorkflowFuture<'_, Result<SumeragiFinalityProof, NativePaymentObservationError>> {
        Box::pin(async move {
            self.0
                .client()
                .get_sumeragi_finality_proof_async(height, SumeragiRootScope::Global)
                .await
                .map_err(NativePaymentObservationError::Transport)
        })
    }
}

pub(super) struct NativePaymentLedger {
    pub request: NativePaymentRequest,
    verifier: Mutex<SumeragiFinalityVerifier>,
    dispatch: Arc<dyn WorkflowLedger>,
    source: Arc<dyn PaymentSource>,
    reads_remaining: AtomicUsize,
    receipt: Mutex<Option<VerifiedPaymentReceipt>>,
    error: Mutex<Option<NativePaymentObservationError>>,
    replay: Mutex<Option<PaymentLocator>>,
}
fn lock<T>(
    value: &Mutex<T>,
) -> Result<std::sync::MutexGuard<'_, T>, NativePaymentObservationError> {
    value.lock().map_err(|_| {
        NativePaymentObservationError::Worker("poisoned payment observation owner".into())
    })
}
impl NativePaymentLedger {
    pub fn new(
        request: NativePaymentRequest,
        verifier: SumeragiFinalityVerifier,
        dispatch: Arc<dyn WorkflowLedger>,
        source: Arc<dyn PaymentSource>,
    ) -> Self {
        Self {
            request,
            verifier: Mutex::new(verifier),
            dispatch,
            source,
            reads_remaining: AtomicUsize::new(0),
            receipt: Mutex::new(None),
            error: Mutex::new(None),
            replay: Mutex::new(None),
        }
    }
    pub fn begin_call(&self, reads: usize) -> Result<(), NativePaymentObservationError> {
        self.reads_remaining.store(reads, Ordering::Relaxed);
        *lock(&self.error)? = None;
        *lock(&self.receipt)? = None;
        Ok(())
    }
    pub fn take_receipt(
        &self,
    ) -> Result<Option<VerifiedPaymentReceipt>, NativePaymentObservationError> {
        Ok(lock(&self.receipt)?.take())
    }
    pub fn take_error(
        &self,
    ) -> Result<Option<NativePaymentObservationError>, NativePaymentObservationError> {
        Ok(lock(&self.error)?.take())
    }

    async fn read_proof(
        &self,
        height: u64,
    ) -> Result<SumeragiFinalityProof, NativePaymentObservationError> {
        let height =
            NonZeroU64::new(height).ok_or(NativePaymentObservationError::CandidateMismatch)?;
        self.reads_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .map_err(|_| NativePaymentObservationError::ReadBudgetExhausted)?;
        let proof = self.source.proof(height).await?;
        if proof.height() != height.get() {
            return Err(NativePaymentObservationError::CandidateMismatch);
        }
        Ok(proof)
    }
    async fn verified_block(
        &self,
        height: u64,
    ) -> Result<VerifiedSumeragiBlock, NativePaymentObservationError> {
        if height < 2 {
            return Err(NativePaymentObservationError::CandidateMismatch);
        }
        loop {
            let next = lock(&self.verifier)?
                .authenticated_height()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(NativePaymentObservationError::CandidateMismatch)?;
            if next > height {
                let proof = self.read_proof(height).await?;
                return Ok(lock(&self.verifier)?.verify_retained_decision(&proof)?);
            }
            // One bounded existing proof transport at a time; no retained block/proof buffer.
            let proof = self.read_proof(next).await?;
            let block = lock(&self.verifier)?.verify(&proof)?;
            if next == height {
                return Ok(block);
            }
        }
    }
    fn check_fees(
        &self,
        receipt: &VerifiedPaymentReceipt,
    ) -> Result<(), NativePaymentObservationError> {
        let TransactionEntrypoint::External(transaction) = receipt.evidence().entrypoint() else {
            return Err(NativePaymentObservationError::CandidateMismatch);
        };
        if transaction.fee_payment_intent() != &self.request.fee_payment
            || transaction.authority() != self.request.intent.settlement_id.owner()
        {
            return Err(NativePaymentObservationError::FeeAuthorizationMismatch);
        }
        self.request
            .validate_payload(transaction.payload())
            .map_err(|_| NativePaymentObservationError::CandidateMismatch)?;
        Ok(())
    }
    pub async fn recover_business(
        &self,
        marker: Option<&NativePaymentCompletionV1>,
    ) -> Result<Option<VerifiedPaymentReceipt>, NativePaymentObservationError> {
        let replay = *lock(&self.replay)?;
        let locator = if let Some(marker) = marker {
            Some(PaymentLocator {
                height: marker.block_height,
                block_hash: HashOf::from_untyped_unchecked(Hash::prehashed(marker.block_hash)),
            })
        } else if replay.is_some() {
            replay
        } else {
            self.source
                .settlement(&self.request.intent.settlement_id)
                .await?
        };
        let Some(locator) = locator else {
            return Ok(None);
        };
        let block = self.verified_block(locator.height).await?;
        if block.header().hash() != locator.block_hash {
            return Err(NativePaymentObservationError::CandidateMismatch);
        }
        let candidate = block
            .block()
            .network_entrypoints()
            .enumerate()
            .find_map(|(index, entry)| {
                let index = u32::try_from(index).ok()?;
                let TransactionEntrypoint::External(transaction) = entry else {
                    return None;
                };
                let iroha_data_model::transaction::Executable::Instructions(instructions) =
                    transaction.instructions()
                else {
                    return None;
                };
                let [instruction] = instructions.as_ref() else {
                    return None;
                };
                let any = instruction.as_any();
                let intent =
                    any.downcast_ref::<SettleAtomic>().or_else(|| match any
                        .downcast_ref::<SettlementInstructionBox>()
                    {
                        Some(SettlementInstructionBox::Atomic(intent)) => Some(intent),
                        _ => None,
                    })?;
                (intent.settlement_id == self.request.intent.settlement_id
                    && block
                        .block()
                        .network_output_at(index)
                        .is_some_and(|(_, output)| output.result.is_ok()))
                .then_some(index)
            })
            .ok_or(NativePaymentObservationError::CandidateMismatch)?;
        let receipt = VerifiedPaymentReceipt::verify_recovered(
            &block,
            self.request.intent.network_id,
            &self.request.intent,
            evidence(block.block(), candidate)?,
        )?;
        self.check_fees(&receipt)?;
        Ok(Some(receipt))
    }
    async fn read_carrier(
        &self,
        identity: &TransactionIdentityV1,
    ) -> Result<CommittedOutcome, NativePaymentObservationError> {
        let hash =
            HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash));
        let location = self.source.carrier(hash).await?;
        let height = match location {
            CarrierLocation::Absent => return Ok(CommittedOutcome::ExactAbsence),
            CarrierLocation::Observed(None) => return Ok(CommittedOutcome::ObservedNotFinal),
            CarrierLocation::Observed(Some(height)) => height,
        };
        let block = self.verified_block(height).await?;
        let index = block
            .block()
            .network_entrypoints()
            .enumerate()
            .find_map(|(index, entry)| {
                let index = u32::try_from(index).ok()?;
                let TransactionEntrypoint::External(transaction) = entry else {
                    return None;
                };
                (transaction.hash() == hash
                    && Hash::from(transaction.hash_as_entrypoint()).as_ref()
                        == &identity.entrypoint_hash)
                    .then_some(index)
            })
            .ok_or(NativePaymentObservationError::CandidateMismatch)?;
        let evidence = evidence(block.block(), index)?;
        block.verify_transaction_execution(&self.request.intent.network_id, &evidence)?;
        if evidence.result().is_ok() {
            let receipt = VerifiedPaymentReceipt::verify(
                &block,
                self.request.intent.network_id,
                hash,
                &self.request.intent,
                evidence,
            )?;
            self.check_fees(&receipt)?;
            *lock(&self.receipt)? = Some(receipt);
            Ok(CommittedOutcome::Applied {
                block_height: Some(height),
            })
        } else {
            if let Err(TransactionRejectionReason::Validation(ValidationFail::SettlementReplay(
                replay,
            ))) = &evidence.result().0
                && replay.settlement_id == self.request.intent.settlement_id
            {
                *lock(&self.replay)? = Some(PaymentLocator {
                    height: replay.committed_block_height,
                    block_hash: replay.committed_block_hash,
                });
            }
            Ok(CommittedOutcome::Rejected {
                detail: "independently authenticated execution rejected this exact signed carrier"
                    .into(),
            })
        }
    }
}
impl WorkflowLedger for NativePaymentLedger {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            match self.request.checked_signed_carrier(bytes) {
                Ok((_, actual)) if &actual == identity => {
                    self.dispatch.dispatch(bytes, identity).await
                }
                Ok(_) => DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::BindingMismatch,
                    detail: "native payment dispatch identity differs from its signed bytes".into(),
                },
                Err(error) => DispatchOutcome::NotAdmitted {
                    code: error.code,
                    detail: error.detail,
                },
            }
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async move {
            match self.read_carrier(identity).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    let detail = error.to_string();
                    if let Ok(mut slot) = lock(&self.error)
                        && slot.is_none()
                    {
                        *slot = Some(error);
                    }
                    CommittedOutcome::ReadFailed { detail }
                }
            }
        })
    }
}

fn evidence(
    block: &SignedBlock,
    index: u32,
) -> Result<CommittedTransaction, NativePaymentObservationError> {
    let entrypoint = block
        .network_entrypoint_at(index as usize)
        .ok_or(NativePaymentObservationError::CandidateMismatch)?
        .clone();
    let (output_index, _) = block
        .network_output_at(index)
        .ok_or(NativePaymentObservationError::CandidateMismatch)?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or(NativePaymentObservationError::CandidateMismatch)?
        .clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(index)
            .ok_or(NativePaymentObservationError::CandidateMismatch)?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or(NativePaymentObservationError::CandidateMismatch)?,
        output,
    })
}
