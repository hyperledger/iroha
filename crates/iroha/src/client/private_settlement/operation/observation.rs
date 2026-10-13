//! Exact authenticated carrier outcomes and final-tip original receipt recovery.

use super::*;
use iroha_data_model::{
    block::SignedBlock, query::CommittedTransaction, sumeragi_finality::VerifiedSumeragiBlock,
    transaction::TransactionEntrypoint,
};
use std::{
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

pub(super) struct SettlementLedger {
    account: AccountClient,
    request: PrivateSettlementRequest,
    state: Arc<Mutex<Option<PublicContext>>>,
    verifier: Mutex<SumeragiFinalityVerifier>,
    reads: AtomicUsize,
    error: Mutex<Option<PrivateSettlementError>>,
    worker: Arc<tokio::sync::Semaphore>,
}
impl SettlementLedger {
    pub fn new(
        account: AccountClient,
        request: PrivateSettlementRequest,
        state: Arc<Mutex<Option<PublicContext>>>,
        verifier: SumeragiFinalityVerifier,
        worker: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            account,
            request,
            state,
            verifier: Mutex::new(verifier),
            reads: AtomicUsize::new(0),
            error: Mutex::new(None),
            worker,
        }
    }
    pub fn begin_call(&self, reads: usize) -> std::result::Result<(), PrivateSettlementError> {
        self.reads.store(reads, Ordering::Relaxed);
        *lock(&self.error)? = None;
        Ok(())
    }
    pub fn take_error(
        &self,
    ) -> std::result::Result<Option<PrivateSettlementError>, PrivateSettlementError> {
        Ok(lock(&self.error)?.take())
    }
    async fn proof(
        &self,
        height: u64,
    ) -> std::result::Result<
        iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
        PrivateSettlementError,
    > {
        let height = NonZeroU64::new(height).ok_or(PrivateSettlementError::Binding)?;
        self.reads
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .map_err(|_| PrivateSettlementError::ReadBudget)?;
        let proof = self
            .account
            .client()
            .get_sumeragi_finality_proof_async(height, SumeragiRootScope::Global)
            .await
            .map_err(PrivateSettlementError::Protocol)?;
        if proof.height() != height.get() {
            return Err(PrivateSettlementError::Binding);
        }
        Ok(proof)
    }
    async fn block(
        &self,
        height: u64,
    ) -> std::result::Result<VerifiedSumeragiBlock, PrivateSettlementError> {
        if height < 2 {
            return Err(PrivateSettlementError::Binding);
        }
        loop {
            let next = lock(&self.verifier)?
                .authenticated_height()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(PrivateSettlementError::Binding)?;
            if next > height {
                let proof = self.proof(height).await?;
                return Ok(lock(&self.verifier)?.verify_retained_decision(&proof)?);
            }
            let proof = self.proof(next).await?;
            let verified = lock(&self.verifier)?.verify(&proof)?;
            if next == height {
                return Ok(verified);
            }
        }
    }
    async fn located(
        &self,
        identity: &TransactionIdentityV1,
        height: Option<u64>,
    ) -> std::result::Result<
        Option<(VerifiedSumeragiBlock, CommittedTransaction)>,
        PrivateSettlementError,
    > {
        let hash =
            HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash));
        let height = if let Some(height) = height {
            height
        } else {
            let Some(response) = self
                .account
                .client()
                .fetch_transaction_status_response_global(hash)
                .await
                .map_err(PrivateSettlementError::Protocol)?
            else {
                return Ok(None);
            };
            super::super::super::validate_global_pipeline_status_response(&response, hash)
                .map_err(PrivateSettlementError::Protocol)?;
            let Some(height) = response.status.block_height else {
                return Ok(None);
            };
            height
        };
        let block = self.block(height).await?;
        let index = block
            .block()
            .network_entrypoints()
            .enumerate()
            .find_map(|(index, entry)| {
                let TransactionEntrypoint::External(transaction) = entry else {
                    return None;
                };
                (super::identity(transaction) == *identity).then_some(index)
            })
            .ok_or(PrivateSettlementError::Binding)?;
        let index = u32::try_from(index).map_err(|_| PrivateSettlementError::Binding)?;
        let evidence = evidence(block.block(), index)?;
        block.verify_transaction_execution(&self.request.manifest().network_id, &evidence)?;
        Ok(Some((block, evidence)))
    }
    fn barrier(
        &self,
    ) -> std::result::Result<PrivateSettlementPrepareBarrierV1, PrivateSettlementError> {
        Ok(lock(&self.state)?
            .as_ref()
            .ok_or(PrivateSettlementError::Binding)?
            .barrier
            .clone())
    }
    fn check_registration(
        &self,
        block: &VerifiedSumeragiBlock,
        evidence: &CommittedTransaction,
    ) -> std::result::Result<(), PrivateSettlementError> {
        if !evidence.result().is_ok() {
            return Err(PrivateSettlementError::Unresolved);
        }
        let TransactionEntrypoint::External(transaction) = evidence.entrypoint() else {
            return Err(PrivateSettlementError::Binding);
        };
        if check_payload(
            &self.request,
            lock(&self.state)?.as_ref(),
            transaction.payload(),
            false,
        )? != REGISTER
        {
            return Err(PrivateSettlementError::Binding);
        }
        if let Some(fee) = evidence.result().nexus_fee_receipt() {
            fee.validate_for_network_input(evidence.entrypoint(), block.height())
                .map_err(|_| PrivateSettlementError::Binding)?;
        }
        Ok(())
    }
    pub async fn verify_registration(
        &self,
        journal: &WorkflowJournalV1,
    ) -> std::result::Result<(), PrivateSettlementError> {
        let attempt = journal
            .steps
            .get(REGISTER)
            .and_then(|s| s.transaction.as_ref())
            .and_then(|t| t.attempts.last())
            .ok_or(PrivateSettlementError::Binding)?;
        let identity = attempt
            .identity
            .as_ref()
            .ok_or(PrivateSettlementError::Binding)?;
        let height = attempt.evidence.as_ref().and_then(|e| e.block_height);
        let (block, evidence) = self
            .located(identity, height)
            .await?
            .ok_or(PrivateSettlementError::Unresolved)?;
        self.check_registration(&block, &evidence)
    }
    pub async fn recover_business(
        &self,
        journal: &WorkflowJournalV1,
    ) -> std::result::Result<Option<VerifiedPrivateSettlementReceipt>, PrivateSettlementError> {
        if !journal.steps[PREPARE].is_done() {
            return Ok(None);
        }
        let barrier = self.barrier()?;
        // Completion is re-read from the original exact journal identity first. These
        // decoded locators do not authenticate an outcome, including after full restart.
        if let Some(attempt) = journal.steps[FINALIZE]
            .transaction
            .as_ref()
            .and_then(|t| t.attempts.last())
            && let Some(identity) = &attempt.identity
            && let Some((block, evidence)) = self
                .located(
                    identity,
                    attempt.evidence.as_ref().and_then(|e| e.block_height),
                )
                .await?
            && evidence.result().is_ok()
        {
            return Ok(Some(VerifiedPrivateSettlementReceipt::verify_recovered(
                &block, &barrier, evidence,
            )?));
        }
        // A public DTO supplies a height only. The independently retained barrier and
        // genesis-rooted successful original input/output authenticate the business result.
        let permit = self
            .worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| PrivateSettlementError::Worker)?;
        let client = self.account.client().clone();
        let bundle_id = barrier.manifest.bundle_id;
        let response = run_worker(permit, move || {
            client.private_settlement_bundle_receipt_v1(bundle_id)
        })
        .await?
        .map_err(PrivateSettlementError::Protocol)?;
        let PrivateSettlementBundleReceiptResponseV1::Finalized(receipt) = response else {
            return Ok(None);
        };
        let block = self.block(receipt.finalized_height).await?;
        for (index, entry) in block.block().network_entrypoints().enumerate() {
            let index = u32::try_from(index).map_err(|_| PrivateSettlementError::Binding)?;
            let TransactionEntrypoint::External(transaction) = entry else {
                continue;
            };
            let Executable::Instructions(instructions) = transaction.instructions() else {
                continue;
            };
            let [instruction] = instructions.as_ref() else {
                continue;
            };
            if instruction
                .as_any()
                .downcast_ref::<FinalizeAtomicPrivateSettlementV1>()
                .is_some_and(|i| i.commit_bundle.manifest.bundle_id == bundle_id)
                && block
                    .block()
                    .network_output_at(index)
                    .is_some_and(|(_, output)| output.result.is_ok())
            {
                return Ok(Some(VerifiedPrivateSettlementReceipt::verify_recovered(
                    &block,
                    &barrier,
                    evidence(block.block(), index)?,
                )?));
            }
        }
        Err(PrivateSettlementError::Binding)
    }
    async fn outcome(
        &self,
        identity: &TransactionIdentityV1,
    ) -> std::result::Result<CommittedOutcome, PrivateSettlementError> {
        let hash =
            HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash));
        let Some(response) = self
            .account
            .client()
            .fetch_transaction_status_response_global(hash)
            .await
            .map_err(PrivateSettlementError::Protocol)?
        else {
            // This permits only explicitly requested retransmission of the same bytes;
            // absence never closes this identity or authorizes a replacement.
            return Ok(CommittedOutcome::ExactAbsence);
        };
        super::super::super::validate_global_pipeline_status_response(&response, hash)
            .map_err(PrivateSettlementError::Protocol)?;
        let Some(height) = response.status.block_height else {
            return Ok(CommittedOutcome::ObservedNotFinal);
        };
        let (block, evidence) = self
            .located(identity, Some(height))
            .await?
            .ok_or(PrivateSettlementError::Binding)?;
        if !evidence.result().is_ok() {
            return Ok(CommittedOutcome::Rejected {
                detail: "independently authenticated original execution rejected this carrier"
                    .into(),
            });
        }
        let TransactionEntrypoint::External(transaction) = evidence.entrypoint() else {
            return Err(PrivateSettlementError::Binding);
        };
        let phase = check_payload(
            &self.request,
            lock(&self.state)?.as_ref(),
            transaction.payload(),
            false,
        )?;
        if phase == REGISTER {
            self.check_registration(&block, &evidence)?;
        } else {
            VerifiedPrivateSettlementReceipt::verify_recovered(&block, &self.barrier()?, evidence)?;
        }
        Ok(CommittedOutcome::Applied {
            block_height: Some(block.height()),
        })
    }
}
impl WorkflowLedger for SettlementLedger {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        expected: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            let transaction = match super::super::super::workflow_ledger::decode_signed(bytes) {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DispatchOutcome::NotAdmitted {
                        code: error.code,
                        detail: error.detail,
                    };
                }
            };
            let checked = (|| {
                check_payload(
                    &self.request,
                    lock(&self.state)?.as_ref(),
                    transaction.payload(),
                    true,
                )?;
                transaction
                    .verify_signature()
                    .map_err(|_| PrivateSettlementError::Binding)?;
                if &super::identity(&transaction) != expected
                    || bytes.len() as u64 > self.request.0.max_carrier_bytes
                {
                    return Err(PrivateSettlementError::Binding);
                }
                Ok::<_, PrivateSettlementError>(())
            })();
            if let Err(error) = checked {
                return DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::BindingMismatch,
                    detail: error.to_string(),
                };
            }
            let permit = match self.worker.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    return DispatchOutcome::NotAdmitted {
                        code: WorkflowErrorCode::LocalResourceUnavailable,
                        detail: "original private-settlement worker is still active".into(),
                    };
                }
            };
            let client = self.account.client().clone();
            // Reuse the existing sponsor-authenticated exact private carrier endpoint,
            // including its authenticated identical-carrier acknowledgement behavior.
            match run_worker(permit, move || {
                client.submit_private_settlement_bundle_v1(&PrivateSettlementBundleSubmitRequestV1 { transaction })
            }).await {
                Ok(Ok(_)) => DispatchOutcome::Accepted,
                _ => DispatchOutcome::Ambiguous { detail: "private-settlement submission may have been admitted; recover the exact original identity".into() },
            }
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async move {
            match self.outcome(identity).await {
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
pub(super) fn evidence(
    block: &SignedBlock,
    index: u32,
) -> std::result::Result<CommittedTransaction, PrivateSettlementError> {
    let entrypoint = block
        .network_entrypoint_at(index as usize)
        .ok_or(PrivateSettlementError::Binding)?
        .clone();
    let (output_index, _) = block
        .network_output_at(index)
        .ok_or(PrivateSettlementError::Binding)?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or(PrivateSettlementError::Binding)?
        .clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(index)
            .ok_or(PrivateSettlementError::Binding)?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or(PrivateSettlementError::Binding)?,
        output,
    })
}
