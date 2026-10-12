//! Destination proof verification of an exact relay carrier, including rejected execution.

use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use eyre::{Result, eyre};
use iroha::{
    client::{AccountClient, Client},
    workflow::{
        CommittedOutcome, DispatchOutcome, SignedStepTransaction, StepFailure,
        TransactionIdentityV1, WorkflowAccount, WorkflowBindingV1, WorkflowErrorCode,
        WorkflowFuture, WorkflowLedger,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::{SignedBlock, consensus::SumeragiRootScope},
    isi::InstructionBox,
    query::CommittedTransaction,
    sumeragi_finality::{SumeragiFinalityProof, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionEntrypoint, TransactionPayload,
    },
};

use iroha_version::codec::DecodeVersioned as _;

// Status selects a locator only. Its success/rejection/expiry text is never an outcome.
enum Location {
    Absent,
    Observed(Option<u64>),
}
trait Source: Send + Sync {
    fn locate(&self, hash: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>>;
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>>;
}
struct OnlineSource {
    client: Arc<Client>,
    scope: SumeragiRootScope,
}
impl Source for OnlineSource {
    fn locate(&self, hash: HashOf<SignedTransaction>) -> WorkflowFuture<'_, Result<Location>> {
        Box::pin(async move {
            let response = match self.scope {
                SumeragiRootScope::Global => {
                    self.client
                        .fetch_transaction_status_response_global(hash)
                        .await?
                }
                SumeragiRootScope::Dataspace { .. } => {
                    self.client
                        .fetch_transaction_status_response_local(hash)
                        .await?
                }
            };
            Ok(response.map_or(Location::Absent, |response| {
                Location::Observed(response.status.block_height)
            }))
        })
    }
    fn proof(&self, height: NonZeroU64) -> WorkflowFuture<'_, Result<SumeragiFinalityProof>> {
        let client = self.client.clone();
        let scope = self.scope;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || client.get_sumeragi_finality_proof(height, scope))
                .await?
        })
    }
}

pub(super) struct RelayLedger {
    source: Arc<dyn Source>,
    dispatch: Arc<dyn WorkflowLedger>,
    verifier: Mutex<SumeragiFinalityVerifier>,
    network: NetworkId,
    authority: AccountId,
    fee_payment: FeePaymentIntent,
    instruction: Mutex<Option<Hash>>,
    max_reads: usize,
    reads: AtomicUsize,
}
fn locked<T>(owner: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    owner
        .lock()
        .map_err(|_| eyre!("AMX destination verifier owner poisoned"))
}
impl RelayLedger {
    pub(super) fn new(
        client: Arc<Client>,
        account: AccountClient,
        dispatch: Arc<dyn WorkflowLedger>,
        verifier: SumeragiFinalityVerifier,
        scope: SumeragiRootScope,
        fee_payment: FeePaymentIntent,
        max_reads: usize,
    ) -> Self {
        Self {
            network: verifier.initial_epoch().network_id,
            authority: account.authority().clone(),
            fee_payment,
            instruction: Mutex::new(None),
            source: Arc::new(OnlineSource { client, scope }),
            dispatch,
            verifier: Mutex::new(verifier),
            max_reads,
            reads: AtomicUsize::new(max_reads),
        }
    }
    pub(super) fn begin_observation(&self, instruction: Hash) -> Result<()> {
        *locked(&self.instruction)? = Some(instruction);
        self.reads.store(self.max_reads, Ordering::Relaxed);
        Ok(())
    }
    // Journal labels and checksums are not authorization. Inspect the actual payload
    // against the independently reconstructed source before signing or dispatching.
    fn check_payload(&self, payload: &TransactionPayload) -> Result<()> {
        let expected = locked(&self.instruction)?
            .ok_or_else(|| eyre!("AMX carrier requires a freshly authenticated source intent"))?;
        let Executable::Instructions(instructions) = payload.instructions() else {
            return Err(eyre!("AMX carrier is not the exact native instruction"));
        };
        let [instruction] = instructions.as_ref() else {
            return Err(eyre!(
                "AMX carrier must contain exactly the original relay instruction"
            ));
        };
        if payload.network_id() != Some(&self.network)
            || payload.authority() != &self.authority
            || instruction_digest(instruction)? != expected
            || !payload.metadata.is_empty()
            || payload.attachments.is_some()
        {
            return Err(eyre!(
                "AMX carrier differs from authenticated source, route authority or fee intent"
            ));
        }
        Ok(())
    }
    fn check_authorized_payload(&self, payload: &TransactionPayload) -> Result<()> {
        self.check_payload(payload)?;
        if payload.fee_payment_intent() != &self.fee_payment {
            return Err(eyre!(
                "AMX carrier fee intent differs from current explicit route authorization"
            ));
        }
        Ok(())
    }
    fn check_signed(
        &self,
        bytes: &[u8],
        identity: &TransactionIdentityV1,
    ) -> Result<(), StepFailure> {
        let transaction = SignedTransaction::decode_all_versioned(bytes).map_err(|error| {
            let code = if error.is_local_resource_refusal() {
                WorkflowErrorCode::LocalResourceUnavailable
            } else {
                WorkflowErrorCode::NonCanonicalEncoding
            };
            StepFailure::new(code, error.to_string())
        })?;
        self.check_authorized_payload(transaction.payload())
            .map_err(|error| {
                StepFailure::new(WorkflowErrorCode::BindingMismatch, error.to_string())
            })?;
        transaction.verify_signature().map_err(|error| {
            StepFailure::new(WorkflowErrorCode::BindingMismatch, error.to_string())
        })?;
        let hash = norito::core::classify_decode_attempt(|| transaction.try_hash_as_entrypoint())
            .map(Hash::from)
            .map_err(|error| {
                let code = match error.kind() {
                    norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
                        WorkflowErrorCode::LocalResourceUnavailable
                    }
                    norito::core::DecodeAttemptErrorKind::Invalid => {
                        WorkflowErrorCode::NonCanonicalEncoding
                    }
                };
                StepFailure::new(code, error.to_string())
            })?;
        if hash.as_ref() != &identity.signed_transaction_hash
            || hash.as_ref() != &identity.entrypoint_hash
        {
            return Err(StepFailure::new(
                WorkflowErrorCode::BindingMismatch,
                "AMX signed bytes differ from journal transaction identity",
            ));
        }
        Ok(())
    }
    async fn proof(&self, height: u64) -> Result<SumeragiFinalityProof> {
        self.reads.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| remaining.checked_sub(1))
            .map_err(|_| eyre!("AMX destination proof-read budget exhausted; retained verifier remains resumable"))?;
        let proof = self
            .source
            .proof(NonZeroU64::new(height).ok_or_else(|| eyre!("zero AMX destination locator"))?)
            .await?;
        if proof.height() != height {
            return Err(eyre!("AMX destination proof differs from requested height"));
        }
        Ok(proof)
    }
    async fn verified_block(&self, height: u64) -> Result<VerifiedSumeragiBlock> {
        if height < 2 {
            return Err(eyre!("AMX carrier must select a non-genesis block"));
        }
        loop {
            let next = locked(&self.verifier)?
                .authenticated_height()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| eyre!("AMX destination height overflow"))?;
            if next > height {
                let proof = self.proof(height).await?;
                return Ok(locked(&self.verifier)?.verify_retained_decision(&proof)?);
            }
            let proof = self.proof(next).await?;
            let block = locked(&self.verifier)?.verify(&proof)?;
            if next == height {
                return Ok(block);
            }
        }
    }
    async fn outcome(&self, identity: &TransactionIdentityV1) -> Result<CommittedOutcome> {
        let hash =
            HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash));
        let height = match self.source.locate(hash).await? {
            // Exact canonical HTTP absence permits only identical-byte retransmission. It
            // cannot close this identity or authorize a fresh signature.
            Location::Absent => return Ok(CommittedOutcome::ExactAbsence),
            Location::Observed(None) => return Ok(CommittedOutcome::ObservedNotFinal),
            Location::Observed(Some(height)) => height,
        };
        let verified = self.verified_block(height).await?;
        let block = verified.block();
        let index = block
            .network_entrypoints()
            .enumerate()
            .find_map(|(index, entry)| {
                let TransactionEntrypoint::External(transaction) = entry else {
                    return None;
                };
                (transaction.hash() == hash
                    && Hash::from(transaction.hash_as_entrypoint()).as_ref()
                        == &identity.entrypoint_hash)
                    .then_some(index as u32)
            })
            .ok_or_else(|| eyre!("AMX destination block lacks the exact signed input"))?;
        let TransactionEntrypoint::External(transaction) = block
            .network_entrypoint_at(index as usize)
            .ok_or_else(|| eyre!("AMX carrier missing"))?
        else {
            return Err(eyre!("AMX carrier is not externally signed"));
        };
        if !cfg!(all(test, sumeragi_daemon_mutation = "HC266")) {
            self.check_payload(transaction.payload())?;
        }
        let evidence = evidence(block, index)?;
        verified.verify_transaction_execution(&self.network, &evidence)?;
        if evidence.result().is_ok() {
            Ok(CommittedOutcome::Applied {
                block_height: Some(height),
            })
        } else {
            Ok(CommittedOutcome::Rejected {
                detail: "authenticated execution rejected this exact AMX carrier".into(),
            })
        }
    }
}

pub(super) struct RelayAccount {
    pub(super) account: Arc<dyn WorkflowAccount>,
    pub(super) ledger: Arc<RelayLedger>,
}
impl WorkflowAccount for RelayAccount {
    fn binding(&self) -> WorkflowBindingV1 {
        self.account.binding()
    }
    fn sign<'a>(
        &'a self,
        unsigned_payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let payload: TransactionPayload = norito::core::classify_decode_attempt(|| {
                norito::decode_canonical(unsigned_payload)
            })
            .map_err(|error| {
                let code = match error.kind() {
                    norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
                        WorkflowErrorCode::LocalResourceUnavailable
                    }
                    norito::core::DecodeAttemptErrorKind::Invalid => {
                        WorkflowErrorCode::NonCanonicalEncoding
                    }
                };
                StepFailure::new(code, error.to_string())
            })?;
            self.ledger
                .check_authorized_payload(&payload)
                .map_err(|error| {
                    StepFailure::new(WorkflowErrorCode::BindingMismatch, error.to_string())
                })?;
            self.account.sign(unsigned_payload).await
        })
    }
    fn identify(&self, signed_transaction: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        self.account.identify(signed_transaction)
    }
}

// A transport response cannot prove the transaction was never admitted anywhere.
fn conservative_dispatch(outcome: DispatchOutcome) -> DispatchOutcome {
    match outcome {
        DispatchOutcome::Refused { detail } | DispatchOutcome::NotAdmitted { detail, .. } => {
            DispatchOutcome::Ambiguous { detail }
        }
        other => other,
    }
}
impl WorkflowLedger for RelayLedger {
    fn dispatch<'a>(
        &'a self,
        bytes: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            if let Err(error) = self.check_signed(bytes, identity) {
                return DispatchOutcome::NotAdmitted {
                    code: error.code,
                    detail: error.detail,
                };
            }
            conservative_dispatch(self.dispatch.dispatch(bytes, identity).await)
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async move {
            self.outcome(identity)
                .await
                .unwrap_or_else(|error| CommittedOutcome::ReadFailed {
                    detail: error.to_string(),
                })
        })
    }
}

pub(super) fn instruction_digest(instruction: &InstructionBox) -> Result<Hash> {
    let mut cause = None;
    let hash = Hash::new_from_writer(|writer| {
        norito::core::write_canonical_to_writer(instruction, writer).map_err(|error| {
            cause = Some(error);
            std::io::Error::from(std::io::ErrorKind::InvalidData)
        })
    });
    if let Some(cause) = cause {
        return Err(cause.into());
    }
    Ok(hash?)
}

fn evidence(block: &SignedBlock, index: u32) -> Result<CommittedTransaction> {
    let entrypoint = block
        .network_entrypoint_at(index as usize)
        .ok_or_else(|| eyre!("AMX carrier input missing"))?
        .clone();
    let (output_index, _) = block
        .network_output_at(index)
        .ok_or_else(|| eyre!("AMX carrier execution missing"))?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or_else(|| eyre!("AMX output missing"))?
        .clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(index)
            .ok_or_else(|| eyre!("AMX input witness missing"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or_else(|| eyre!("AMX output witness missing"))?,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::workflow::WorkflowErrorCode;

    #[test]
    fn transport_refusal_cannot_close_an_amx_identity() {
        for outcome in [
            DispatchOutcome::Refused {
                detail: "rejected".into(),
            },
            DispatchOutcome::NotAdmitted {
                code: WorkflowErrorCode::LocalResourceUnavailable,
                detail: "busy".into(),
            },
        ] {
            assert!(matches!(
                conservative_dispatch(outcome),
                DispatchOutcome::Ambiguous { .. }
            ));
        }
        assert_eq!(
            conservative_dispatch(DispatchOutcome::Accepted),
            DispatchOutcome::Accepted
        );
        assert_eq!(
            conservative_dispatch(DispatchOutcome::AlreadyKnown),
            DispatchOutcome::AlreadyKnown
        );
    }
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod proof_tests;

#[cfg(test)]
#[path = "retry_tests.rs"]
mod retry_tests;
