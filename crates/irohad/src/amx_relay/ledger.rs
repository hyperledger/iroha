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
    sumeragi_amx::{AmxDebitApprovalV1, VerifiedAmxDebitApprovalV1},
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
    // Untrusted scan bound only: successful effects require independently verified blocks.
    fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>>;
    fn approval<'a>(
        &'a self,
        _approval: &'a AmxDebitApprovalV1,
        _relay: &'a AccountId,
        _schema: Hash,
        _block: &'a VerifiedSumeragiBlock,
    ) -> WorkflowFuture<'a, Result<VerifiedAmxDebitApprovalV1>> {
        Box::pin(async { Err(eyre!("exact AMX debit approval proof is unavailable")) })
    }
}
struct OnlineSource {
    client: Arc<Client>,
    scope: SumeragiRootScope,
}
impl Source for OnlineSource {
    fn approval<'a>(
        &'a self,
        approval: &'a AmxDebitApprovalV1,
        relay: &'a AccountId,
        schema: Hash,
        block: &'a VerifiedSumeragiBlock,
    ) -> WorkflowFuture<'a, Result<VerifiedAmxDebitApprovalV1>> {
        Box::pin(async move {
            self.client
                .get_amx_debit_approval_state_async(approval, relay, schema, block)
                .await
        })
    }
    fn applied_height(&self) -> WorkflowFuture<'_, Result<u64>> {
        Box::pin(async move { Ok(self.client.status().get().await?.blocks) })
    }
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
        Box::pin(async move {
            self.client
                .get_sumeragi_finality_proof_async(height, self.scope)
                .await
        })
    }
}

#[derive(Default)]
struct HandoffScan {
    effect: Option<Hash>,
    next: u64,
    found: Option<u64>,
}

pub(super) struct RelayLedger {
    source: Arc<dyn Source>,
    dispatch: Arc<dyn WorkflowLedger>,
    verifier: Mutex<SumeragiFinalityVerifier>,
    network: NetworkId,
    authority: AccountId,
    fee_payment: FeePaymentIntent,
    instruction: Mutex<Option<Hash>>,
    approval: Mutex<Option<AmxDebitApprovalV1>>,
    handoff_scan: Mutex<HandoffScan>,
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
        account: &AccountClient,
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
            approval: Mutex::new(None),
            handoff_scan: Mutex::new(HandoffScan::default()),
            source: Arc::new(OnlineSource { client, scope }),
            dispatch,
            verifier: Mutex::new(verifier),
            max_reads,
            reads: AtomicUsize::new(max_reads),
        }
    }
    pub(super) fn begin_observation(
        &self,
        instruction: Hash,
        approval: Option<AmxDebitApprovalV1>,
    ) -> Result<()> {
        *locked(&self.instruction)? = Some(instruction);
        *locked(&self.approval)? = approval;
        self.reads.store(self.max_reads, Ordering::Relaxed);
        Ok(())
    }
    /// Recover an already successful handoff delivered by any authorized carrier. The
    /// retained cursor/locator only saves read work; every positive result is reverified.
    pub(super) async fn recover_handoff(&self, expected: &InstructionBox) -> Result<bool> {
        if cfg!(all(test, sumeragi_daemon_mutation = "HC331")) {
            return Ok(false);
        }
        let effect = handoff_effect(expected)?
            .ok_or_else(|| eyre!("original boundary intent does not contain a handoff"))?;
        let found = {
            let mut scan = locked(&self.handoff_scan)?;
            if scan.effect != Some(effect) {
                *scan = HandoffScan {
                    effect: Some(effect),
                    next: 2,
                    found: None,
                };
            }
            scan.found
        };
        if let Some(height) = found {
            let block = self.verified_block(height).await?;
            if successful_handoff(&block, &self.network, effect)? {
                return Ok(true);
            }
            return Err(eyre!(
                "original successful handoff locator changed its authenticated effect"
            ));
        }
        let tip = self.source.applied_height().await?;
        loop {
            let next = locked(&self.handoff_scan)?.next;
            if next > tip {
                return Ok(false);
            }
            let block = self.verified_block(next).await?;
            if successful_handoff(&block, &self.network, effect)? {
                locked(&self.handoff_scan)?.found = Some(next);
                return Ok(true);
            }
            locked(&self.handoff_scan)?.next = next
                .checked_add(1)
                .ok_or_else(|| eyre!("AMX handoff recovery height overflow"))?;
        }
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
    async fn authorize_debit(&self, payload: &TransactionPayload) -> Result<()> {
        use iroha_data_model::isi::sumeragi_amx::PrepareAmxV1;
        self.check_authorized_payload(payload)?;
        let Executable::Instructions(instructions) = payload.instructions() else {
            unreachable!("checked native payload")
        };
        if instructions[0]
            .as_any()
            .downcast_ref::<PrepareAmxV1>()
            .is_none()
        {
            return Ok(());
        }
        let approval = locked(&self.approval)?.clone().ok_or_else(|| {
            eyre!("native AMX Prepare has no independently selected debit approval")
        })?;
        // Status is only a locator. Once this route has authenticated a later cut, a
        // stale/Byzantine status reply cannot roll consent verification back to an old
        // grant. A fresh process still establishes a historical fact, not proof that
        // no later revoke exists; native execution always rechecks current permission.
        let height = self
            .source
            .applied_height()
            .await?
            .max(locked(&self.verifier)?.authenticated_height().unwrap_or(0));
        let block = self.verified_block(height).await?;
        let schema = iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|error| eyre!(error))?;
        let verified = self
            .source
            .approval(&approval, &self.authority, schema, &block)
            .await?;
        if verified.approval() != &approval
            || verified.relay() != &self.authority
            || verified.height() != block.height()
        {
            return Err(eyre!(
                "native AMX debit approval proof differs from its original intent and relay"
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
                    .then_some(index)
            })
            .ok_or_else(|| eyre!("AMX destination block lacks the exact signed input"))?;
        let TransactionEntrypoint::External(transaction) = block
            .network_entrypoint_at(index)
            .ok_or_else(|| eyre!("AMX carrier missing"))?
        else {
            return Err(eyre!("AMX carrier is not externally signed"));
        };
        if !cfg!(all(test, sumeragi_daemon_mutation = "HC266")) {
            self.check_payload(transaction.payload())?;
        }
        let proof_index = u32::try_from(index)
            .map_err(|_| eyre!("AMX carrier input index exceeds the proof format"))?;
        let evidence = evidence(block, proof_index)?;
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
            self.ledger
                .authorize_debit(&payload)
                .await
                .map_err(|error| {
                    // Failed evidence acquisition is not a monetary or authorization
                    // verdict. Keep this exact unsigned reservation available to retry.
                    StepFailure::new(
                        WorkflowErrorCode::LocalResourceUnavailable,
                        error.to_string(),
                    )
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
            let transaction = match SignedTransaction::decode_all_versioned(bytes) {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DispatchOutcome::NotAdmitted {
                        code: if error.is_local_resource_refusal() {
                            WorkflowErrorCode::LocalResourceUnavailable
                        } else {
                            WorkflowErrorCode::NonCanonicalEncoding
                        },
                        detail: error.to_string(),
                    };
                }
            };
            if let Err(error) = self.authorize_debit(transaction.payload()).await {
                return DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::LocalResourceUnavailable,
                    detail: error.to_string(),
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

// Local equality key for a verified handoff scan, never a proof or dispatch authority.
// Both expected and observed handoffs use this sole nominal frame; the borrowed
// original header and result are streamed without copying their private preimages.
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(name = "irohad::amx_relay::HandoffEffect")]
struct HandoffEffect<'a> {
    direction: u8,
    dataspace: iroha_model_base::topology::DataSpaceId,
    consensus_header: &'a [u8],
    result_preimage: &'a [u8],
}

fn handoff_effect(instruction: &InstructionBox) -> Result<Option<Hash>> {
    use iroha_data_model::isi::sumeragi_amx::{RelayAmxHandoffV1, RelayGlobalAmxHandoffV1};
    let (direction, dataspace, proof) =
        if let Some(value) = instruction.as_any().downcast_ref::<RelayAmxHandoffV1>() {
            (0u8, value.dataspace, &value.proof)
        } else if let Some(value) = instruction
            .as_any()
            .downcast_ref::<RelayGlobalAmxHandoffV1>()
        {
            (1u8, value.dataspace, &value.proof)
        } else {
            return Ok(None);
        };
    // A different valid exact-quorum QC may certify the same original boundary.
    // Both its source header and certified result remain byte-exact; destination
    // successful execution authenticates the candidate's own QC and authorization.
    let original = HandoffEffect {
        direction,
        dataspace,
        consensus_header: proof.block.consensus_header.as_slice(),
        result_preimage: proof.block.result_preimage.as_slice(),
    };
    let mut cause = None;
    let hash = Hash::new_from_writer(|writer| {
        norito::core::write_canonical_to_writer(&original, writer).map_err(|error| {
            cause = Some(error);
            std::io::Error::from(std::io::ErrorKind::InvalidData)
        })
    });
    if let Some(cause) = cause {
        return Err(cause.into());
    }
    Ok(Some(hash?))
}

fn successful_handoff(
    verified: &VerifiedSumeragiBlock,
    network: &NetworkId,
    expected: Hash,
) -> Result<bool> {
    for (index, entry) in verified.block().network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(transaction) = entry else {
            continue;
        };
        let Executable::Instructions(instructions) = transaction.instructions() else {
            continue;
        };
        let mut matches = false;
        for instruction in instructions {
            if handoff_effect(instruction)? == Some(expected) {
                matches = true;
                break;
            }
        }
        if !matches {
            continue;
        }
        let index = u32::try_from(index).map_err(|_| eyre!("handoff input index overflow"))?;
        let evidence = evidence(verified.block(), index)?;
        verified.verify_transaction_execution(network, &evidence)?;
        if evidence.result().is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
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

#[cfg(test)]
#[path = "handoff_recovery_tests.rs"]
mod handoff_recovery_tests;

#[cfg(test)]
#[path = "online_tests.rs"]
mod online_tests;

#[cfg(test)]
#[path = "handoff_effect_tests.rs"]
mod handoff_effect_tests;

#[cfg(test)]
#[path = "approval_tests.rs"]
mod approval_tests;

#[cfg(test)]
#[path = "expiry_recovery_tests.rs"]
mod expiry_recovery_tests;
