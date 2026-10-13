//! Decision delivery from original Begin and Decision executions on one Global root.
//!
//! Heights and transaction ids select sources; they never authenticate an obligation.
//! Both original native readers and the immutable replayed participant registration remain
//! live until the funded Decision graph moves into its exact Settle instruction. Successful
//! delivery may retain a Decision before Prepare; it is not proof of participant settlement.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::{AmxInstructionAdmissionErrorV1, InstructionBox, PendingAmxInstructionV1},
    sumeragi_amx::{AllocatedAmxRecordProofV1, AmxRecordKind, AmxRecordV1},
};
use iroha_model_base::topology::DataSpaceId;

use super::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1,
    NativeAmxRelayDescriptorV1, NativeAmxRelayIntentV1, NativeAmxRelaySourceV1, amx_record_proof,
};
use crate::state::{StateReadOnly, WorldReadOnly};

/// Original native source or instruction refusal; never an acknowledgement or absence.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxDecisionRelayErrorV1 {
    /// The original execution pool could not retain the joined source jobs.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// The original Begin or Decision acquisition/authentication refused.
    #[error(transparent)]
    Proof(#[from] NativeAmxRecordProofErrorV1),
    /// The exact funded Decision graph could not enter its instruction owner.
    #[error(transparent)]
    Instruction(#[from] AmxInstructionAdmissionErrorV1),
    /// The requested obligation, participant or original source differs.
    #[error("native Decision delivery source: {0}")]
    Source(&'static str),
}

/// Bounded source progress or the sole move-only Decision delivery.
#[derive(Debug)]
pub enum NativeAmxDecisionRelayPollV1 {
    /// The same original source or proof job made progress without delivering an instruction.
    Pending,
    /// The original Decision is ready for separately authorized signing and fee funding.
    Complete(NativeAmxRelayIntentV1),
}

/// One retained Begin/Decision join, including all original backing across refusal.
///
/// The source State must come from authenticated replay. Its AMX registration is immutable:
/// handoffs change committees, never the registered network or instance. Begin proves the
/// participant set; that registration, not Begin alone, binds the destination lineage.
/// There is no constructor accepting a claimed proof, decoded intent or target network.
#[must_use = "retain the original Decision delivery job through refusal or retire it explicitly"]
pub struct NativeAmxDecisionRelayReadV1<'v, V: StateReadOnly> {
    // Both source readers remain in one admitted slot. Moving the public job does not
    // copy their large inline state, and allocation refusal precedes source acquisition.
    original: ChargedBuffer<DecisionDelivery<'v, V>>,
}

struct DecisionDelivery<'v, V: StateReadOnly> {
    instruction: Option<InstructionBox>,
    pending: Option<PendingAmxInstructionV1<'static>>,
    decision: Option<AllocatedAmxRecordProofV1>,
    begin: Option<AllocatedAmxRecordProofV1>,
    decision_read: NativeAmxRecordProofReadV1<'v, V>,
    begin_read: NativeAmxRecordProofReadV1<'v, V>,
    descriptor: Option<NativeAmxRelayDescriptorV1>,
    view: &'v V,
    budget: AllocationBudget,
    transaction: [u8; 32],
    participant: DataSpaceId,
    decision_height: u64,
    absent: bool,
    complete: bool,
    #[cfg(test)]
    instruction_probe: Option<Box<dyn FnOnce(&InstructionBox) + 'v>>,
}

/// Select the original Begin and Decision for one registered destination participant.
///
/// Source acquisition is lazy and bounded by `poll`. A missing selected record is an error,
/// not a completed delivery. Discovery and a durable outbound journal belong to the caller.
/// No later block or current unpruned transaction entry is required.
///
/// # Errors
/// Invalid height order or a source State whose authenticated root is not Global.
pub fn decision_amx_relay<V: StateReadOnly>(
    view: &V,
    begin_height: u64,
    decision_height: u64,
    transaction: [u8; 32],
    participant: DataSpaceId,
) -> Result<NativeAmxDecisionRelayReadV1<'_, V>, NativeAmxDecisionRelayErrorV1> {
    use NativeAmxDecisionRelayErrorV1 as Error;
    if begin_height < 2 || decision_height < begin_height {
        return Err(Error::Source(
            "Decision must follow its certified non-genesis Begin",
        ));
    }
    if view.native_execution_tip().map(|tip| tip.root_scope()) != Some(SumeragiRootScope::Global) {
        return Err(Error::Source(
            "Decision delivery requires the authenticated Global root",
        ));
    }
    let budget = view.prepared_contract_cache().execution_budget().clone();
    let mut original = ChargedBuffer::new(1, &budget)?;
    original.push_reserved(DecisionDelivery {
        instruction: None,
        pending: None,
        decision: None,
        begin: None,
        decision_read: amx_record_proof(
            view,
            decision_height,
            AmxRecordKind::Decision,
            transaction,
        ),
        begin_read: amx_record_proof(view, begin_height, AmxRecordKind::Begin, transaction),
        descriptor: None,
        view,
        budget,
        transaction,
        participant,
        decision_height,
        absent: false,
        complete: false,
        #[cfg(test)]
        instruction_probe: None,
    });
    Ok(NativeAmxDecisionRelayReadV1 { original })
}

impl<V: StateReadOnly> NativeAmxDecisionRelayReadV1<'_, V> {
    /// Advance one original proof stage, preserving every completed allocation on refusal.
    ///
    /// # Errors
    /// Exact original source/proof/instruction refusal. An already delivered job refuses.
    pub fn poll(&mut self) -> Result<NativeAmxDecisionRelayPollV1, NativeAmxDecisionRelayErrorV1> {
        self.original.as_mut_slice()[0].poll()
    }

    /// Complete the same selected delivery without replacing a refused source.
    ///
    /// # Errors
    /// The original typed refusal from `poll`; all retained work remains in this job.
    pub fn complete(&mut self) -> Result<NativeAmxRelayIntentV1, NativeAmxDecisionRelayErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxDecisionRelayPollV1::Pending => {}
                NativeAmxDecisionRelayPollV1::Complete(intent) => return Ok(intent),
            }
        }
    }
}

impl<V: StateReadOnly> DecisionDelivery<'_, V> {
    fn joined_descriptor(
        &self,
    ) -> Result<NativeAmxRelayDescriptorV1, NativeAmxDecisionRelayErrorV1> {
        use NativeAmxDecisionRelayErrorV1 as Error;
        let begin_source = self.begin_read.completed_original()?;
        let decision_source = self.decision_read.completed_original()?;
        let begin_header = begin_source
            .header()
            .ok_or(Error::Source("original Begin has no certified header"))?;
        let decision_header = decision_source
            .header()
            .ok_or(Error::Source("original Decision has no certified header"))?;
        if begin_source.root_scope() != SumeragiRootScope::Global
            || decision_source.root_scope() != SumeragiRootScope::Global
            || begin_header.instance != decision_header.instance
        {
            return Err(Error::Source(
                "Begin and Decision belong to different Global roots",
            ));
        }
        let begin = self
            .begin
            .as_ref()
            .ok_or(Error::Source("original Begin missing"))?;
        if !matches!(&begin.canonical().record, AmxRecordV1::Begin(value)
            if value.tx == self.transaction && value.has_participant(self.participant))
        {
            return Err(Error::Source("Begin does not authorize this participant"));
        }
        let registration = self
            .view
            .world()
            .sumeragi_amx()
            .dataspace(self.participant)
            .ok_or(Error::Source("original participant registration missing"))?;
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: *self.view.network_id(),
            dataspace_id: self.participant,
        };
        if registration.tracker.result_scope != scope.into() {
            return Err(Error::Source(
                "registered child scope differs from this participant",
            ));
        }
        Ok(NativeAmxRelayDescriptorV1 {
            source_network: *self.view.network_id(),
            source_scope: SumeragiRootScope::Global,
            source_height: self.decision_height,
            source_carrier: decision_source.block_hash(),
            source: NativeAmxRelaySourceV1::Record {
                key: iroha_data_model::sumeragi_amx::amx_record_witness_key(
                    AmxRecordKind::Decision,
                    self.transaction,
                ),
            },
            target_network: registration.tracker.current.network_id,
            target_scope: scope,
            target_instance: registration.tracker.instance,
            ready_at_ms: None,
        })
    }

    /// Advance one original proof stage, preserving every completed allocation on refusal.
    ///
    /// # Errors
    /// Exact original source/proof/instruction refusal. An already delivered job refuses.
    pub fn poll(&mut self) -> Result<NativeAmxDecisionRelayPollV1, NativeAmxDecisionRelayErrorV1> {
        use NativeAmxDecisionRelayErrorV1 as Error;
        use NativeAmxDecisionRelayPollV1 as Poll;
        if self.complete || self.absent {
            return Err(Error::Source(
                "Decision job is completed or names an absent record",
            ));
        }
        if self.begin.is_none() {
            match self.begin_read.poll()? {
                NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                NativeAmxRecordProofPollV1::Complete(proof) => {
                    self.begin = proof;
                    if self.begin.is_none() {
                        self.absent = true;
                        return Err(Error::Source("selected original Begin is absent"));
                    }
                }
            }
            return Ok(Poll::Pending);
        }
        if self.pending.is_none() && self.instruction.is_none() {
            if self.decision.is_none() {
                match self.decision_read.poll()? {
                    NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                    NativeAmxRecordProofPollV1::Complete(proof) => {
                        self.decision = proof;
                        if self.decision.is_none() {
                            self.absent = true;
                            return Err(Error::Source("selected original Decision is absent"));
                        }
                    }
                }
            }
            if !matches!(&self.decision.as_ref().expect("original Decision").canonical().record,
                AmxRecordV1::Decision(value) if value.tx == self.transaction)
            {
                return Err(Error::Source("selected Decision names another transaction"));
            }
            self.descriptor = Some(self.joined_descriptor()?);
            self.pending = Some(
                self.decision
                    .take()
                    .expect("original Decision moves once")
                    .into_settle(self.participant),
            );
        }
        if Some(self.joined_descriptor()?) != self.descriptor {
            return Err(Error::Source("original delivery binding changed"));
        }
        if self.instruction.is_none() {
            self.instruction = Some(
                self.pending
                    .as_mut()
                    .expect("original pending instruction")
                    .complete(&self.budget)?,
            );
        }
        #[cfg(test)]
        if let Some(probe) = self.instruction_probe.take() {
            probe(self.instruction.as_ref().expect("original instruction"));
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC267")))]
        if Some(self.joined_descriptor()?) != self.descriptor {
            return Err(Error::Source(
                "original delivery binding changed after admission",
            ));
        }
        self.complete = true;
        Ok(Poll::Complete(NativeAmxRelayIntentV1 {
            descriptor: self.descriptor.expect("original descriptor"),
            instruction: self
                .instruction
                .take()
                .expect("original instruction moves once"),
        }))
    }
}

#[cfg(test)]
impl<'v, V: StateReadOnly> NativeAmxDecisionRelayReadV1<'v, V> {
    pub(crate) fn probe_instruction_prepared_once(
        &mut self,
        probe: impl FnOnce(&InstructionBox) + 'v,
    ) {
        let original = &mut self.original.as_mut_slice()[0];
        assert!(
            original.instruction_probe.is_none()
                && original.instruction.is_none()
                && !original.complete
        );
        original.instruction_probe = Some(Box::new(probe));
    }
    pub(crate) fn retained_instruction(&self) -> Option<&InstructionBox> {
        self.original.as_slice()[0].instruction.as_ref()
    }
}
