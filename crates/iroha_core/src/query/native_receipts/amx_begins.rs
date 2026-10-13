//! Prepare delivery from an original successful signed Begin on the Global root.
//!
//! The original certified carrier owns the complete transaction. Pending admission shares that
//! immutable block owner and borrows its exact input; no decoded transaction replaces it.
//! Global registration binds the destination lineage. Signing, customer debit authority and
//! fees remain separate from this source-bound, physically admitted instruction.

use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::{
        AmxInstructionAdmissionErrorV1, InstructionBox, PendingAmxInstructionV1,
        sumeragi_amx::{BeginAmxV1, PrepareAmxV1},
    },
    sumeragi_amx::{
        AllocatedAmxRecordProofV1, AmxError, AmxRecordKind, AmxRecordProofV1, AmxRecordV1,
        AmxTransactionV1,
    },
    transaction::Executable,
};
use iroha_model_base::topology::DataSpaceId;

use super::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1,
    NativeAmxRelayDescriptorV1, NativeAmxRelayIntentV1, NativeAmxRelaySourceV1, amx_record_proof,
};
use crate::state::{StateReadOnly, WorldReadOnly};

/// Exact original source or admission refusal; none acknowledges a delivered Prepare.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxBeginRelayErrorV1 {
    /// Original certificate, archive or Begin proof acquisition refused.
    #[error(transparent)]
    Proof(#[from] NativeAmxRecordProofErrorV1),
    /// Original transaction validation or canonical identity computation refused.
    #[error(transparent)]
    Transaction(#[from] AmxError),
    /// Exact proof and additional Prepare fields could not enter their funded owner.
    #[error(transparent)]
    Instruction(#[from] AmxInstructionAdmissionErrorV1),
    /// The selected successful Begin or immutable destination registration differs.
    #[error("native Begin delivery source: {0}")]
    Source(&'static str),
}

/// Bounded acquisition progress or the sole move-only Prepare delivery.
#[derive(Debug)]
pub enum NativeAmxBeginRelayPollV1 {
    /// The same original job advanced without delivering an instruction.
    Pending,
    /// Source-bound Prepare ready for separately authorized signing and fee funding.
    Complete(NativeAmxRelayIntentV1),
}

/// One original Begin and its successful signed input retained across local refusal.
///
/// Only the authenticated source reader can establish authority. Scalar selectors locate the
/// original input and immutable participant registration; they never replace either owner.
#[must_use = "retain the original Begin delivery job through refusal or retire it explicitly"]
pub struct NativeAmxBeginRelayReadV1<'v, V: StateReadOnly> {
    instruction: Option<InstructionBox>,
    pending: Option<PendingAmxInstructionV1<'static>>,
    begin: Option<AllocatedAmxRecordProofV1>,
    read: NativeAmxRecordProofReadV1<'v, V>,
    descriptor: Option<NativeAmxRelayDescriptorV1>,
    input: Option<(usize, usize)>,
    view: &'v V,
    budget: AllocationBudget,
    transaction: [u8; 32],
    participant: Option<DataSpaceId>,
    height: u64,
    absent: bool,
    complete: bool,
    #[cfg(test)]
    instruction_probe: Option<Box<dyn FnOnce(&InstructionBox) + 'v>>,
}

/// Select one original successful Begin for a registered participant's Prepare.
///
/// The source State must come from authenticated replay. Original history suffices after
/// pruning and restart; no successor block, copied transaction or current AMX entry is needed.
/// The supported source is a direct `BeginAmxV1` in an ordinary signed instruction list.
/// Indirect contract/trigger emissions refuse until their original invocation input is owned;
/// neither discovery coordinates nor current World data can reconstruct their terms.
///
/// # Errors
/// Genesis selection or a source State whose authenticated root is not Global.
pub fn begin_amx_relay<V: StateReadOnly>(
    view: &V,
    height: u64,
    transaction: [u8; 32],
    participant: DataSpaceId,
) -> Result<NativeAmxBeginRelayReadV1<'_, V>, NativeAmxBeginRelayErrorV1> {
    use NativeAmxBeginRelayErrorV1 as Error;
    if height < 2 {
        return Err(Error::Source(
            "Begin requires certified non-genesis history",
        ));
    }
    if view.native_execution_tip().map(|tip| tip.root_scope()) != Some(SumeragiRootScope::Global) {
        return Err(Error::Source(
            "Begin delivery requires the authenticated Global root",
        ));
    }
    Ok(NativeAmxBeginRelayReadV1 {
        instruction: None,
        pending: None,
        begin: None,
        read: amx_record_proof(view, height, AmxRecordKind::Begin, transaction),
        descriptor: None,
        input: None,
        view,
        budget: view.prepared_contract_cache().execution_budget().clone(),
        transaction,
        participant: Some(participant),
        height,
        absent: false,
        complete: false,
        #[cfg(test)]
        instruction_probe: None,
    })
}

/// Select an existing original successful Begin for its funded Global expiry carrier.
/// Historical selection remains available after a decision so durable carrier recovery is
/// never orphaned by pending-state pruning. The service must authenticate that decision
/// before any new dispatch; this source alone does not assert the obligation is unresolved.
///
/// # Errors
/// The source is not certified non-genesis Global history.
pub fn expire_amx_relay<'v, V: StateReadOnly>(
    view: &'v V,
    height: u64,
    transaction: [u8; 32],
) -> Result<NativeAmxBeginRelayReadV1<'v, V>, NativeAmxBeginRelayErrorV1> {
    let mut read = begin_amx_relay(view, height, transaction, DataSpaceId::UNIVERSAL)?;
    read.participant = None;
    Ok(read)
}

impl<V: StateReadOnly> NativeAmxBeginRelayReadV1<'_, V> {
    fn original_begin(&self) -> Result<&AmxRecordProofV1, NativeAmxBeginRelayErrorV1> {
        self.begin
            .as_ref()
            .map(AllocatedAmxRecordProofV1::canonical)
            .or_else(|| {
                self.pending
                    .as_ref()?
                    .source()
                    .map(AllocatedAmxRecordProofV1::canonical)
            })
            .or_else(|| {
                self.instruction
                    .as_ref()?
                    .as_any()
                    .downcast_ref::<PrepareAmxV1>()
                    .map(|value| &value.begin)
                    .or_else(|| self.instruction.as_ref()?.amx_expiry_begin())
            })
            .ok_or(NativeAmxBeginRelayErrorV1::Source(
                "original Begin graph missing",
            ))
    }

    fn select_original_input(&self) -> Result<(usize, usize), NativeAmxBeginRelayErrorV1> {
        use NativeAmxBeginRelayErrorV1 as Error;
        let source = self.read.completed_original()?;
        let block = source.block();
        let mut selected = None;
        for input_index in 0..block.external_entrypoint_count() {
            let index = u32::try_from(input_index)
                .map_err(|_| Error::Source("input index exceeds native bound"))?;
            let (_, output) = block.network_output_at(index).ok_or(Error::Source(
                "original signed input has no explicit execution outcome",
            ))?;
            if output.result.as_ref().is_err() {
                continue;
            }
            let Some(signed) = block.external_signed_transaction_ref_at(input_index) else {
                continue;
            };
            let Executable::Instructions(instructions) = signed.instructions() else {
                continue;
            };
            for (instruction_index, instruction) in instructions.iter().enumerate() {
                let Some(begin) = instruction.as_any().downcast_ref::<BeginAmxV1>() else {
                    continue;
                };
                if begin.transaction.id()? == self.transaction {
                    if selected.replace((input_index, instruction_index)).is_some() {
                        return Err(Error::Source("multiple successful original Begin inputs"));
                    }
                }
            }
        }
        selected.ok_or(Error::Source(
            "selected Begin lacks its original successful signed input",
        ))
    }

    fn original_transaction(&self) -> Result<&AmxTransactionV1, NativeAmxBeginRelayErrorV1> {
        use NativeAmxBeginRelayErrorV1 as Error;
        let (input, instruction) = self
            .input
            .ok_or(Error::Source("original input not selected"))?;
        let source = self.read.completed_original()?;
        let block = source.block();
        let index =
            u32::try_from(input).map_err(|_| Error::Source("input index exceeds native bound"))?;
        let (_, output) = block
            .network_output_at(index)
            .ok_or(Error::Source("original Begin outcome missing"))?;
        if output.result.as_ref().is_err() {
            return Err(Error::Source("original Begin execution rejected"));
        }
        let signed = block
            .external_signed_transaction_ref_at(input)
            .ok_or(Error::Source("original Begin signed input missing"))?;
        let Executable::Instructions(instructions) = signed.instructions() else {
            return Err(Error::Source("original Begin instructions missing"));
        };
        let begin = instructions
            .get(instruction)
            .and_then(|value| value.as_any().downcast_ref::<BeginAmxV1>())
            .ok_or(Error::Source("original Begin instruction differs"))?;
        if begin.transaction.id()? != self.transaction {
            return Err(Error::Source("original Begin transaction differs"));
        }
        Ok(&begin.transaction)
    }

    fn joined_descriptor(&self) -> Result<NativeAmxRelayDescriptorV1, NativeAmxBeginRelayErrorV1> {
        use NativeAmxBeginRelayErrorV1 as Error;
        let source = self.read.completed_original()?;
        if source.root_scope() != SumeragiRootScope::Global || source.header().is_none() {
            return Err(Error::Source(
                "Begin is not an original certified Global execution",
            ));
        }
        let AmxRecordV1::Begin(begin) = &self.original_begin()?.record else {
            return Err(Error::Source("original record is not Begin"));
        };
        let transaction = self.original_transaction()?;
        if begin.tx != self.transaction
            || self
                .participant
                .is_some_and(|participant| !begin.has_participant(participant))
            || begin.deadline != transaction.deadline
            || begin.expires_at_ms != transaction.expires_at_ms
            || begin
                .participants
                .iter()
                .copied()
                .ne(transaction.legs.iter().map(|leg| leg.dataspace))
        {
            return Err(Error::Source(
                "Begin does not authorize the exact transaction and participant",
            ));
        }
        let Some(participant) = self.participant else {
            return Ok(NativeAmxRelayDescriptorV1 {
                source_network: *self.view.network_id(),
                source_scope: SumeragiRootScope::Global,
                source_height: self.height,
                source_carrier: source.block_hash(),
                source: NativeAmxRelaySourceV1::Record {
                    key: iroha_data_model::sumeragi_amx::amx_record_witness_key(
                        AmxRecordKind::Begin,
                        begin.tx,
                    ),
                },
                target_network: *self.view.network_id(),
                target_scope: SumeragiRootScope::Global,
                target_instance: source
                    .header()
                    .ok_or(Error::Source("original Global header missing"))?
                    .instance
                    .0,
                ready_at_ms: Some(begin.expires_at_ms),
            });
        };
        let registration = self
            .view
            .world()
            .sumeragi_amx()
            .dataspace(participant)
            .ok_or(Error::Source("original participant registration missing"))?;
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: *self.view.network_id(),
            dataspace_id: participant,
        };
        if registration.tracker.result_scope != scope.into() {
            return Err(Error::Source(
                "registered child scope differs from this participant",
            ));
        }
        Ok(NativeAmxRelayDescriptorV1 {
            source_network: *self.view.network_id(),
            source_scope: SumeragiRootScope::Global,
            source_height: self.height,
            source_carrier: source.block_hash(),
            source: NativeAmxRelaySourceV1::Record {
                key: iroha_data_model::sumeragi_amx::amx_record_witness_key(
                    AmxRecordKind::Begin,
                    self.transaction,
                ),
            },
            target_network: registration.tracker.current.network_id,
            target_scope: scope,
            target_instance: registration.tracker.instance,
            ready_at_ms: None,
        })
    }

    /// Advance the original source and funded instruction without replacing refused work.
    ///
    /// # Errors
    /// Exact acquisition, transaction, namespace or local admission refusal. Completed jobs refuse.
    pub fn poll(&mut self) -> Result<NativeAmxBeginRelayPollV1, NativeAmxBeginRelayErrorV1> {
        use NativeAmxBeginRelayErrorV1 as Error;
        use NativeAmxBeginRelayPollV1 as Poll;
        if self.complete || self.absent {
            return Err(Error::Source(
                "Begin job is completed or names an absent record",
            ));
        }
        if self.pending.is_none() && self.instruction.is_none() {
            if self.begin.is_none() {
                match self.read.poll()? {
                    NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                    NativeAmxRecordProofPollV1::Complete(proof) => {
                        self.begin = proof;
                        if self.begin.is_none() {
                            self.absent = true;
                            return Err(Error::Source("selected original Begin is absent"));
                        }
                    }
                }
            }
            if self.input.is_none() {
                self.input = Some(self.select_original_input()?);
            }
            self.descriptor = Some(self.joined_descriptor()?);
            let (input, instruction) = self
                .input
                .ok_or(Error::Source("original input not selected"))?;
            let block = self.read.completed_original()?.block().clone();
            let begin = self
                .begin
                .take()
                .ok_or(Error::Source("original Begin already moved"))?;
            self.pending = Some(match self.participant {
                Some(participant) => {
                    begin.into_prepare_from_block(participant, block, input, instruction)
                }
                None => begin.into_expire(),
            });
        }
        if Some(self.joined_descriptor()?) != self.descriptor {
            return Err(Error::Source("original delivery binding changed"));
        }
        if self.instruction.is_none() {
            self.instruction = Some(
                self.pending
                    .as_mut()
                    .ok_or(Error::Source("original pending instruction missing"))?
                    .complete(&self.budget)?,
            );
        }
        #[cfg(test)]
        if let Some(probe) = self.instruction_probe.take() {
            probe(
                self.instruction
                    .as_ref()
                    .ok_or(Error::Source("original instruction missing"))?,
            );
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC271")))]
        if Some(self.joined_descriptor()?) != self.descriptor {
            return Err(Error::Source(
                "original delivery binding changed after admission",
            ));
        }
        self.complete = true;
        Ok(Poll::Complete(NativeAmxRelayIntentV1 {
            descriptor: self
                .descriptor
                .ok_or(Error::Source("original descriptor missing"))?,
            instruction: self
                .instruction
                .take()
                .ok_or(Error::Source("original instruction already moved"))?,
        }))
    }

    /// Complete the selected delivery while retaining all work across typed refusal.
    ///
    /// # Errors
    /// The original refusal from [`Self::poll`]; nothing is acknowledged on failure.
    pub fn complete(&mut self) -> Result<NativeAmxRelayIntentV1, NativeAmxBeginRelayErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxBeginRelayPollV1::Pending => {}
                NativeAmxBeginRelayPollV1::Complete(intent) => return Ok(intent),
            }
        }
    }
}

#[cfg(test)]
impl<'v, V: StateReadOnly> NativeAmxBeginRelayReadV1<'v, V> {
    pub(crate) fn probe_instruction_prepared_once(
        &mut self,
        probe: impl FnOnce(&InstructionBox) + 'v,
    ) {
        assert!(self.instruction_probe.is_none() && self.instruction.is_none() && !self.complete);
        self.instruction_probe = Some(Box::new(probe));
    }
    pub(crate) fn retained_instruction(&self) -> Option<&InstructionBox> {
        self.instruction.as_ref()
    }
}
