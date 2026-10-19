//! Original Worker-owned partial and completed leg graphs, without result caching.
//!
//! Each direct signed occurrence has its own physical source identity. The bank
//! belongs to the same signature/source attempt and never grants State authority.
//! TODO: fund captured diagnostic Strings and extend this custody to indirect
//! invocation owners without restricting their valid execution paths.

use super::{AmxLegDecodeErrorV1, PrepareAmxV1};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_data_model::{
    block::SignedBlock,
    sumeragi_amx::{
        AmxTransferLegV1, CompletedAmxTransferLegDecodeV1, PendingAmxTransferLegDecodeV1,
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use iroha_sumeragi::availability::{AvailabilityFrame, AvailableBody, PayloadBytes};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Occurrence {
    input: usize,
    instruction: usize,
    frame: usize,
    frame_len: usize,
}
struct PendingOccurrence {
    leg: PendingAmxTransferLegDecodeV1,
    occurrence: Occurrence,
}
struct CompletedOccurrence {
    // The actual values and decoder controls retire before enclosing metadata.
    leg: CompletedAmxTransferLegDecodeV1,
    occurrence: Occurrence,
}

/// Inline owner attached to one original SignatureDecodeAttempt.
/// No unrelated State cache or equal-value deduplication participates.
pub(crate) struct NativeAmxLegPreparations {
    pending: Option<PendingOccurrence>,
    parked: Option<ChargedBuffer<Option<PendingOccurrence>>>,
    staged: Option<CompletedOccurrence>,
    completed: Option<ChargedBuffer<CompletedOccurrence>>,
    // Clones of already-funded shared owners allocate no new shell or backing.
    // Worker retains the original authenticated metadata in its signature attempt.
    payload: PayloadBytes,
    availability: AvailabilityFrame,
    pool: AllocationBudget,
    wire: usize,
    wire_len: usize,
    inputs: usize,
    input_count: usize,
    #[cfg(all(test, sumeragi_core_mutation = "HC167"))]
    original_publication: Option<u64>,
    capacity: Option<usize>,
}
impl NativeAmxLegPreparations {
    /// Bind the actual retained original graph and authenticated charged source.
    /// This constructor allocates nothing and interprets no later leg fields.
    pub(crate) fn new(
        block: &SignedBlock,
        source: &AvailableBody,
        pool: &AllocationBudget,
    ) -> Self {
        let inputs = block.external_entrypoints_slice();
        let capacity = inputs.iter().try_fold(0_usize, |sum, input| {
            let count = signed(input)
                .and_then(|tx| match tx.instructions() {
                    Executable::Instructions(instructions) => Some(
                        instructions
                            .iter()
                            .filter(|isi| isi.as_any().downcast_ref::<PrepareAmxV1>().is_some())
                            .count(),
                    ),
                    _ => None,
                })
                .unwrap_or(0);
            sum.checked_add(count)
        });
        Self {
            pending: None,
            parked: None,
            staged: None,
            completed: None,
            payload: source.payload().clone(),
            availability: source.availability().clone(),
            pool: pool.clone(),
            wire: source.payload().as_slice().as_ptr() as usize,
            wire_len: source.payload().as_slice().len(),
            inputs: inputs.as_ptr() as usize,
            input_count: inputs.len(),
            #[cfg(all(test, sumeragi_core_mutation = "HC167"))]
            original_publication: None,
            capacity,
        }
    }

    /// A same-content substituted source or foreign pool is never reusable.
    /// State authority is reacquired by the native validator on every execution attempt.
    pub(crate) fn matches_original(
        &self,
        block: &SignedBlock,
        retained_source: &AvailableBody,
        source: &AvailableBody,
        pool: &AllocationBudget,
    ) -> bool {
        let Some(payload) = self.payload.charged_source(pool) else {
            return false;
        };
        let Some(availability) = self.availability.charged_source(pool) else {
            return false;
        };
        let inputs = block.external_entrypoints_slice();
        self.pool.same_pool(pool)
            && retained_source == source
            && retained_source
                .payload()
                .charged_source(pool)
                .is_some_and(|original| std::ptr::eq(payload, original))
            && source
                .payload()
                .charged_source(pool)
                .is_some_and(|offered| std::ptr::eq(payload, offered))
            && retained_source
                .availability()
                .charged_source(pool)
                .is_some_and(|original| std::ptr::eq(availability, original))
            && source
                .availability()
                .charged_source(pool)
                .is_some_and(|offered| std::ptr::eq(availability, offered))
            && source.payload().as_slice().as_ptr() as usize == self.wire
            && source.payload().as_slice().len() == self.wire_len
            && (cfg!(all(test, sumeragi_core_mutation = "HC151"))
                || inputs.as_ptr() as usize == self.inputs)
            && inputs.len() == self.input_count
            && self
                .pending
                .as_ref()
                .is_none_or(|slot| slot.leg.belongs_to(pool))
            && self.parked.as_ref().is_none_or(|slots| {
                slots.belongs_to(pool)
                    && slots
                        .as_slice()
                        .iter()
                        .flatten()
                        .all(|slot| slot.leg.belongs_to(pool))
            })
            && self
                .staged
                .as_ref()
                .is_none_or(|slot| slot.leg.belongs_to(pool))
            && self.completed.as_ref().is_none_or(|slots| {
                slots.belongs_to(pool)
                    && slots
                        .as_slice()
                        .iter()
                        .all(|slot| slot.leg.belongs_to(pool))
            })
    }

    /// Mutant restores the erroneous binding of immutable decoded bytes to the first State cut.
    #[cfg(all(test, sumeragi_core_mutation = "HC167"))]
    pub(crate) fn matches_original_publication(&mut self, generation: u64) -> bool {
        let original = *self.original_publication.get_or_insert(generation);
        crate::state::is_stable_state_view_generation(original, generation)
    }

    fn occurrence(
        &self,
        input: &TransactionEntrypoint,
        input_index: usize,
        ordinal: usize,
        instruction: &PrepareAmxV1,
    ) -> Result<Option<Occurrence>, ()> {
        // Merged lane/indirect sources are not cached by this external-input owner.
        if input_index >= self.input_count {
            return Ok(None);
        }
        let address = self
            .inputs
            .checked_add(
                input_index
                    .checked_mul(std::mem::size_of::<TransactionEntrypoint>())
                    .ok_or(())?,
            )
            .ok_or(())?;
        if std::ptr::from_ref(input) as usize != address {
            return Err(());
        }
        let Some(signed) = signed(input) else {
            return Ok(None);
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            return Ok(None);
        };
        let original = instructions
            .get(ordinal)
            .and_then(|isi| isi.as_any().downcast_ref::<PrepareAmxV1>())
            .ok_or(())?;
        if original != instruction {
            return Err(());
        }
        let leg = original.transaction.leg(original.dataspace).ok_or(())?;
        Ok(Some(Occurrence {
            input: address,
            instruction: ordinal,
            frame: leg.payload.as_ptr() as usize,
            frame_len: leg.payload.len(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn partial_metadata_bytes(&self) -> Option<usize> {
        std::alloc::Layout::array::<Option<PendingOccurrence>>(self.capacity?)
            .ok()
            .map(|layout| layout.size())
    }

    fn park_pending(&mut self) -> Result<(), LegExecutionError<std::convert::Infallible>> {
        if self.pending.is_none() {
            return Ok(());
        }
        if self.parked.is_none() {
            let capacity = self.capacity.ok_or(LegExecutionError::Invariant)?;
            if capacity == 0 {
                return Err(LegExecutionError::Invariant);
            }
            // The actual signed-input count bounds metadata. Admission happens
            // only when a second visited occurrence needs an independent owner;
            // refusal keeps the first graph and its original controls inline.
            self.parked = Some(
                ChargedBuffer::new(capacity, &self.pool).map_err(LegExecutionError::Metadata)?,
            );
        }
        let slots = self.parked.as_mut().ok_or(LegExecutionError::Invariant)?;
        if let Some(empty) = slots.as_mut_slice().iter_mut().find(|slot| slot.is_none()) {
            *empty = self.pending.take();
            return Ok(());
        }
        if slots.as_slice().len() >= slots.capacity() {
            return Err(LegExecutionError::Invariant);
        }
        let pending = self.pending.take().ok_or(LegExecutionError::Invariant)?;
        if let Err(original) = slots.try_push(Some(pending)) {
            self.pending = original;
            return Err(LegExecutionError::Invariant);
        }
        Ok(())
    }

    fn promote(&mut self) -> Result<(), LegExecutionError<std::convert::Infallible>> {
        if self.staged.is_none() {
            return Ok(());
        }
        if self.completed.is_none() {
            let capacity = self.capacity.ok_or(LegExecutionError::Invariant)?;
            if capacity == 0 {
                return Err(LegExecutionError::Invariant);
            }
            // Admission occurs after canonical decoding and execution, never as
            // a whole-frame preview. A refusal keeps staged values + controls.
            self.completed = Some(
                ChargedBuffer::new(capacity, &self.pool).map_err(LegExecutionError::Metadata)?,
            );
        }
        let slots = self
            .completed
            .as_mut()
            .ok_or(LegExecutionError::Invariant)?;
        if slots.as_slice().len() >= slots.capacity() {
            return Err(LegExecutionError::Invariant);
        }
        let slot = self.staged.take().ok_or(LegExecutionError::Invariant)?;
        if let Err(original) = slots.try_push(slot) {
            self.staged = Some(original);
            return Err(LegExecutionError::Invariant);
        }
        Ok(())
    }
}

fn signed(input: &TransactionEntrypoint) -> Option<&SignedTransaction> {
    match input {
        TransactionEntrypoint::External(tx) => Some(tx),
        TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction()),
        TransactionEntrypoint::SealedCommitment(_) | TransactionEntrypoint::AnonymousBallot(_) => {
            None
        }
    }
}

/// Exclusive short-lived StateTransaction borrow of the actual original input.
pub(crate) struct NativeAmxLegExecution<'attempt> {
    bank: &'attempt mut NativeAmxLegPreparations,
    input: &'attempt TransactionEntrypoint,
    input_index: usize,
}
impl<'attempt> NativeAmxLegExecution<'attempt> {
    pub(crate) fn new(
        bank: &'attempt mut NativeAmxLegPreparations,
        input: &'attempt TransactionEntrypoint,
        input_index: usize,
    ) -> Self {
        Self {
            bank,
            input,
            input_index,
        }
    }

    pub(crate) fn with_leg<R, E>(
        &mut self,
        instruction: &PrepareAmxV1,
        ordinal: usize,
        budget: &AllocationBudget,
        execute: impl FnOnce(&AmxTransferLegV1) -> Result<R, E>,
    ) -> Result<R, LegExecutionError<E>> {
        if !self.bank.pool.same_pool(budget) {
            return Err(LegExecutionError::Invariant);
        }
        let occurrence = self
            .bank
            .occurrence(self.input, self.input_index, ordinal, instruction)
            .map_err(|()| LegExecutionError::Invariant)?;
        let Some(occurrence) = occurrence else {
            let frame = instruction
                .transaction
                .leg(instruction.dataspace)
                .ok_or(LegExecutionError::Invariant)?;
            let owner =
                super::decode_leg(&frame.payload, budget).map_err(LegExecutionError::Decode)?;
            return execute(owner.canonical()).map_err(LegExecutionError::Execution);
        };
        if let Some(slot) = self.bank.completed.as_ref().and_then(|slots| {
            slots
                .as_slice()
                .iter()
                .find(|slot| same_occurrence(slot.occurrence, occurrence))
        }) {
            if !slot.leg.belongs_to(budget) {
                return Err(LegExecutionError::Invariant);
            }
            return execute(slot.leg.canonical()).map_err(LegExecutionError::Execution);
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC150"))]
        if self
            .bank
            .staged
            .as_ref()
            .is_some_and(|slot| slot.occurrence == occurrence)
        {
            // Mutant retires only the completed decoder/graph before an exact retry.
            self.bank.staged = None;
        }
        if self
            .bank
            .staged
            .as_ref()
            .is_some_and(|slot| slot.occurrence != occurrence)
        {
            self.bank.promote().map_err(widen)?;
        }
        if self.bank.staged.is_none() {
            // Borrow the immutable original occurrence, never a cloned Vec or a
            // self-reference into this bank. The Model owner compares the exact
            // slice identity and full original hash on every synchronous entry.
            let original = signed(self.input)
                .and_then(|signed| match signed.instructions() {
                    Executable::Instructions(instructions) => instructions.get(ordinal),
                    _ => None,
                })
                .and_then(|isi| isi.as_any().downcast_ref::<PrepareAmxV1>())
                .and_then(|original| original.transaction.leg(original.dataspace))
                .ok_or(LegExecutionError::Invariant)?;
            let parked = self.bank.parked.as_ref().and_then(|slots| {
                slots.as_slice().iter().position(|slot| {
                    slot.as_ref()
                        .is_some_and(|slot| same_occurrence(slot.occurrence, occurrence))
                })
            });
            #[cfg(all(test, sumeragi_core_mutation = "HC223"))]
            if parked.is_some() {
                // Mutant omits only resumption of a preceding original occurrence;
                // it retains the later partial owner and all captured classifiers.
                return Err(LegExecutionError::Invariant);
            }
            if parked.is_none() {
                if self
                    .bank
                    .pending
                    .as_ref()
                    .is_some_and(|slot| slot.occurrence != occurrence)
                {
                    self.bank.park_pending().map_err(widen)?;
                }
                if self.bank.pending.is_none() {
                    let leg = super::with_leg_decode_pool(budget, |original_pool| {
                        PendingAmxTransferLegDecodeV1::new(&original.payload, original_pool)
                    });
                    self.bank.pending = Some(PendingOccurrence { leg, occurrence });
                }
            }
            let pending =
                match parked {
                    Some(index) => self.bank.parked.as_mut().and_then(|slots| {
                        slots.as_mut_slice().get_mut(index).and_then(Option::as_mut)
                    }),
                    None => self.bank.pending.as_mut(),
                }
                .ok_or(LegExecutionError::Invariant)?;
            let leg = match super::decode_retained_leg(&mut pending.leg, &original.payload, budget)
            {
                Ok(leg) => leg,
                Err(error) => {
                    #[cfg(all(test, sumeragi_core_mutation = "HC222"))]
                    {
                        // Restore only the original premature partial retirement
                        // after the unchanged canonical/refusal error.
                        match parked {
                            Some(index) => {
                                *self
                                    .bank
                                    .parked
                                    .as_mut()
                                    .and_then(|slots| slots.as_mut_slice().get_mut(index))
                                    .ok_or(LegExecutionError::Invariant)? = None
                            }
                            None => self.bank.pending = None,
                        }
                    }
                    // Invalid sources retain initialized prefix backing too.
                    // Replay enters the same canonical parser again and produces
                    // a fresh captured cause; no verdict/diagnostic is cached.
                    return Err(LegExecutionError::Decode(error));
                }
            };
            // Completion moved every graph/control allocation out. Removing this
            // now-empty destination cannot refund another occurrence's backing.
            match parked {
                Some(index) => {
                    *self
                        .bank
                        .parked
                        .as_mut()
                        .and_then(|slots| slots.as_mut_slice().get_mut(index))
                        .ok_or(LegExecutionError::Invariant)? = None
                }
                None => self.bank.pending = None,
            }
            self.bank.staged = Some(CompletedOccurrence { leg, occurrence });
        }
        let slot = self
            .bank
            .staged
            .as_ref()
            .ok_or(LegExecutionError::Invariant)?;
        if !slot.leg.belongs_to(budget) {
            return Err(LegExecutionError::Invariant);
        }
        // Current authorization, balances, proof verification, Candidate and fees
        // run on every retry. Only completed canonical materialization is reused.
        let result = execute(slot.leg.canonical()).map_err(LegExecutionError::Execution)?;
        self.bank.promote().map_err(widen)?;
        Ok(result)
    }
}

pub(crate) enum LegExecutionError<E> {
    Decode(AmxLegDecodeErrorV1),
    Metadata(ChargedBufferError),
    Invariant,
    Execution(E),
}
fn widen<E>(error: LegExecutionError<std::convert::Infallible>) -> LegExecutionError<E> {
    match error {
        LegExecutionError::Decode(error) => LegExecutionError::Decode(error),
        LegExecutionError::Metadata(error) => LegExecutionError::Metadata(error),
        LegExecutionError::Invariant => LegExecutionError::Invariant,
        LegExecutionError::Execution(never) => match never {},
    }
}

fn same_occurrence(left: Occurrence, right: Occurrence) -> bool {
    #[cfg(all(test, sumeragi_core_mutation = "HC152"))]
    {
        left.input == right.input
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC152")))]
    {
        left == right
    }
}
