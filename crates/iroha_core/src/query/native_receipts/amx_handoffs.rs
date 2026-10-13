//! Final-epoch relay delivery from the same original authenticated native source.
//! The enclosing discovery owns this state in its original prepaid job slot.

use super::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofReadV1, NativeAmxRelayDescriptorV1,
    NativeAmxRelayIntentV1, NativeAmxRelaySourceV1,
};
use crate::state::{StateReadOnly, WorldReadOnly};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::{AmxInstructionAdmissionErrorV1, InstructionBox, PendingAmxHandoffInstructionV1},
    sumeragi_amx::{AllocatedAmxHandoffProofV1, AmxProofAllocationErrorV1},
};
use iroha_model_base::topology::DataSpaceId;

/// Original certificate-only proof or funded action refused; never an acknowledgement.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxHandoffRelayErrorV1 {
    /// Original native source or namespace verification refused.
    #[error(transparent)]
    Proof(#[from] NativeAmxRecordProofErrorV1),
    /// Exact certificate buffers or ledger could not enter the original pool.
    #[error(transparent)]
    Allocation(#[from] AmxProofAllocationErrorV1),
    /// The original funded proof could not enter its canonical registered instruction.
    #[error(transparent)]
    Instruction(#[from] AmxInstructionAdmissionErrorV1),
    /// The boundary, source role or immutable registration does not match.
    #[error("native handoff delivery source: {0}")]
    Source(&'static str),
}
use NativeAmxHandoffRelayErrorV1 as Error;

#[derive(Default)]
pub(super) struct HandoffDelivery {
    instruction: Option<InstructionBox>,
    pending: Option<PendingAmxHandoffInstructionV1>,
    descriptor: Option<NativeAmxRelayDescriptorV1>,
    delivered: bool,
}
impl HandoffDelivery {
    pub(super) fn poll<V: StateReadOnly>(
        &mut self,
        view: &V,
        read: &NativeAmxRecordProofReadV1<'_, V>,
        participant: DataSpaceId,
        budget: &AllocationBudget,
    ) -> Result<Option<NativeAmxRelayIntentV1>, Error> {
        if self.delivered {
            return Err(Error::Source(
                "handoff already delivered by this source owner",
            ));
        }
        let descriptor = joined_descriptor(view, read, participant)?;
        if self
            .descriptor
            .is_some_and(|original| original != descriptor)
        {
            return Err(Error::Source(
                "handoff lost its original destination or boundary",
            ));
        }
        if self.pending.is_none() && self.instruction.is_none() {
            let source = read.completed_original()?;
            let certificate = source
                .block()
                .commit_certificate()
                .ok_or(Error::Source("original boundary certificate missing"))?;
            let proof = AllocatedAmxHandoffProofV1::from_original_certificate(certificate, budget)?;
            self.pending = Some(match descriptor.source_scope() {
                SumeragiRootScope::Global => proof.into_global_handoff(participant),
                SumeragiRootScope::Dataspace { .. } => proof.into_participant_handoff(participant),
            });
            self.descriptor = Some(descriptor);
            return Ok(None);
        }
        if self.instruction.is_none() {
            self.instruction = Some(
                self.pending
                    .as_mut()
                    .expect("original pending handoff")
                    .complete(budget)?,
            );
            return Ok(None);
        }
        // No source graph leaves before the final original namespace, authority and route join.
        // Refusal retains the exact completed action, without rereading or reallocating it.
        if joined_descriptor(view, read, participant)? != descriptor {
            return Err(Error::Source("handoff final original source changed"));
        }
        self.delivered = true;
        Ok(Some(NativeAmxRelayIntentV1 {
            descriptor,
            instruction: self.instruction.take().expect("original complete handoff"),
        }))
    }
}

fn joined_descriptor<V: StateReadOnly>(
    view: &V,
    read: &NativeAmxRecordProofReadV1<'_, V>,
    participant: DataSpaceId,
) -> Result<NativeAmxRelayDescriptorV1, Error> {
    let original = read.completed_original()?;
    let header = original
        .header()
        .ok_or(Error::Source("handoff needs native non-genesis source"))?;
    let schedule = &original.commitment().schedule;
    let boundary = schedule.boundary.as_ref().ok_or(Error::Source(
        "original certified carrier is not an epoch boundary",
    ))?;
    // Native prefix verification has already authenticated the complete schedule.
    // These scalar joins make explicit which original handoff this descriptor names;
    // they do not replace authenticated boundary validation with shape checks.
    if header.height != boundary.height
        || header.height != schedule.current.authorization.last_height
        || header.epoch.epoch != schedule.current.authorization.epoch
        || header.epoch.epoch.checked_add(1) != Some(boundary.next.authorization.epoch)
        || boundary.next.authorization.first_height
            != header
                .height
                .checked_add(1)
                .ok_or(Error::Source("handoff height overflow"))?
        || schedule.current.network_id != *view.network_id()
        || boundary.next.network_id != *view.network_id()
    {
        return Err(Error::Source(
            "original boundary changed its source coordinates",
        ));
    }
    let (target_network, target_scope, target_instance) = match original.root_scope() {
        SumeragiRootScope::Global => {
            let registration = view
                .world()
                .sumeragi_amx()
                .dataspace(participant)
                .ok_or(Error::Source("original participant registration missing"))?;
            let scope = SumeragiRootScope::Dataspace {
                parent_network_id: *view.network_id(),
                dataspace_id: participant,
            };
            if registration.tracker.result_scope != scope.into() {
                return Err(Error::Source("original participant scope differs"));
            }
            (
                registration.tracker.current.network_id,
                scope,
                registration.tracker.instance,
            )
        }
        SumeragiRootScope::Dataspace {
            parent_network_id,
            dataspace_id,
        } => {
            let native = view
                .world()
                .sumeragi_amx_participant()
                .canonical()
                .ok_or(Error::Source("original private AMX registration missing"))?;
            let global = &native.participant.global;
            if participant != dataspace_id
                || native.participant.dataspace != dataspace_id
                || global.current.network_id != parent_network_id
                || global.result_scope != SumeragiRootScope::Global.into()
            {
                return Err(Error::Source(
                    "original private parent registration differs",
                ));
            }
            (
                parent_network_id,
                SumeragiRootScope::Global,
                global.instance,
            )
        }
    };
    Ok(NativeAmxRelayDescriptorV1 {
        source_network: *view.network_id(),
        source_scope: original.root_scope(),
        source_height: header.height,
        source_carrier: original.block_hash(),
        source: NativeAmxRelaySourceV1::EpochBoundary {
            epoch: header.epoch.epoch,
            next_epoch: boundary.next.authorization.epoch,
        },
        target_network,
        target_scope,
        target_instance,
        ready_at_ms: None,
    })
}

#[cfg(test)]
impl HandoffDelivery {
    pub(super) fn retained_proof(&self) -> Option<&AllocatedAmxHandoffProofV1> {
        self.pending.as_ref()?.source()
    }
    pub(super) fn retained_instruction(&self) -> Option<&InstructionBox> {
        self.instruction.as_ref()
    }
}
