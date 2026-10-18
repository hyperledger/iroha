//! Staged live-network handoff input from independently authenticated original finality.
//!
//! This is an operator delivery used to isolate delayed-decision retention. It is
//! not an alternate committee authority or a claim that an unfunded relay is live.

use eyre::{Result, ensure, eyre};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    NetworkId, block::consensus::SumeragiRootScope, isi::InstructionBox,
    sumeragi_amx::AllocatedAmxHandoffProofV1, sumeragi_finality::VerifiedSumeragiBlock,
};
use iroha_model_base::topology::DataSpaceId;

/// Preserve the original certificate in the existing finite AMX action owner.
pub(super) fn boundary_delivery(
    block: &VerifiedSumeragiBlock,
    expected_global: NetworkId,
    participant: DataSpaceId,
    expected_epoch: u64,
    budget: &AllocationBudget,
) -> Result<InstructionBox> {
    let schedule = &block.commitment().schedule;
    let boundary = schedule
        .boundary
        .as_ref()
        .ok_or_else(|| eyre!("selected original carrier is not an epoch boundary"))?;
    ensure!(
        block.root_scope() == SumeragiRootScope::Global
            && schedule.current.network_id == expected_global
            && boundary.next.network_id == expected_global
            && schedule.current.authorization.epoch == expected_epoch
            && boundary.next.authorization.epoch == expected_epoch.checked_add(1).unwrap()
            && block.height() == schedule.current.authorization.last_height
            && boundary.height == block.height()
            && boundary.next.authorization.first_height == block.height().checked_add(1).unwrap(),
        "handoff must advance the exact independently pinned Global history by one epoch"
    );
    let original = block
        .block()
        .commit_certificate()
        .ok_or_else(|| eyre!("verified native boundary lacks its original certificate"))?;
    let proof = AllocatedAmxHandoffProofV1::from_original_certificate(original, budget)?;
    let instruction = proof.into_global_handoff(participant).complete(budget)?;
    ensure!(instruction.amx_proof_admitted_to(budget));
    Ok(instruction)
}
