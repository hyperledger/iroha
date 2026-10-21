//! Archive's hard own authorization and evidence-owner boundary (lean lineage).
//!
//! A proves the own step inline: `ArchiveLineagePending` runs the administrative
//! archive rule on the authenticated predecessor and successor, and every stage
//! constrains both openings and the statement, so no own sigma is re-verified.
//! The own receipt is hard-verified under the predecessor payment key in slot 0
//! of the merged signature leaf, whose soft slot 1 is the incoming receipt; the
//! credential and its certificate are carried by continuity. Invalid incoming
//! evidence may select the adjusted-lineage no-op branch. It never excuses a
//! malformed own receipt, a changed retained Payment or a changed statement.
//! TODO: execute all fixed owners and qualify genuine Q/A/W chains before
//! admitting an Archive key.

use iroha_plonk::frontend::Error;
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{context::ContextPlan, schedule::OperationTask};

pub mod authorization;
pub mod evidence;
pub mod incoming;
pub mod maps;
pub mod proofs;
pub mod results;
pub mod retained;
pub mod stage;

/// Maximum original Receive sigma within the canonical Credited envelope.
/// The fixed 679-byte carrier is measured by G1's envelope tests. The total
/// verifier retains every byte up to this bound, even for a wrong proof length.
pub const MAX_RECEIVE_SIGMA_RAW_BYTES: usize = 10_034 - 679;

/// Maximum original Status Omega, including its public 320-byte transcript.
/// The canonical Credited Status envelope has 2,188 fixed bytes excluding the
/// transport. This is an envelope capacity, never an admitted proof length.
pub const MAX_STATUS_OMEGA_RAW_BYTES: usize = 320 + 10_034 - 2_188;

#[cfg(test)]
mod tests;

pub(super) fn require_variant(variant: Variant) -> Result<(), Error> {
    if matches!(variant, Variant::ArchiveReceive | Variant::ArchiveStatus) {
        Ok(())
    } else {
        Err(Error::Synthesis)
    }
}

/// Index of the merged signature leaf (own receipt hard, incoming receipt soft).
/// `ArchiveReceive`'s Q0 is its incoming-only `Q_sigma`; `ArchiveStatus` has no
/// `Q_sigma`, so the leaf is its only Q.
pub(super) fn signature_q(variant: Variant) -> Result<usize, Error> {
    require_variant(variant)?;
    Ok(usize::from(variant == Variant::ArchiveReceive))
}

pub(super) fn require_task(
    plan: &ContextPlan,
    stage: u32,
    task: OperationTask,
) -> Result<(), Error> {
    require_variant(plan.operation().frame().variant())?;
    if !plan
        .operation_tasks(usize::try_from(stage).map_err(|_| Error::BoundsFailure)?)
        .is_some_and(|tasks| tasks.contains(&task))
    {
        return Err(Error::Synthesis);
    }
    Ok(())
}
