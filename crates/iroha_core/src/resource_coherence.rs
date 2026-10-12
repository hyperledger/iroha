//! Complete-invocation resource policy checks before publication and during restore.

use std::num::NonZeroU32;

use iroha_data_model::parameter::system::resource_coherence::{
    SuccessorResourceCoherenceError, validate_successor_resource_limits,
};

use crate::state::WorldReadOnly;

/// A semantic policy or authenticated schedule inconsistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PolicyCoherenceError {
    /// The final candidate cannot describe its two successor heights.
    #[error("two successor heights cannot follow committed height {committed_height}")]
    HeightOverflow { committed_height: u64 },
    /// The authenticated retained schedule omits a needed successor cap.
    #[error("authenticated block parameters are missing at height {height}")]
    MissingScheduledParameters { height: u64 },
    /// A retained schedule carries a zero block cap.
    #[error("authenticated block cap is zero at height {height}")]
    ZeroScheduledBlockCap { height: u64 },
    /// Restored canonical parameters disagree with their retained lag-two cap.
    #[error(
        "restored parameter block cap {parameter_max_block_bytes} differs from authenticated cap {scheduled_max_block_bytes} at height {height}"
    )]
    RestoredBlockCapMismatch {
        height: u64,
        parameter_max_block_bytes: u32,
        scheduled_max_block_bytes: u32,
    },
    /// A complete privacy/chain candidate is incoherent at an effective height.
    #[error(transparent)]
    Effective(#[from] SuccessorResourceCoherenceError),
}

impl PolicyCoherenceError {
    /// Reject the complete invocation through its ordinary disposable-overlay path.
    pub(crate) fn into_transaction_rejection(
        self,
    ) -> iroha_data_model::transaction::error::TransactionRejectionReason {
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted(format!(
                "incoherent final resource policy: {self}"
            )),
        )
    }
}

fn scheduled_cap(
    world: &impl WorldReadOnly,
    height: u64,
) -> Result<NonZeroU32, PolicyCoherenceError> {
    let slot = world
        .consensus_schedule()
        .get(height)
        .ok_or(PolicyCoherenceError::MissingScheduledParameters { height })?;
    NonZeroU32::new(slot.params().max_block_bytes)
        .ok_or(PolicyCoherenceError::ZeroScheduledBlockCap { height })
}

/// Validate the final invocation/block candidate without mutating either policy owner.
pub(crate) fn validate_final_policy(
    world: &impl WorldReadOnly,
    committed_height: u64,
) -> Result<(), PolicyCoherenceError> {
    let parameters = world.parameters();
    let after_next_cap = parameters.sumeragi().max_block_bytes();
    let next_height = committed_height
        .checked_add(1)
        .ok_or(PolicyCoherenceError::HeightOverflow { committed_height })?;
    let next_cap = if committed_height == 1 {
        // The authenticated genesis result installs both successor parameter slots.
        after_next_cap
    } else {
        scheduled_cap(world, next_height)?
    };
    validate_successor_resource_limits(
        committed_height,
        parameters.transaction().max_tx_bytes(),
        next_cap,
        after_next_cap,
        world.privacy_consensus_policy(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Check restored original policies against both admitted successor schedule slots.
pub(crate) fn validate_restored_policy(
    world: &impl WorldReadOnly,
    committed_height: u64,
) -> Result<(), PolicyCoherenceError> {
    let parameters = world.parameters();
    let parameter_cap = parameters.sumeragi().max_block_bytes();
    let (next, after_next) = if committed_height == 0 {
        // A pre-genesis snapshot has no certified schedule. Its own full parameters
        // govern bootstrap; no local runtime settings participate in this check.
        (parameter_cap, parameter_cap)
    } else {
        let next_height = committed_height
            .checked_add(1)
            .ok_or(PolicyCoherenceError::HeightOverflow { committed_height })?;
        let after_height = next_height
            .checked_add(1)
            .ok_or(PolicyCoherenceError::HeightOverflow { committed_height })?;
        let after_cap = scheduled_cap(world, after_height)?;
        if after_cap != parameter_cap {
            return Err(PolicyCoherenceError::RestoredBlockCapMismatch {
                height: after_height,
                parameter_max_block_bytes: parameter_cap.get(),
                scheduled_max_block_bytes: after_cap.get(),
            });
        }
        (scheduled_cap(world, next_height)?, after_cap)
    };
    validate_successor_resource_limits(
        committed_height,
        parameters.transaction().max_tx_bytes(),
        next,
        after_next,
        world.privacy_consensus_policy(),
    )?;
    Ok(())
}
