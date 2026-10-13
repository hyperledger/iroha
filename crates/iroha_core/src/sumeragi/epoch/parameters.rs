//! Signed NPoS evidence-delay parameters read from committed State.
//!
//! Epoch authority belongs to the authenticated signed genesis and its certified
//! successors. World parameter arithmetic cannot establish a height's authority.

use crate::{execution_attempt::ExecutionAttemptError as Attempt, state::WorldReadOnly};

/// Resolve the signed on-chain delay before consensus-evidence penalties apply.
pub(crate) fn resolve_npos_slashing_delay_blocks_from_world(
    world: &impl WorldReadOnly,
) -> Result<Option<u64>, Attempt<String>> {
    Ok(world
        .sumeragi_npos_parameters()?
        .map(|params| params.slashing_delay_blocks()))
}
