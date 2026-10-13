//! SCCP's ordered reconciliation segment of the shared block-start governance clock.
//!
//! The external prefix owns the original global pass and its remaining budget. No standalone
//! SCCP budget, assumed-empty Parliament iterator, or locally generated receipt substitutes it.

use super::{keepalive::DueWorkUnavailable, parliament_iface, reconciliation_store};
use crate::state::{StateBlock, StateBlockStartError};
use iroha_data_model::block::consensus::SumeragiRootScope;

/// Run due reconciliation closes on this exact original Global block, before enactments.
/// # Errors
/// Defers an unavailable Parliament prefix or original local storage refusal. Deterministic
/// accounting inconsistencies abort the candidate; no partial close can be published.
pub(crate) fn advance_reconciliation<E: std::fmt::Debug>(state: &mut StateBlock<'_>) -> Result<(), StateBlockStartError<E>> {
    if state.sumeragi_schedule.original_root_scope() != Some(SumeragiRootScope::Global)
        || reconciliation_store::earliest_due(&state.world, state._curr_block.creation_time_ms).is_none() {
        return Ok(());
    }
    parliament_iface::with_sccp_g2a_prefix(state, |state, cursor| {
        while let Some((_, network, revision)) = reconciliation_store::earliest_due(&state.world, state._curr_block.creation_time_ms) {
            let Some(_position) = cursor.take_reconciliation_position(state)
                .map_err(StateBlockStartError::GovernanceDueUnavailable)? else { break; };
            let mut transaction = state.try_transaction().map_err(StateBlockStartError::Storage)?;
            let result = super::reconciliation::end_one(&mut transaction, network, revision);
            transaction.require_storage_admission().map_err(StateBlockStartError::Storage)?;
            match result {
                Ok(true) => transaction.apply(),
                Ok(false) => return Err(StateBlockStartError::GovernanceDueUnavailable(DueWorkUnavailable)),
                Err(error) => return Err(StateBlockStartError::Policy(error.to_string())),
            }
        }
        state.require_storage_admission().map_err(StateBlockStartError::Storage)
    })
}
