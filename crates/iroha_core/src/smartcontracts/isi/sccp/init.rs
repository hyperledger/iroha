//! Genesis-only `InitializeSccpV1` (`specs/sccp.md` §4.1, §4.15, §4.18). Owner: ws31.
//!
//! Uses the original signed-genesis NPoS committee, validates the one-hour epoch floor and
//! genesis-pinned staking policy, and stages generation 1, parameters, reset nonce and route
//! escrows in the same transaction. Local custody refusals prevent publication; they do not
//! produce an invalid-transaction verdict or a finality-degraded event.

use super::generation_error::SccpGenerationLocalError;
use super::{
    Error, escrow,
    generation::{self, GenerationWriteError},
    params, store,
};
use crate::state::{StateReadOnly, StateStorageAdmissionError, StateTransaction};
use iroha_data_model::{account::AccountId, isi::sccp::InitializeSccpV1};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: InitializeSccpV1 refused: {reason}").into())
}

/// Retain exact local failure custody before bridging the model-owned instruction result.
fn generation_error(error: GenerationWriteError, stx: &mut StateTransaction<'_, '_>) -> Error {
    match error {
        GenerationWriteError::Owner(original) => {
            if let Some(local) = SccpGenerationLocalError::from_owner(&original) {
                stx.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(local));
                refuse("local generation ownership did not complete")
            } else {
                refuse(original)
            }
        }
        GenerationWriteError::Storage(original) => {
            stx.arm_local_storage_refusal(StateStorageAdmissionError::World(original));
            refuse("local generation storage did not complete")
        }
        GenerationWriteError::SourceCut => {
            stx.arm_local_storage_refusal(StateStorageAdmissionError::SccpGeneration(
                SccpGenerationLocalError::Invariant("genesis generation source cut changed"),
            ));
            refuse("local generation source cut changed")
        }
    }
}

/// Initialize only from captured signed genesis, with atomic generation and escrow effects.
///
/// # Errors
/// Refuses missing/invalid native authority, repeated initialization, invalid epoch/staking
/// policy, invalid parameters or zero nonce. Original local resource errors remain armed on
/// the enclosing attempt and cannot become a consensus rejection.
pub fn execute_initialize(
    instruction: InitializeSccpV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if !state_transaction._curr_block.is_genesis() {
        return Err(refuse("valid only inside the genesis block"));
    }
    if store::parameters::get(&*state_transaction.world).is_some() {
        return Err(refuse("SCCP is already initialized"));
    }
    let source = state_transaction
        .sccp_genesis_source
        .ok_or_else(|| refuse("original signed-genesis NPoS committee capture is required"))?;
    if source.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global {
        return Err(refuse(
            "original signed genesis must select the Global root scope",
        ));
    }
    let chain = state_transaction.world.parameters.get().sumeragi();
    params::validate_epoch(
        chain.epoch_length_blocks.get(),
        chain.block_cadence_ms.get(),
    )
    .map_err(refuse)?;
    let original_epoch = &source.epoch().authorization;
    let original_blocks = original_epoch
        .last_height
        .checked_sub(original_epoch.first_height)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| refuse("signed-genesis epoch duration overflows"))?;
    params::validate_epoch(original_blocks, chain.block_cadence_ms.get()).map_err(refuse)?;
    params::validate_staking_policy(
        &*state_transaction.world,
        &instruction.parameters,
        &state_transaction.nexus().staking,
    )
    .map_err(refuse)?;
    if instruction.reset_nonce == [0; 32] {
        return Err(refuse("reset_nonce must be nonzero"));
    }
    let budget = state_transaction.execution_budget();
    let owner = generation::prepare_genesis(
        &*state_transaction.world,
        source,
        &instruction.parameters,
        *state_transaction.network_id(),
        state_transaction._curr_block.creation_time_ms,
        &budget,
    )
    .map_err(|error| generation_error(error, state_transaction))?
    .map_err(|reason| refuse(format_args!("native genesis committee: {reason:?}")))?;
    generation::install_genesis(state_transaction, owner, &budget)
        .map_err(|error| generation_error(error, state_transaction))?;
    store::parameters::set(state_transaction, Some(instruction.parameters));
    store::reset_nonce::set(state_transaction, Some(instruction.reset_nonce));
    escrow::create_route_escrows(state_transaction)
}

#[cfg(test)]
mod tests;
