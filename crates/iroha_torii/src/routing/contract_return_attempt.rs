//! Preserve unfinished return collection before creating public contract responses.

use iroha_core::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred},
    smartcontracts::ivm::return_value::{EntrypointReturnDecodeError, decode_entrypoint_return},
};
use iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1;
use norito::json::Value;

/// Collect an actual return while retaining its original local retry owner.
pub(super) fn decode(
    vm: &ivm::IVM,
    schema: &EntrypointValueTypeV1,
) -> Result<Value, ExecutionAttemptError<EntrypointReturnDecodeError>> {
    decode_entrypoint_return(vm, schema).map_err(classify)
}

fn classify(
    error: EntrypointReturnDecodeError,
) -> ExecutionAttemptError<EntrypointReturnDecodeError> {
    match error {
        EntrypointReturnDecodeError::ExecutionDeferred { word_index, reason } => {
            match ExecutionDeferred::try_from_vm_error(reason) {
                Ok(owner) => ExecutionAttemptError::Deferred(owner),
                Err(reason) => ExecutionAttemptError::Rejected(
                    EntrypointReturnDecodeError::ExecutionDeferred { word_index, reason },
                ),
            }
        }
        error => ExecutionAttemptError::Rejected(error),
    }
}

#[cfg(test)]
mod tests;
