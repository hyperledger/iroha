//! Original State-pool VM construction and typed optional-prepass failures.
//!
//! A dynamic prepass produces scheduling hints, not an execution verdict. Its
//! outer caller may conservatively fence an unfinished attempt; resource
//! refusal must retain its original identity until that explicit boundary.

use crate::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred},
    smartcontracts::ivm::cache::PreparedContractCache,
};

pub(super) fn vm_error(stage: &str, error: ivm::VMError) -> ExecutionAttemptError<String> {
    match ExecutionDeferred::try_from_vm_error(error) {
        Ok(reason) => ExecutionAttemptError::Deferred(reason),
        Err(error) => ExecutionAttemptError::Rejected(format!("{stage}: {error}")),
    }
}

/// Use the same original cache owner later installed into the prepass host.
/// This performs no pool wait and cannot substitute equal-looking limits.
pub(super) fn new_vm(
    cache: &PreparedContractCache,
    gas_limit: u64,
) -> Result<ivm::IVM, ExecutionAttemptError<String>> {
    ivm::IVM::try_new_with_memory_budget(gas_limit, cache.execution_budget())
        .map_err(|error| vm_error("ivm.new", error))
}

/// Raw selector preparation uses the same funded canonical artifact path as
/// later execution; no private untracked artifact copy or second cache exists.
pub(super) fn prepare(
    cache: &PreparedContractCache,
    bytecode: &[u8],
) -> Result<ivm::PreparedContract, ExecutionAttemptError<String>> {
    cache
        .get_or_prepare(ivm::contract_code_hash(bytecode), bytecode)
        .map_err(|error| vm_error("failed to prepare raw contract artifact", error))
}

#[cfg(test)]
mod tests;
