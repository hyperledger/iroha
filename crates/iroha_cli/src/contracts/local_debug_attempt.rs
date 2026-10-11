//! Keep unfinished local execution out of completed contract-debug reports.

use eyre::WrapErr as _;
use iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1;
use ivm::{IVM, VMError, host::IVMHost};

/// Run before draining host effects or building any completed debug response.
pub(super) fn run(vm: &mut IVM, host: &mut dyn IVMHost) -> eyre::Result<Result<(), VMError>> {
    completed(vm.run_with_host(host))
}

/// Keep the original typed return error, including its local VM refusal owner.
pub(super) fn decode_return(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    context: &'static str,
) -> eyre::Result<norito::json::Value> {
    iroha_core::smartcontracts::ivm::return_value::decode_entrypoint_return(vm, schema)
        .wrap_err(context)
}

pub(super) fn completed(outcome: Result<(), VMError>) -> eyre::Result<Result<(), VMError>> {
    match outcome {
        Err(error) if error.execution_deferral().is_some() => {
            // Move the original typed error, including any allocation release
            // owner, into the operational error. Rendering this CLI error is an
            // external output boundary; this does not claim funded formatting.
            Err(eyre::Report::new(error)
                .wrap_err("local contract debug execution did not complete"))
        }
        outcome => Ok(outcome),
    }
}

#[cfg(test)]
mod tests;
