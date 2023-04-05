//! Main and default Iroha instruction validator.

#![no_std]
#![no_main]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

pub mod isi;

use iroha_validator::{data_model::transaction::SignedTransaction, pass_conditions, prelude::*};

/// Apply `callback` macro for all token types from this crate.
///
/// Callback technique is used because of macro expansion order. With that technique we can
/// apply callback to token types declared in other modules.
///
/// # WARNING !!!
///
/// If you add new module with tokens don't forget to add it here!
macro_rules! map_all_crate_tokens {
    ($callback:ident) => {
        $crate::isi::account::map_tokens!($callback);
        $crate::isi::asset::map_tokens!($callback);
        $crate::isi::asset_definition::map_tokens!($callback);
        $crate::isi::domain::map_tokens!($callback);
        $crate::isi::parameter::map_tokens!($callback);
        $crate::isi::peer::map_tokens!($callback);
        $crate::isi::role::map_tokens!($callback);
        $crate::isi::trigger::map_tokens!($callback);
        $crate::isi::validator::map_tokens!($callback);
    };
}

pub(crate) use map_all_crate_tokens;

/// Validate operation.
#[cfg_attr(feature = "entrypoint", entrypoint(params = "[authority, operation]"))]
pub fn validate(
    authority: <Account as Identifiable>::Id,
    operation: NeedsValidationBox,
) -> Verdict {
    match operation {
        NeedsValidationBox::Transaction(transaction) => validate_and_execute_transaction(
            &authority,
            &transaction,
            validate_and_execute_instruction,
            validate_query,
        ),
        NeedsValidationBox::Instruction(instruction) => {
            validate_and_execute_instruction(&authority, &instruction, validate_query)
        }
        NeedsValidationBox::Query(query) => validate_query(&authority, query),
    }
}

/// Default validation of [`SignedTransaction`].
///
/// Performs execution if transaction contains [`Executable::Instructions`]
/// and does nothing if [`Executable::Wasm`].
///
/// Execution is done to properly validate dependent instructions.
pub fn validate_and_execute_transaction<I, Q>(
    authority: &<Account as Identifiable>::Id,
    transaction: &SignedTransaction,
    validate_and_execute_instruction: I,
    validate_query: Q,
) -> Verdict
where
    I: Fn(&<Account as Identifiable>::Id, &InstructionBox, Q) -> Verdict,
    Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
{
    match transaction.payload().instructions() {
        Executable::Wasm(wasm) => validate_wasm(wasm),
        Executable::Instructions(instructions) => {
            for isi in instructions {
                let verdict = validate_and_execute_instruction(authority, isi, validate_query);
                if verdict.is_deny() {
                    return verdict;
                }
            }
            pass!()
        }
    }
}

/// WASM validation is automatically done by execution on Iroha side.
/// All instructions executed by WASM will be passed as
/// [`NeedsValidationBox::Instruction`] to this validator.
///
/// That said, this function always returns [`Pass`](Verdict::Pass).
pub fn validate_wasm(_wasm: &WasmSmartContract) -> Verdict {
    pass!()
}

/// Default validation of [`InstructionBox`].
/// Fallbacks to [`DefaultValidate`] and execute instruction on success.
///
/// Execution is done to properly validate dependent instructions.
///
/// `validate_query` function used to validate queries inside instruction expressions.
pub fn validate_and_execute_instruction<Q>(
    authority: &<Account as Identifiable>::Id,
    instruction: &InstructionBox,
    validate_query: Q,
) -> Verdict
where
    Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
{
    let verdict = instruction.default_validate(authority, validate_query);
    if verdict.is_pass() {
        instruction.execute()
    }
    verdict
}

/// Default validation for [`QueryBox`].
/// Always returns [`Pass`](Verdict::Pass).
#[allow(clippy::needless_pass_by_value)]
pub fn validate_query(_authority: &<Account as Identifiable>::Id, _query: QueryBox) -> Verdict {
    pass!()
}

/// Validation trait implemented for all instructions.
///
/// Mainly used to simplify code in `iroha_default_validator` but can also accessed by custom user
/// validator to fallback to a default validation implementation.
pub trait DefaultValidate {
    /// Validate instruction and return [`Pass`](Verdict::Pass) if validation passed successfully
    /// or [`Deny`](Verdict::Deny) in other case.
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy;
}
