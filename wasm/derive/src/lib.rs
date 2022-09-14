//! Macros for writing smart contracts and validators

use proc_macro::TokenStream;

mod entrypoint;
mod validator;

/// Annotate the user-defined function that starts the execution of a smart contract.
///
/// # Attributes
///
/// This macro can have an attribute describing entrypoint parameters.
///
/// The syntax is:
/// `#[iroha_wasm::entrypoint(params = "[<type>,*]")]`, where `<type>` is one of:
/// - `authority` - an account id of the smart contract authority
/// - `triggering_event` - an event that triggers the execution of the smart contract
///
/// None, one or both parameters in any order can be specified.
/// Parameters will be passed to the entrypoint function in the order they are specified.
///
/// ## Authority
///
/// A real function parameter type corresponding to the `authority` should have
/// `iroha_wasm::iroha_data_model::prelude::AccountId` type.
///
/// ## Triggering event
///
/// A real function parameter type corresponding to the `triggering_event` should have
/// type implementing `TryFrom<iroha_data_model::prelude::Event>`.
///
/// So any subtype of `Event` can be specified, i.e. `TimeEvent` or `DataEvent`.
/// For details see `iroha_wasm::iroha_data_model::prelude::Event`.
///
/// If conversion will fail in runtime then an error message will be printed,
/// if `debug` feature is enabled.
///
/// # Panics
///
/// - If got unexpected syntax of attribute
/// - If function has a return type
///
/// # Examples
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// Using without parameters:
/// ```ignore
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint() {
///     // do stuff
/// }
/// ```
///
/// Using only `authority` parameter:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id) {
///     dbg(&format!("Trigger authority: {authority}"));
/// }
/// ```
///
/// Using both `authority` and `triggering_event` parameters:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority, triggering_event]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id, event: DataEvent) {
///     dbg(&format!(
///         "Trigger authority: {authority};\n\
///          Triggering event: {event:?}"
///     ));
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}

/// Annotate the user-defined function that starts the execution of a validator.
///
/// Annotated function should have one parameter of the type which implements
/// `TryFrom<NeedsPermissionBox>`.
///
/// Validators are only checking if an operation is **invalid**, not its validness.
/// A validator can either deny the operation or pass it to the next validator if there is one.
///
/// # Panics
///
/// - If the function does not have a return type
///
/// # Example
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// ```ignore
/// use iroha_wasm::validator::prelude::*;
///
/// #[entrypoint]
/// pub fn validate(_: QueryBox) -> Verdict {
///     Verdict::Deny("No queries are allowed".to_owned())
/// }
/// ```
#[proc_macro_attribute]
pub fn validator_entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    validator::impl_entrypoint(attr, item)
}
