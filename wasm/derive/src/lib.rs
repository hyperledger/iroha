//! Macros for writing smart contracts and validators

use proc_macro::TokenStream;

mod entrypoint;

/// Annotate the user-defined function that starts the execution of a smart contract.
///
/// # Attributes
///
/// This macro can have an attribute describing main(i.e. entrypoint) function parameters.
///
/// The syntax is:
/// `#[iroha_wasm::main(params = "[<type>,*]")]`, where `<type>` is one of:
/// - `authority` is an account id of the smart contract authority
/// - `triggering_event` is an event that triggers the execution of the smart contract
///
/// None, one or both parameters in any order can be specified.
/// Parameters will be passed to the main(i.e. entrypoint) function in the order they are specified.
///
/// ## Authority
///
/// A function parameter type corresponding to the `authority` should have
/// `iroha_wasm::data_model::prelude::AccountId` type.
///
/// ## Triggering event
///
/// A function parameter type corresponding to the `triggering_event` should have
/// type implementing `TryFrom<iroha_data_model::prelude::Event>`.
///
/// So any subtype of `Event` can be specified, i.e. `TimeEvent` or `DataEvent`.
/// For details see `iroha_wasm::data_model::prelude::Event`.
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
/// #[iroha_wasm::main]
/// fn main() {
///     // do stuff
/// }
/// ```
///
/// Using only `authority` parameter:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::main(params = "[authority]")]
/// fn main(authority: AccountId) {
///     dbg(&format!("Trigger authority: {authority}"));
/// }
/// ```
///
/// Using both `authority` and `triggering_event` parameters:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::main(params = "[authority, triggering_event]")]
/// fn main(authority: AccountId, event: DataEvent) {
///     dbg(&format!(
///         "Trigger authority: {authority};\n\
///          Triggering event: {event:?}"
///     ));
/// }
/// ```
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}
