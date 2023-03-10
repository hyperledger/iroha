//! Macros for writing smart contracts and validators

use proc_macro::TokenStream;

mod entrypoint;

/// Annotate the user-defined function that starts the execution of a smart contract.
///
/// # Examples
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// ```ignore
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint() {
///     // do stuff
/// }
/// ```
///
/// No parameters
///
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// Using only `authority` parameter:
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id) {
///     dbg(&format!("Trigger authority: {authority}"));
/// }
/// ```
///
/// Using both `authority` and `triggering_event` parameters:
///
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id, event: DataEvent) {
///     dbg(&format!(
///         "Trigger authority: {authority};\n\
///          Triggering event: {event:?}"
///     ));
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(_: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(item)
}
