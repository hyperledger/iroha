//! Macros for writing smart contracts.

use proc_macro::TokenStream;

mod entrypoint;

/// Annotate the user-defined function that starts the execution of the smart contract.
///
/// Requires function to accept one argument of type `AccountId`, which represents the smart contract owner.
///
/// # Panics
///
/// - If function has a return type
///
/// # Examples
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// Using without parameters:
/// ```ignore
/// #[iroha_wasm::main]
/// fn main(owner: AccountId) {
///    todo!()
/// }
/// ```
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}
