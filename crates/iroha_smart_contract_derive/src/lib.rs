//! Macros for writing smart contracts.

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;

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
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// Using without parameters:
/// ```ignore
/// #[iroha_smart_contract::main]
/// fn main(owner: AccountId) {
///    todo!()
/// }
/// ```
#[manyhow]
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(
            emitter,
            "Smart contract entrypoint does not accept attributes"
        );
    }

    let Some(item) = emitter.handle(syn::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let result = entrypoint::impl_entrypoint(&mut emitter, item);

    emitter.finish_token_stream_with(result)
}
