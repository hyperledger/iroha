//! Macros for writing smart contracts.

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;

mod entrypoint;

/// Annotate the user-defined function that starts the execution of the smart contract.
///
/// Requires function to accept two arguments of types:
/// 1. `host: Iroha` - handle to the host system (use it to execute instructions and queries)
/// 2. `context: Context` - context of the execution (authority, triggering event, etc)
///
/// # Panics
///
/// - If function has a return type
///
/// # Examples
//
/// ```ignore
/// use crate::prelude::*;
///
/// #[main]
/// fn main(host: Iroha, context: Context) {
///     todo!()
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
