//! Crate with trigger procedural macros.

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;

mod entrypoint;

/// Annotate the user-defined function that starts the execution of the trigger.
///
/// Requires function to accept two arguments of types:
/// 1. `AccountId`, which represents the trigger owner
/// 2. `Event`, which represents the event which triggered this trigger execution
///
/// # Examples
///
/// ```ignore
/// use iroha_trigger::prelude::*;
///
/// #[main]
/// fn main(owner: AccountId, event: Event) {
///     todo!()
/// }
/// ```
#[manyhow]
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(emitter, "#[main] attribute does not accept arguments");
    }

    let Some(item) = emitter.handle(syn2::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let result = entrypoint::impl_entrypoint(&mut emitter, item);

    emitter.finish_token_stream_with(result)
}
