//! Crate with trigger procedural macros.

#![allow(clippy::panic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote};

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
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}
