//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote};

mod smartcontract;
mod trigger;

/// Use to annotate the user-defined function that starts the execution of a smart contract.
///
/// Should be used for smart contracts (inside transactions).
/// For triggers, see [`trigger_entrypoint`].
//
#[proc_macro_error]
#[proc_macro_attribute]
pub fn entrypoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    smartcontract::impl_entrypoint(attrs, item)
}

/// Use to annotate the user-defined function that starts the execution of a trigger.
///
/// Should be used for trigger smart contracts.
/// For just smart contract (i.e. for transactions) see [`entrypoint`].
#[proc_macro_error]
#[proc_macro_attribute]
pub fn trigger_entrypoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    trigger::impl_entrypoint(attrs, item)
}
