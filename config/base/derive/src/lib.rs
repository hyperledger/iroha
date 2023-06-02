//! Contains various configuration related macro definitions.

#![allow(clippy::arithmetic_side_effects, clippy::std_instead_of_core)]

use proc_macro::TokenStream;
use proc_macro_error::proc_macro_error;

pub(crate) mod documented;
pub(crate) mod proxy;
pub(crate) mod utils;
pub(crate) mod view;

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_error]
#[proc_macro_derive(Configuration, attributes(config))]
pub fn configuration_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    proxy::impl_builder(ast).into()
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(Documented, attributes(config))]
pub fn documented_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    documented::impl_documented(&ast)
}

/// Generate view for given struct and convert from type to its view.
/// More details in `iroha_config_base` reexport.
#[proc_macro]
pub fn view(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    view::impl_view(ast)
}
