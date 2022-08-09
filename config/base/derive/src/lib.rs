//! Contains various configuration related macro definitions.

use proc_macro::TokenStream;

pub(crate) mod configurable;
pub(crate) mod configuration;
pub(crate) mod utils;
pub(crate) mod view;

/// Derive for config loading. More details in `iroha_config_base` reexport
#[proc_macro_derive(Configurable, attributes(config))]
pub fn configurable_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    configurable::impl_configurable(&ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(Configuration)]
pub fn configuration_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    configuration::impl_configuration(&ast)
}

/// Generate view for given struct and convert from type to its view.
/// More details in `iroha_config_base` reexport.
#[proc_macro]
pub fn view(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    view::impl_view(ast)
}
