//! Contains various configuration related macro definitions.

#![allow(clippy::arithmetic, clippy::std_instead_of_core)]

use proc_macro::TokenStream;

pub(crate) mod documented;
pub(crate) mod proxy;
pub(crate) mod utils;
pub(crate) mod view;

/// Derive for config loading. More details in `iroha_config_base` reexport
#[proc_macro_derive(Combine)]
pub fn combine_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    proxy::impl_combine(&ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(Builder, attributes(builder))]
pub fn builder_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    proxy::impl_build(&ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(LoadFromEnv, attributes(config))]
pub fn load_from_env_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    proxy::impl_load_from_env(&ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(LoadFromDisk)]
pub fn load_from_disk_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    proxy::impl_load_from_disk(&ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(Proxy)]
pub fn proxy_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as utils::StructWithFields);
    proxy::impl_proxy(ast)
}

/// Derive for config querying and setting. More details in `iroha_config_base` reexport
#[proc_macro_derive(Documented)]
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
