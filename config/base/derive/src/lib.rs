//! Contains the `#[derive(Configurable)]` macro definition.

use proc_macro::TokenStream;
use proc_macro_error::abort_call_site;
use quote::quote;

pub(crate) mod config;
pub(crate) mod proxy;
pub(crate) mod utils;
pub(crate) mod view;

#[proc_macro_derive(Proxy)]
pub fn proxy_derive(input: TokenStream) -> TokenStream {
    let ast = match syn::parse(input) {
        Ok(ast) => ast,
        Err(err) => {
            abort_call_site!("Failed to parse input Token Stream: {}", err)
        }
    };
    proxy::impl_proxy(&ast)
}

/// Derive for config. More details in `iroha_config_base` reexport
#[proc_macro_derive(Configurable, attributes(config))]
pub fn configurable_derive(input: TokenStream) -> TokenStream {
    let ast = match syn::parse(input) {
        Ok(ast) => ast,
        Err(err) => {
            abort_call_site!("Failed to parse input Token Stream: {}", err)
        }
    };
    config::impl_configurable(&ast)
}

/// Generate view for given struct and convert from type to its view.
/// More details in `iroha_config_base` reexport.
#[proc_macro]
pub fn view(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as view::ViewInput);
    let original = view::gen_original_struct(ast.clone());
    let view = view::gen_view_struct(ast);
    let impl_from = view::gen_impl_from(&original, &view);
    // let impl_default = gen_impl_default(&original, &view);
    let impl_has_view = view::gen_impl_has_view(&original);
    let assertions = view::gen_assertions(&view);
    let out = quote! {
        #original
        #impl_has_view
        #view
        #impl_from
        // #impl_default
        #assertions
    };
    out.into()
}
