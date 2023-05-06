//! Macro for writing smart contract entrypoint

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, punctuated::Punctuated};

mod kw {
    pub mod param_types {
        syn::custom_keyword!(authority);
        syn::custom_keyword!(triggering_event);
    }
}

/// Enum representing possible attributes for [`entrypoint`] macro
enum Attr {
    /// List of parameters
    Params(iroha_derive_primitives::params::ParamsAttr<ParamType>),
    /// Empty attribute. Used when attribute input is empty
    Empty,
}

impl syn::parse::Parse for Attr {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Attr::Empty);
        }

        Ok(Attr::Params(input.parse()?))
    }
}

/// Type of smart contract entrypoint function parameter.
///
/// *Type* here means not just *Rust* type but also a purpose of a parameter.
/// So that it uses [`Authority`](ParamType::Authority) instead of [`AccountId`].
enum ParamType {
    Authority,
    TriggeringEvent,
}

impl syn::parse::Parse for ParamType {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        use kw::param_types::*;

        iroha_derive_primitives::parse_keywords!(input,
            authority => ParamType::Authority,
            triggering_event => ParamType::TriggeringEvent,
        )
    }
}

impl iroha_derive_primitives::params::ConstructArg for ParamType {
    fn construct_arg(&self) -> syn::Expr {
        match self {
            ParamType::Authority => {
                parse_quote! {
                    ::iroha_wasm::query_authority()
                }
            }
            ParamType::TriggeringEvent => {
                parse_quote! {{
                    use ::iroha_wasm::debug::DebugExpectExt as _;

                    let top_event = ::iroha_wasm::query_triggering_event();
                    ::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                        ::core::convert::TryInto::try_into(top_event),
                        "Failed to convert top-level event to the concrete one"
                    )
                }}
            }
        }
    }
}

/// [`entrypoint`](crate::entrypoint()) macro implementation
pub fn impl_entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    assert!(
        syn::ReturnType::Default == sig.output,
        "Exported function must not have a return type"
    );

    let args = match syn::parse_macro_input!(attr as Attr) {
        Attr::Params(params_attr) => params_attr.construct_args(),
        Attr::Empty => Punctuated::new(),
    };
    let fn_name = &sig.ident;

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_wasm::{debug::DebugExpectExt as _, ExecuteOnHost as _};
        ),
    );

    quote! {
        /// Smart contract entrypoint
        #[no_mangle]
        #[doc(hidden)]
        unsafe extern "C" fn _iroha_wasm_main() {
            #fn_name(#args)
        }

        // NOTE: Host objects are allways passed by value to wasm
        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}
