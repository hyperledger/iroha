//! Macro for writing smart contract entrypoint

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, punctuated::Punctuated};

mod kw {
    syn::custom_keyword!(params);

    pub mod param_types {
        syn::custom_keyword!(authority);
        syn::custom_keyword!(triggering_event);
    }
}

/// Enum representing possible attributes for [`entrypoint`] macro
enum Attr {
    /// List of parameters
    Params(ParamsAttr),
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

/// Attribute with expected parameters for smart contract entrypoint function
struct ParamsAttr {
    _params_kw: kw::params,
    _equal: syn::token::Eq,
    params: Params,
}

impl syn::parse::Parse for ParamsAttr {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let params_kw = input.parse()?;
        let equal = input.parse()?;
        let params_str: syn::LitStr = input.parse()?;
        let params = syn::parse_str(&params_str.value())?;
        Ok(ParamsAttr {
            _params_kw: params_kw,
            _equal: equal,
            params,
        })
    }
}

/// Collection of parameter types that the smart contract entrypoint function is expecting
struct Params {
    _bracket_token: syn::token::Bracket,
    types: Punctuated<ParamType, syn::token::Comma>,
}

impl syn::parse::Parse for Params {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let content;
        let bracket_token = syn::bracketed!(content in input);

        Ok(Params {
            _bracket_token: bracket_token,
            types: content.parse_terminated(ParamType::parse)?,
        })
    }
}

/// Type of smart contract entrypoint function parameter.
///
/// *Type* here means not just *Rust* type but also a purpose of a parameter.
/// So that it uses [`Authority`](ParamType::Authority) instead of `account::Id`.
enum ParamType {
    Authority,
    TriggeringEvent,
}

impl syn::parse::Parse for ParamType {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        if input.parse::<kw::param_types::authority>().is_ok() {
            Ok(ParamType::Authority)
        } else if input.parse::<kw::param_types::triggering_event>().is_ok() {
            Ok(ParamType::TriggeringEvent)
        } else {
            Err(input.error("expected `authority` or `triggering_event`"))
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
        Attr::Params(param_attr) => construct_args(&param_attr.params.types),
        Attr::Empty => Punctuated::new(),
    };
    let fn_name = &sig.ident;

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_wasm::Execute as _;
        ),
    );

    quote! {
        /// Smart contract entrypoint
        #[no_mangle]
        pub unsafe extern "C" fn _iroha_wasm_main(
        ) {
            #fn_name(#args)
        }

        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}

fn construct_args(
    types: &Punctuated<ParamType, syn::token::Comma>,
) -> Punctuated<syn::Expr, syn::token::Comma> {
    types
        .iter()
        .map(|param_type| -> syn::Expr {
            match param_type {
                ParamType::Authority => {
                    parse_quote! {
                        ::iroha_wasm::query_authority()
                    }
                }
                ParamType::TriggeringEvent => {
                    parse_quote! {{
                        use ::iroha_wasm::debug::DebugExpectExt as _;

                        let top_event = ::iroha_wasm::query_triggering_event();
                        ::core::convert::TryInto::try_into(top_event)
                            .dbg_expect("Failed to convert top-level event to the concrete one")
                    }}
                }
            }
        })
        .collect()
}
