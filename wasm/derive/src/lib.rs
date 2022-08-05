//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote, punctuated::Punctuated};

mod kw {
    syn::custom_keyword!(params);

    pub mod param_types {
        syn::custom_keyword!(authority);
        syn::custom_keyword!(triggering_event);
    }
}

enum Attr {
    Params(ParamsAttr),
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

struct Params {
    _bracket_token: syn::token::Bracket,
    types: Punctuated<ParamType, syn::token::Comma>,
}

impl syn::parse::Parse for Params {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let content;

        Ok(Params {
            _bracket_token: syn::bracketed!(content in input),
            types: content.parse_terminated(ParamType::parse)?,
        })
    }
}

enum ParamType {
    Authority,
    TriggeringEvent,
}

impl syn::parse::Parse for ParamType {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        if let Ok(_) = input.parse::<kw::param_types::authority>() {
            Ok(ParamType::Authority)
        } else if let Ok(_) = input.parse::<kw::param_types::triggering_event>() {
            Ok(ParamType::TriggeringEvent)
        } else {
            Err(input.error("expected `authority` or `triggering_event`"))
        }
    }
}

/// Use to annotate the user-defined function that starts the execution of a smart contract.
///
/// Should be used for smart contracts (inside transactions).
/// For triggers, see [`trigger_entrypoint`].
//
#[proc_macro_error]
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    if syn::ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    let args = match syn::parse_macro_input!(attr as Attr) {
        Attr::Params(param_attr) => construct_args(&param_attr.params.types),
        Attr::Empty => Punctuated::new()
    };
    let fn_name = &sig.ident;

    block.stmts.insert(
        0,
        parse_quote!(
            use ::iroha_wasm::Execute as _;
        ),
    );

    quote! {
        // NOTE: The size of the `_len` parameters is defined by the target architecture
        // which is `wasm32-unknown-unknown` and therefore not dependent by the architecture
        // smart contract is compiled on or the architecture smart contract is run on
        /// Smart contract entry point
        ///
        /// # Safety
        ///
        /// Given pointers and lengths must comprise a valid memory slice
        #[no_mangle]
        pub unsafe extern "C" fn _iroha_trigger_main(
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
    types.iter().map(|param_type| -> syn::Expr {
        match param_type {
            ParamType::Authority => {
                parse_quote!{
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
    }).collect()
}
