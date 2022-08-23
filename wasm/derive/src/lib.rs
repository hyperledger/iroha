//! Macros for writing smart contracts

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

/// Collection of types of parameters that smart contract entrypoint function is expecting
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

/// Use to annotate the user-defined function that starts the execution of a smart contract.
///
/// # Attributes
///
/// This macro can have an attribute describing entrypoint parameters.
///
/// The syntax is:
/// `#[iroha_wasm::entrypoint(params = "[<type>,*]")]`, where `<type>` is one of:
/// - `authority` - an account id of the smart contract authority
/// - `triggering_event` - an event that triggers the execution of the smart contract
///
/// None, one or both parameters in any order can be specified.
/// Parameters will be passed to the entrypoint function in the order they are specified.
///
/// ## Authority
///
/// A real function parameter type corresponding to the `authority` should have
/// `iroha_wasm::iroha_data_model::prelude::AccountId` type.
///
/// ## Triggering event
///
/// A real function parameter type corresponding to the `triggering_event` should have
/// type implementing `TryFrom<iroha_data_model::prelude::Event>`.
///
/// So any subtype of `Event` can be specified, i.e. `TimeEvent` or `DataEvent`.
/// For details see `iroha_wasm::iroha_data_model::prelude::Event`.
///
/// If conversion will fail in runtime then an error message will be printed,
/// if `debug` feature is enabled.
///
/// # Panics
///
/// - If got unexpected syntax of attribute
/// - If function has a return type
///
/// # Examples
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// Using without parameters:
/// ```ignore
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint() {
///     // do stuff
/// }
/// ```
///
/// Using only `authority` parameter:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id) {
///     dbg(&format!("Trigger authority: {authority}"));
/// }
/// ```
///
/// Using both `authority` and `triggering_event` parameters:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority, triggering_event]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id, event: DataEvent) {
///     dbg(&format!(
///         "Trigger authority: {authority};\n\
///          Triggering event: {event:?}"
///     ));
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
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
            use iroha_wasm::Execute as _;
        ),
    );

    quote! {
        /// Smart contract entry point
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
