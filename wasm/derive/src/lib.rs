//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote, punctuated::Punctuated};

/// Use to annotate the user-defined function that starts the execution of a smart contract.
///
/// Should be used for smart contracts (inside transactions).
/// For triggers, see [`trigger_entrypoint`].
//
#[proc_macro_error]
#[proc_macro_attribute]
pub fn entrypoint(_: TokenStream, item: TokenStream) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        mut block,
    } = parse_macro_input!(item);

    if syn::ReturnType::Default != sig.output {
        abort!(sig.output, "Exported function must not have a return type");
    }

    let args = construct_args(&sig.inputs);
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

        #[allow(clippy::needless_pass_by_value)]
        #(#attrs)*
        #vis #sig
        #block
    }
    .into()
}

fn construct_args(
    inputs: &Punctuated<syn::FnArg, syn::token::Comma>,
) -> Punctuated<syn::Expr, syn::token::Comma> {
    let mut args = Punctuated::new();

    let mut args_iter = inputs.iter().filter_map(|input| {
        if let syn::FnArg::Typed(typed) = input {
            Some(typed)
        } else {
            None
        }
    });
    if let Some(_account_arg) = args_iter.next() {
        args.push(parse_quote! {
            ::iroha_wasm::query_authority()
        });
    }
    if let Some(_event_arg) = args_iter.next() {
        args.push(parse_quote! {{
            let top_event = ::iroha_wasm::query_triggering_event();
            ::core::convert::TryInto::try_into(top_event)
                .expect("Failed to convert top-level event to the concrete one")
        }});
    }

    args
}
