//! Crate with derive macroses for futures

#![allow(clippy::expect_used, clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, Generics, ItemFn, ReturnType, Signature};

fn impl_telemetry_future(
    ItemFn {
        attrs,
        vis,
        sig,
        block,
    }: ItemFn,
) -> TokenStream2 {
    let Signature {
        asyncness,
        ident,
        generics: Generics {
            params,
            where_clause,
            ..
        },
        inputs,
        output,
        ..
    } = sig;

    if asyncness.is_none() {
        abort!(
            asyncness,
            "Function should be async for using telemetry_future"
        );
    }

    let output = match &output {
        ReturnType::Type(_, tp) => quote! { #tp },
        ReturnType::Default => quote! { () },
    };

    quote! {
        #(#attrs)*
        #vis async fn #ident < #params > ( #inputs ) -> #output
        #where_clause
        {
            let __future_name = concat!(module_path!(), "::", stringify!(#ident));
            iroha_futures::TelemetryFuture::new(async #block, __future_name).await
        }
    }
}

/// Macro for wrapping future for getting telemetry info about poll times and numbers
#[proc_macro_error]
#[proc_macro_attribute]
pub fn telemetry_future(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    if cfg!(feature = "telemetry") {
        impl_telemetry_future(input)
    } else {
        quote! { #input }
    }
    .into()
}
