//! Crate with derive macros for futures
use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Generics, ItemFn, ReturnType, Signature};

fn impl_telemetry_future(
    emitter: &mut Emitter,
    ItemFn {
        attrs,
        vis,
        sig,
        block,
    }: ItemFn,
) -> TokenStream {
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
        emit!(
            emitter,
            ident,
            "Only async functions can be instrumented for `telemetry_future`"
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
#[manyhow]
#[proc_macro_attribute]
pub fn telemetry_future(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    if !args.is_empty() {
        emit!(emitter, args, "Unexpected arguments");
    }

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };
    let result = if cfg!(feature = "telemetry") {
        impl_telemetry_future(&mut emitter, input)
    } else {
        quote! { #input }
    };

    emitter.finish_token_stream_with(result)
}
