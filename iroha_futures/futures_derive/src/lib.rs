//! Crate with derive macroses for futures

#![allow(clippy::expect_used, clippy::str_to_string)]

use std::iter;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, token::Comma, FnArg, Ident, ItemFn, Member, Pat,
    PatTuple, PatType, ReturnType,
};

fn pat_get_name(pat: &Pat) -> Ident {
    fn tuple_ident(tuple: &PatTuple) -> Ident {
        let ident = tuple
            .elems
            .iter()
            .map(pat_get_name)
            .map(|ident| ident.to_string())
            .collect::<Vec<_>>()
            .join("_");
        Ident::new(&ident, Span::mixed_site())
    }

    match pat {
        Pat::Ident(ident) => ident.ident.clone(),
        Pat::Struct(structure) => {
            let path = structure
                .path
                .segments
                .last()
                .expect("Structure pattern always has at least 1 segment.")
                .ident
                .to_string();
            let fields = structure.fields.iter().map(|field| match &field.member {
                Member::Named(named) => named.to_string(),
                _ => unreachable!(),
            });
            let ident = iter::once(path).chain(fields).collect::<Vec<_>>().join("_");
            Ident::new(&ident, Span::mixed_site())
        }
        Pat::TupleStruct(tuplestruct) => {
            let path = tuplestruct
                .path
                .segments
                .last()
                .expect("Structure pattern always has at least 1 segment.")
                .ident
                .to_string();
            let ident = tuple_ident(&tuplestruct.pat).to_string();
            Ident::new(&format!("{}_{}", path, ident), Span::mixed_site())
        }
        Pat::Tuple(tuple) => tuple_ident(tuple),
        _ => unreachable!(),
    }
}

fn input_name(input: &FnArg) -> TokenStream2 {
    if let FnArg::Typed(PatType { pat, .. }) = input {
        let ident = pat_get_name(&**pat);
        quote! { #ident }
    } else {
        quote! { self }
    }
}

fn impl_telemetry_future(
    ItemFn {
        attrs,
        vis,
        sig,
        block,
    }: ItemFn,
) -> TokenStream2 {
    if sig.asyncness.is_none() {
        abort!(
            sig.asyncness,
            "Function should be async for using telemetry_future"
        );
    }

    let ident = &sig.ident;
    let generics = &sig.generics;
    let input_names = sig.inputs.iter().map(input_name).collect::<Vec<_>>();

    let inputs = sig
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Typed(PatType { attrs, ty, .. }) => {
                let ident = input_name(input);
                quote! { #(#attrs)* #ident: #ty }
            }
            self_bind => quote! { #self_bind },
        })
        .collect::<Punctuated<_, Comma>>();
    let output = match &sig.output {
        ReturnType::Type(_, tp) => quote! { #tp },
        ReturnType::Default => quote! { () },
    };

    quote! {
        fn #ident #generics ( #inputs ) -> iroha_futures::TelemetryFuture<
            impl std::future::Future<Output = #output>
        > {
            #(#attrs)*
            #vis #sig
            #block

            iroha_futures::TelemetryFuture::new(#ident(#(#input_names,)*), stringify!(#ident))
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
