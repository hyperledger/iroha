//! Module with actor derive macroses

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort_call_site;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    DeriveInput, GenericParam, Generics, Ident, LitStr, Token, Type,
};

struct Result {
    _ident: Ident,
    _eq: Token![=],
    result: LitStr,
}

const RESULT: &str = "result";

// TODO: make it const generic type once it will be stabilized
fn parse_const_ident(input: ParseStream, ident: &'static str) -> syn::Result<Ident> {
    let parse_ident: Ident = input.parse()?;
    if parse_ident == ident {
        Ok(parse_ident)
    } else {
        Err(syn::Error::new_spanned(parse_ident, "Unknown ident"))
    }
}

impl Parse for Result {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _ident: parse_const_ident(input, RESULT)?,
            _eq: input.parse()?,
            result: input.parse()?,
        })
    }
}

/// Derive for message. Check other doc in `iroha_actor` reexport
#[proc_macro_derive(Message, attributes(message))]
pub fn message_derive(input: TokenStream) -> TokenStream {
    let ast = match syn::parse(input) {
        Ok(ast) => ast,
        Err(err) => {
            abort_call_site!("Failed to parse input Token Stream: {}", err)
        }
    };
    impl_message(&ast).into()
}

fn generic_ident(param: &GenericParam) -> TokenStream2 {
    match param {
        GenericParam::Type(ty) => {
            let ident = &ty.ident;
            quote! { #ident }
        }
        GenericParam::Const(constgeneric) => {
            let ident = &constgeneric.ident;
            quote! { #ident }
        }
        GenericParam::Lifetime(lifetime) => {
            let lifetime = &lifetime.lifetime;
            quote! { #lifetime }
        }
    }
}

fn impl_message(ast: &DeriveInput) -> TokenStream2 {
    let ident = &ast.ident;
    let Generics {
        params,
        where_clause,
        ..
    } = &ast.generics;
    let result_ty = ast
        .attrs
        .iter()
        .find_map(|attr| attr.parse_args::<Result>().ok())
        .map_or_else(|| "()".to_owned(), |result| result.result.value());
    let result_ty: Type = match syn::parse_str(&result_ty) {
        Ok(result_ty) => result_ty,
        Err(err) => {
            abort_call_site!("Failed to parse message result type: {}", err)
        }
    };

    let ident_params = params.iter().map(generic_ident).collect::<Vec<_>>();
    let (params, ident_params) = if params.is_empty() {
        (quote! {}, quote! {})
    } else {
        (quote! { <#params> }, quote! { <#(#ident_params,)*> })
    };

    quote! {
        impl #params iroha_actor::Message for #ident #ident_params
        #where_clause
        {
            type Result = #result_ty;
        }
    }
}
