#![allow(clippy::module_name_repetitions, missing_docs)]

use proc_macro::TokenStream;
use quote::quote;

mod display;
mod error;

#[proc_macro_derive(Error, attributes(error, source))]
pub fn error_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_error(&ast)
}

fn impl_error(ast: &syn::DeriveInput) -> TokenStream {
    let display = display::impl_fmt(ast);
    let error = error::impl_source(ast);
    let result = quote! {
        #display
        #error
    };
    result.into()
}
