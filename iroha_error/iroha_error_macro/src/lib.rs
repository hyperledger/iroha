#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::use_self,
    clippy::implicit_return,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::enum_glob_use,
    clippy::wildcard_imports
)]
extern crate proc_macro;

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
