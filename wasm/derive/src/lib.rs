//! Macros for writing smartcontracts

#![allow(clippy::str_to_string)]

use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, parse_quote};

mod smartcontract;
mod trigger;

/// Used to annotate user-defined function which starts the execution of smartcontract.
///
/// Should be used for smartcontracts i.e. inside transactions.
/// For triggers see [`trigger_entrypoint`].
//
// TODO: Should it be renamed to something like `smartcontract_entrypoint`?
#[proc_macro_error]
#[proc_macro_attribute]
pub fn entrypoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    smartcontract::impl_entrypoint(attrs, item)
}

/// Used to annotate user-defined function which starts the execution of trigger.
///
/// Should be used for trigger smartcontracts.
/// For just smartcontract (i.e. for transactions) see [`entrypoint`].
#[proc_macro_error]
#[proc_macro_attribute]
pub fn trigger_entrypoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    trigger::impl_entrypoint(attrs, item)
}

fn check_types(
    fn_args: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
    types_iter: impl Iterator<Item = &'static str>,
) {
    for (fn_arg, ty) in fn_args.iter().zip(types_iter) {
        if let syn::FnArg::Typed(pat) = fn_arg {
            check_type(&pat.ty, ty)
        } else {
            abort!(fn_arg, "Exported function must not take `self` argument");
        }
    }
}

fn check_type(ty: &syn::Type, expected_type: &str) {
    if *ty == parse_quote!(<Account as Identifiable>::Id) {
        return;
    }

    if let syn::Type::Path(path) = ty {
        let syn::Path { segments, .. } = &path.path;

        if let Some(type_name) = segments.last().map(|ty| &ty.ident) {
            if *type_name == expected_type {
                return;
            }
        }
    }

    abort!(
        ty,
        "Argument to the exported function must be of the `{}` type",
        expected_type
    )
}
