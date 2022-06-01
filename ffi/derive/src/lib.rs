#![allow(clippy::str_to_string, missing_docs)]

use bindgen::gen_ffi_fn;
use derive::gen_fns_from_derives;
use impl_visitor::ImplDescriptor;
use proc_macro::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_macro_input, Item};

mod bindgen;
mod derive;
mod impl_visitor;

#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_bindgen(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(gen_ffi_fn);

            quote! {
                #item

                #( #ffi_fns )*
            }
        }
        Item::Struct(item) => {
            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generic structs not supported");
            }

            let ffi_fns = gen_fns_from_derives(&item);

            quote! {
                #item

                #( #ffi_fns )*
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

fn get_ident(path: &syn::Path) -> &syn::Ident {
    &path.segments.last().expect_or_abort("Defined").ident
}
