#![allow(clippy::str_to_string, missing_docs)]

use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, visit::Visit, Item};

use crate::ffi::ImplDescriptor;

mod ffi;

#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_bindgen(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let mut impl_descriptor = ImplDescriptor::new();
            impl_descriptor.visit_item_impl(&item);
            let ffi_fns = impl_descriptor.fns;

            quote! {
                #item
                #( #ffi_fns )*
            }
        }
        Item::Struct(item) => {
            use heck::ToSnakeCase;

            let struct_name = &item.ident;
            let drop_ffi_fn_name = syn::Ident::new(
                &format!("{}_drop", struct_name.to_string().to_snake_case()),
                proc_macro2::Span::call_site(),
            );

            for __attr in &item.attrs {
                // TODO: Generate from getset.
                // Also check for repr(C)?
            }
            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generic structs not supported");
            }

            quote! {
                #item

                // TODO: This fn could be made generic? Which pointer type to take if so?
                pub unsafe extern "C" fn #drop_ffi_fn_name(handle: *mut #struct_name) -> iroha_ffi::FfiResult {
                    core::mem::drop(Box::from_raw(handle));
                    iroha_ffi::FfiResult::Ok
                }
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}
