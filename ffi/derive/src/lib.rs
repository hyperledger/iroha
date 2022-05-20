#![allow(clippy::str_to_string, missing_docs)]

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_macro_input, parse_quote, visit::Visit, visit_mut::VisitMut, Item, ItemStruct};

use crate::visitor::{ImplDescriptor, SelfResolver};

mod visitor;

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
            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generic structs not supported");
            }

            let struct_name = &item.ident;
            let ffi_fns = get_ffi_getters(&item);
            let drop_fn_doc = format!(" Drop function for [`{}`]", struct_name);
            let drop_ffi_fn_name = syn::Ident::new(
                &format!("{}_drop", snake_case_ident(struct_name)),
                proc_macro2::Span::call_site(),
            );

            quote! {
                #item

                #( #ffi_fns )*

                #[doc = #drop_fn_doc]
                #[no_mangle]
                pub unsafe extern "C" fn #drop_ffi_fn_name(handle: *mut #struct_name) {
                    Box::from_raw(handle);
                }
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

/// Look for a `skip` of the attribute identified by `attr_ident`.
pub(crate) fn should_skip(attrs: &[syn::Attribute], attr_ident: &str) -> bool {
    attrs.iter().any(|attr| {
        if attr.path.is_ident(attr_ident) {
            if let Ok(path) = attr.parse_args::<syn::Path>() {
                return path.is_ident("skip");
            }
        }

        false
    })
}

fn get_ffi_getters(item: &ItemStruct) -> Vec<syn::ItemFn> {
    match &item.fields {
        syn::Fields::Unnamed(_) | syn::Fields::Unit => unreachable!("Only named structs supported"),
        syn::Fields::Named(fields) => {
            let mut ffi_fns = vec![];

            for field in &fields.named {
                if let Some(ffi_fn) = generate_ffi_getter(&item.ident, field) {
                    ffi_fns.push(ffi_fn);
                }
            }

            ffi_fns
        }
    }
}

fn generate_ffi_getter(struct_name: &syn::Ident, field: &syn::Field) -> Option<syn::ItemFn> {
    let field_name = field.ident.as_ref().expect_or_abort("Defined");

    if should_skip(&field.attrs, "getset") {
        return None;
    }

    if let syn::Type::Path(mut field_ty) = field.ty.clone() {
        SelfResolver::new(&parse_quote! { #struct_name }).visit_type_path_mut(&mut field_ty);

        let ffi_fn_name = syn::Ident::new(
            &format!("{}_{}", snake_case_ident(struct_name), field_name),
            proc_macro2::Span::call_site(),
        );

        let ffi_fn_doc = format!(
            " FFI function equivalent of [`{}::get_{}`]",
            struct_name,
            field.ident.as_ref().expect_or_abort("Defined")
        );

        return Some(parse_quote! {
            #[doc = #ffi_fn_doc]
            #[no_mangle]
            pub unsafe extern "C" fn #ffi_fn_name(handle: *const #struct_name, output: *mut *const #field_ty) -> iroha_ffi::FfiResult {
                let handle = &*handle;
                output.write(handle.#field_name() as *const _);
                iroha_ffi::FfiResult::Ok
            }
        });
    }

    None
}

fn snake_case_ident(ident: &syn::Ident) -> String {
    ident.to_string().to_snake_case()
}
