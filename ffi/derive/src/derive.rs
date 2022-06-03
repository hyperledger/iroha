use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, ItemStruct};

use crate::arg::Arg;

/// Type of accessor method derived for a structure
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Derive {
    Setter,
    Getter,
    MutGetter,
}

/// Generate FFI function equivalents of derived methods
pub fn gen_fns_from_derives(item: &ItemStruct) -> Vec<syn::ItemFn> {
    let struct_derives = parse_derives(&item.attrs).unwrap_or_default();

    let mut ffi_derives = Vec::new();
    match &item.fields {
        syn::Fields::Named(syn::FieldsNamed { named, .. }) => named.iter().for_each(|field| {
            if let Some(mut field_derives) = parse_derives(&field.attrs) {
                field_derives.extend(struct_derives.clone());

                for derive in field_derives {
                    ffi_derives.push(gen_ffi_derive(&item.ident, field, derive));
                }
            }
        }),
        syn::Fields::Unnamed(_) | syn::Fields::Unit => {
            abort!(item, "Only named structs supported")
        }
    }

    ffi_derives
}

/// Parses getset attributes to find out which methods it derives
fn parse_derives(attrs: &[syn::Attribute]) -> Option<HashSet<Derive>> {
    attrs
        .iter()
        .filter_map(|attr| {
            if let Ok(syn::Meta::List(meta_list)) = attr.parse_meta() {
                return meta_list.path.is_ident("getset").then(|| meta_list.nested);
            }

            None
        })
        .flatten()
        .try_fold(HashSet::new(), |mut acc, nested| {
            if let syn::NestedMeta::Meta(item) = nested {
                match item {
                    syn::Meta::NameValue(item) => {
                        if item.lit == parse_quote! {"pub"} {
                            if item.path.is_ident("set") {
                                acc.insert(Derive::Setter);
                            } else if item.path.is_ident("get") {
                                acc.insert(Derive::Getter);
                            } else if item.path.is_ident("get_mut") {
                                acc.insert(Derive::MutGetter);
                            }
                        }
                    }
                    syn::Meta::Path(path) => {
                        if path.is_ident("skip") {
                            return None;
                        }
                    }
                    _ => abort!(item, "Unsupported getset attribute"),
                }
            }

            Some(acc)
        })
}

fn gen_derive_method_name(field_name: &Ident, derive: Derive) -> syn::Ident {
    Ident::new(
        &match derive {
            Derive::Setter => format!("set_{}", field_name),
            Derive::Getter => format!("{}", field_name),
            Derive::MutGetter => format!("{}_mut", field_name),
        },
        proc_macro2::Span::call_site(),
    )
}

// NOTE: [#docs = "some_doc"] expands to ///some_doc, therefore the leading space
fn gen_ffi_docs(struct_name: &Ident, derive_method_name: &syn::Ident) -> String {
    format!(
        " FFI function equivalent of [`{}::{}`]",
        struct_name, derive_method_name
    )
}

fn gen_ffi_fn_name(struct_name: &Ident, derive_method_name: &syn::Ident) -> syn::Ident {
    Ident::new(
        &format!("{}__{}", struct_name, derive_method_name),
        proc_macro2::Span::call_site(),
    )
}

fn gen_null_ptr_check(arg: &Ident) -> TokenStream {
    quote! {
        if #arg.is_null() {
            // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
            return iroha_ffi::FfiResult::ArgIsNull;
        }
    }
}

fn gen_ffi_fn_args(handle: &Arg, field: &Arg, derive: Derive) -> TokenStream {
    let (handle_name, handle_ffi_type) = (&handle.name, &handle.ffi_type);
    let (field_name, field_ffi_type) = (&field.name, &field.ffi_type);

    match derive {
        Derive::Setter => quote! {
            #handle_name: #handle_ffi_type, #field_name: #field_ffi_type
        },
        Derive::Getter | Derive::MutGetter => quote! {
            #handle_name: #handle_ffi_type, #field_name: *mut #field_ffi_type
        },
    }
}

fn gen_ffi_fn_body(method_name: &Ident, handle: &Arg, field: &Arg, derive: Derive) -> TokenStream {
    let handle_name = &handle.name;
    let field_name = &field.name;

    match derive {
        Derive::Setter => {
            let null_ptr_checks = vec![gen_null_ptr_check(handle_name)];

            let handle_ffi_to_src = &handle.ffi_to_src;
            let field_ffi_to_src = &field.ffi_to_src;

            quote! {
                #( #null_ptr_checks )*

                #handle_ffi_to_src
                #field_ffi_to_src

                #handle_name.#method_name(#field_name);

                iroha_ffi::FfiResult::Ok
            }
        }
        Derive::Getter | Derive::MutGetter => {
            let null_ptr_checks = vec![
                gen_null_ptr_check(handle_name),
                gen_null_ptr_check(field_name),
            ];

            let handle_ffi_to_src = &handle.ffi_to_src;
            let output_src_to_ffi = &field.src_to_ffi;

            quote! {
                #( #null_ptr_checks )*

                #handle_ffi_to_src
                let __output_ptr = #field_name;
                let #field_name = #handle_name.#method_name();
                #output_src_to_ffi

                __output_ptr.write(#field_name);
                iroha_ffi::FfiResult::Ok
            }
        }
    }
}

fn gen_ffi_derive(struct_name: &Ident, field: &syn::Field, derive: Derive) -> syn::ItemFn {
    let field_name = field.ident.as_ref().expect_or_abort("Defined");

    let self_ty = parse_quote! {#struct_name};
    let field_ty = field.ty.clone();
    let (handle, arg) = match derive {
        Derive::Setter => (
            Arg::handle(&self_ty, parse_quote! {&mut #struct_name}),
            Arg::input(&self_ty, parse_quote! {field}, field_ty),
        ),
        Derive::Getter => (
            Arg::handle(&self_ty, parse_quote! {&#struct_name}),
            Arg::output(&self_ty, parse_quote! {output}, parse_quote! {&#field_ty}),
        ),
        Derive::MutGetter => (
            Arg::handle(&self_ty, parse_quote! {&mut #struct_name}),
            Arg::output(
                &self_ty,
                parse_quote! {output},
                parse_quote! {&mut #field_ty},
            ),
        ),
    };

    let derive_method_name = gen_derive_method_name(field_name, derive);
    let ffi_fn_name = gen_ffi_fn_name(struct_name, &derive_method_name);
    let ffi_fn_doc = gen_ffi_docs(struct_name, &derive_method_name);
    let ffi_fn_args = gen_ffi_fn_args(&handle, &arg, derive);
    let ffi_fn_body = gen_ffi_fn_body(&derive_method_name, &handle, &arg, derive);

    parse_quote! {
        #[doc = #ffi_fn_doc]
        #[no_mangle]
        pub unsafe extern "C" fn #ffi_fn_name(#ffi_fn_args) -> iroha_ffi::FfiResult {
            let res = std::panic::catch_unwind(|| {
                #ffi_fn_body
            });

            match res {
                Ok(res) => res,
                Err(_) => {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    iroha_ffi::FfiResult::UnrecoverableError
                },
            }
        }
    }
}
