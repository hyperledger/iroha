use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, visit_mut::VisitMut, Ident, ItemStruct, Type};

use crate::{get_ident, impl_visitor::SelfResolver};

/// Type of accessor method derived for a structure
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Derive {
    Set,
    Get,
    GetMut,
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
                                acc.insert(Derive::Set);
                            } else if item.path.is_ident("get") {
                                acc.insert(Derive::Get);
                            } else if item.path.is_ident("get_mut") {
                                acc.insert(Derive::GetMut);
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
            Derive::Set => format!("set_{}", field_name),
            Derive::Get => format!("{}", field_name),
            Derive::GetMut => format!("{}_mut", field_name),
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
            return iroha_ffi::FfiResult::ArgIsNull;
        }
    }
}

fn gen_ffi_fn_args(struct_name: &Ident, mut field_ty: &Type, derive: Derive) -> TokenStream {
    if let Type::Path(ty) = field_ty {
        let last_seg = &ty.path.segments.last().expect_or_abort("Defined");

        if last_seg.ident == "Option" {
            field_ty = crate::impl_visitor::generic_arg_types(last_seg)[0];
        }
    }

    match derive {
        Derive::Set => {
            quote! {handle: *mut #struct_name, field: *const #field_ty}
        }
        Derive::Get => {
            quote! {handle: *const #struct_name, output: *mut *const #field_ty}
        }
        Derive::GetMut => {
            quote! {handle: *mut #struct_name, output: *mut *mut #field_ty}
        }
    }
}

fn gen_option_ptr_conversion(field_ty: &Type, derive: Derive) -> Option<TokenStream> {
    if let Type::Path(ty) = field_ty {
        if get_ident(&ty.path) == "Option" {
            return match derive {
                Derive::Set => None,
                Derive::Get => Some(quote! {
                    let method_res = match method_res {
                        Some(method_res) => method_res,
                        None => core::ptr::null(),
                    };
                }),
                Derive::GetMut => Some(quote! {
                    let method_res = match method_res {
                        Some(method_res) => method_res,
                        None => core::ptr::null_mut(),
                    };
                }),
            };
        }
    }

    None
}

fn gen_ffi_fn_body(method_name: &Ident, field_ty: &Type, derive: Derive) -> TokenStream {
    let mut null_ptr_checks = vec![gen_null_ptr_check(&parse_quote! {handle})];
    let option_ptr_conversion = gen_option_ptr_conversion(field_ty, derive);

    match derive {
        Derive::Set => {
            null_ptr_checks.push(gen_null_ptr_check(&parse_quote! {field}));

            quote! {
                #( #null_ptr_checks )*
                let handle = &mut *handle;
                let field = (&*field).clone();
                handle.#method_name(field);
                iroha_ffi::FfiResult::Ok
            }
        }
        Derive::Get => {
            null_ptr_checks.push(gen_null_ptr_check(&parse_quote! {output}));

            quote! {
                #( #null_ptr_checks )*
                let handle = &*handle;
                let method_res = handle.#method_name();
                #option_ptr_conversion
                output.write(method_res);
                iroha_ffi::FfiResult::Ok
            }
        }
        Derive::GetMut => {
            null_ptr_checks.push(gen_null_ptr_check(&parse_quote! {output}));

            quote! {
                #( #null_ptr_checks )*
                let handle = &mut *handle;
                let method_res = handle.#method_name();
                #option_ptr_conversion
                output.write(method_res);
                iroha_ffi::FfiResult::Ok
            }
        }
    }
}

fn gen_ffi_derive(struct_name: &Ident, field: &syn::Field, derive: Derive) -> syn::ItemFn {
    let field_name = field.ident.as_ref().expect_or_abort("Defined");

    let mut field_ty = field.ty.clone();
    if let Type::Path(field_ty) = &mut field_ty {
        SelfResolver::new(&parse_quote! { #struct_name }).visit_type_path_mut(field_ty);
    }

    let derive_method_name = gen_derive_method_name(field_name, derive);
    let ffi_fn_name = gen_ffi_fn_name(struct_name, &derive_method_name);
    let ffi_fn_doc = gen_ffi_docs(struct_name, &derive_method_name);
    let ffi_fn_args = gen_ffi_fn_args(struct_name, &field_ty, derive);
    let ffi_fn_body = gen_ffi_fn_body(&derive_method_name, &field_ty, derive);

    parse_quote! {
        #[doc = #ffi_fn_doc]
        #[no_mangle]
        pub unsafe extern "C" fn #ffi_fn_name(#ffi_fn_args) -> iroha_ffi::FfiResult {
            #ffi_fn_body
        }
    }
}
