use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, ItemStruct};

use crate::{
    export::{gen_arg_ffi_to_src, gen_arg_src_to_ffi},
    impl_visitor::{Arg, InputArg, Receiver, ReturnArg},
};

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

fn gen_ffi_fn_args(handle: &Receiver, field: &impl Arg, derive: Derive) -> TokenStream {
    let (handle_name, handle_type) = (&handle.name(), handle.ffi_type_resolved());
    let (field_name, field_type) = (&field.name(), field.ffi_type_resolved());

    match derive {
        Derive::Setter => quote! {
            #handle_name: #handle_type, #field_name: #field_type,
        },
        Derive::Getter | Derive::MutGetter => quote! {
            #handle_name: #handle_type, #field_name: <#field_type as iroha_ffi::Output>::OutPtr
        },
    }
}

fn gen_ffi_fn_body(
    method_name: &Ident,
    handle_arg: &Receiver,
    field_arg: &impl Arg,
    derive: Derive,
) -> TokenStream {
    let (handle_name, into_handle) = (handle_arg.name(), gen_arg_ffi_to_src(handle_arg, false));

    match derive {
        Derive::Setter => {
            let (field_name, into_field) = (field_arg.name(), gen_arg_ffi_to_src(field_arg, false));

            quote! {{
                #into_handle
                #into_field

                #handle_name.#method_name(#field_name);
                Ok(())
            }}
        }
        Derive::Getter | Derive::MutGetter => {
            let (field_name, from_field) = (field_arg.name(), gen_arg_src_to_ffi(field_arg, true));

            quote! {{
                #into_handle

                let __out_ptr = #field_name;
                let #field_name = #handle_name.#method_name();
                #from_field
                iroha_ffi::OutPtrOf::write(__out_ptr, #field_name)?;
                Ok(())
            }}
        }
    }
}

fn gen_ffi_derive(item_name: &Ident, field: &syn::Field, derive: Derive) -> syn::ItemFn {
    let handle_name = Ident::new("__handle", proc_macro2::Span::call_site());
    let field_name = field.ident.as_ref().expect_or_abort("Defined");
    let self_ty = parse_quote! {#item_name};

    let derive_method_name = gen_derive_method_name(field_name, derive);
    let ffi_fn_name = gen_ffi_fn_name(item_name, &derive_method_name);
    let ffi_fn_doc = gen_ffi_docs(item_name, &derive_method_name);

    let field_ty = &field.ty;
    let (ffi_fn_args, ffi_fn_body) = match derive {
        Derive::Setter => {
            let (handle_arg, field_arg) = (
                Receiver::new(Some(&self_ty), handle_name, parse_quote! {&mut Self}),
                InputArg::new(Some(&self_ty), field_name, field_ty),
            );

            (
                gen_ffi_fn_args(&handle_arg, &field_arg, derive),
                gen_ffi_fn_body(&derive_method_name, &handle_arg, &field_arg, derive),
            )
        }
        Derive::Getter => {
            let field_ty = parse_quote! {&#field_ty};

            let (handle_arg, field_arg) = (
                Receiver::new(Some(&self_ty), handle_name, parse_quote! {&Self}),
                ReturnArg::new(Some(&self_ty), field_name.clone(), &field_ty),
            );

            (
                gen_ffi_fn_args(&handle_arg, &field_arg, derive),
                gen_ffi_fn_body(&derive_method_name, &handle_arg, &field_arg, derive),
            )
        }
        Derive::MutGetter => {
            let field_ty = parse_quote! {&mut #field_ty};

            let (handle_arg, field_arg) = (
                Receiver::new(Some(&self_ty), handle_name, parse_quote! {&mut Self}),
                ReturnArg::new(Some(&self_ty), field_name.clone(), &field_ty),
            );

            (
                gen_ffi_fn_args(&handle_arg, &field_arg, derive),
                gen_ffi_fn_body(&derive_method_name, &handle_arg, &field_arg, derive),
            )
        }
    };

    parse_quote! {
        #[doc = #ffi_fn_doc]
        #[no_mangle]
        unsafe extern "C" fn #ffi_fn_name<'itm>(#ffi_fn_args) -> iroha_ffi::FfiResult {
            let res = std::panic::catch_unwind(|| {
                #[allow(clippy::shadow_unrelated)]
                let fn_body = || #ffi_fn_body;

                if let Err(err) = fn_body() {
                    return err;
                }

                iroha_ffi::FfiResult::Ok
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
