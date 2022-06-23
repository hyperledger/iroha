use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, ItemStruct, Type};

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

fn gen_ffi_fn_args(handle: (&Ident, &Type), field: (&Ident, &Type), derive: Derive) -> TokenStream {
    let (handle_name, handle_type) = (&handle.0, handle.1.clone());
    let (field_name, field_type) = (&field.0, field.1.clone());

    match derive {
        Derive::Setter => quote! {
            #handle_name: <#handle_type as iroha_ffi::IntoFfi>::FfiType,
            #field_name: <#field_type as iroha_ffi::IntoFfi>::FfiType,
        },
        Derive::Getter | Derive::MutGetter => quote! {
            #handle_name: <#handle_type as iroha_ffi::IntoFfi>::FfiType,
            #field_name: <#field_type as iroha_ffi::IntoFfi>::OutFfiType,
        },
    }
}

fn gen_ffi_fn_body(
    method_name: &Ident,
    handle: (&Ident, &Type),
    field: (&Ident, &Type),
    derive: Derive,
) -> TokenStream {
    let (handle_name, handle_type) = (&handle.0, handle.1.clone());
    let (field_name, field_type) = (&field.0, field.1.clone());

    let handle = quote! {
        let mut handle_store = Default::default();
        // TODO: Handle unwrap
        let #handle_name = <#handle_type as iroha_ffi::TryFromFfi>::try_from_ffi(#handle_name, &mut handle_store).unwrap();
    };

    match derive {
        Derive::Setter => {
            quote! {
                #handle
                let mut field_store = Default::default();
                // TODO: Handle unwrap
                let #field_name = <#field_type as iroha_ffi::TryFromFfi>::try_from_ffi(#handle_name, &mut field_store).unwrap();
                #handle_name.#method_name(#field_name);
                iroha_ffi::FfiResult::Ok
            }
        }
        Derive::Getter | Derive::MutGetter => {
            quote! {
                #handle

                let __out_ptr = #field_name;
                let #field_name = #handle_name.#method_name();
                let mut output_store = Default::default();
                <#field_type as iroha_ffi::IntoFfi>::write_out(#field_name, &mut output_store, __out_ptr);
                iroha_ffi::FfiResult::Ok
            }
        }
    }
}

fn gen_ffi_derive(struct_name: &Ident, field: &syn::Field, derive: Derive) -> syn::ItemFn {
    let handle_name = Ident::new("__handle", proc_macro2::Span::call_site());
    let field_name = field.ident.as_ref().expect_or_abort("Defined");

    //let field_name = match derive {
    //    Derive::Setter => parse_quote! {field},
    //    Derive::Getter | Derive::MutGetter => parse_quote! {output},
    //};
    let field_ty = field.ty.clone();
    let (handle_type, field_type) = match derive {
        Derive::Setter => (parse_quote! {&mut #struct_name}, field_ty),
        Derive::Getter => (parse_quote! {&#struct_name}, parse_quote! {&#field_ty}),
        Derive::MutGetter => (
            parse_quote! {&mut #struct_name},
            parse_quote! {&mut #field_ty},
        ),
    };

    let derive_method_name = gen_derive_method_name(field_name, derive);
    let ffi_fn_name = gen_ffi_fn_name(struct_name, &derive_method_name);
    let ffi_fn_doc = gen_ffi_docs(struct_name, &derive_method_name);
    let ffi_fn_args = gen_ffi_fn_args(
        (&handle_name, &handle_type),
        (field_name, &field_type),
        derive,
    );
    let ffi_fn_body = gen_ffi_fn_body(
        &derive_method_name,
        (&handle_name, &handle_type),
        (field_name, &field_type),
        derive,
    );

    parse_quote! {
        #[doc = #ffi_fn_doc]
        #[no_mangle]
        unsafe extern "C" fn #ffi_fn_name(#ffi_fn_args) -> iroha_ffi::FfiResult {
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
