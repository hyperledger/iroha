#![allow(clippy::str_to_string, missing_docs)]

use impl_visitor::ImplDescriptor;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, Item, NestedMeta};

use crate::convert::{derive_into_ffi, derive_try_from_ffi};

mod convert;
mod ffi_fn;
mod impl_visitor;
mod util;
#[cfg(feature = "client")]
mod wrapper;

struct FfiItems(Vec<syn::DeriveInput>);

impl syn::parse::Parse for FfiItems {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut items = Vec::new();

        while !input.is_empty() {
            items.push(input.parse()?);
        }

        Ok(Self(items))
    }
}
impl quote::ToTokens for FfiItems {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let items = &self.0;
        tokens.extend(quote! {#(#items)*})
    }
}

/// Derive implementations of traits required to convert from an FFI compatible type
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn ffi(input: TokenStream) -> TokenStream {
    let mut items = Vec::new();

    for item in parse_macro_input!(input as FfiItems).0 {
        items.push(process_ffi_type(item));
    }

    quote! {
        #(#items)*
    }
    .into()
}

/// Generate FFI functions
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_export(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(ffi_fn::generate);

            #[cfg(feature = "client")]
            let item = wrapper::wrap_impl_item(&impl_descriptor.fns);

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        Item::Struct(item) => {
            let derived_methods = util::gen_derived_methods(&item);
            let ffi_fns = derived_methods.iter().map(ffi_fn::generate);

            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics are not supported");
            }

            #[cfg(feature = "client")]
            let impl_block = wrapper::wrap_impl_item(&derived_methods);

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

fn process_ffi_type(input: syn::DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items supported");
    }

    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    let into_ffi_derives = derive_into_ffi(&input);
    let try_from_ffi_derives = derive_try_from_ffi(&input);

    #[cfg(feature = "client")]
    let input = if is_opaque(&input, &find_attr(&input.attrs, "repr")) {
        wrapper::wrap_as_opaque(input)
    } else {
        quote! {#input}
    };

    quote! {
        #input

        #into_ffi_derives
        #try_from_ffi_derives
    }
}

fn is_opaque(input: &syn::DeriveInput, repr: &[NestedMeta]) -> bool {
    if let syn::Data::Enum(item) = &input.data {
        if is_fieldless_enum(&input.ident, item, repr) {
            return false;
        }
    }

    !is_repr_attr(repr, "C")
}

fn is_fieldless_enum(name: &syn::Ident, item: &syn::DataEnum, repr: &[NestedMeta]) -> bool {
    enum_size(name, repr); // NOTE: Verifies that repr(Int) is defined

    !item
        .variants
        .iter()
        .any(|variant| !matches!(variant.fields, syn::Fields::Unit))
}

fn find_attr(attrs: &[syn::Attribute], name: &str) -> Vec<NestedMeta> {
    attrs
        .iter()
        .filter_map(|attr| {
            if let Ok(syn::Meta::List(meta_list)) = attr.parse_meta() {
                return meta_list.path.is_ident(name).then(|| meta_list.nested);
            }

            None
        })
        .flatten()
        .collect()
}

fn is_repr_attr(repr: &[NestedMeta], name: &str) -> bool {
    repr.into_iter().any(|meta| {
        if let NestedMeta::Meta(item) = meta {
            match item {
                syn::Meta::Path(ref path) => {
                    if path.is_ident(name) {
                        return true;
                    }
                }
                _ => abort!(item, "Unknown repr attribute"),
            }
        }

        false
    })
}

fn enum_size(enum_name: &syn::Ident, repr: &[NestedMeta]) -> TokenStream2 {
    if is_repr_attr(repr, "u8") {
        quote! {u8}
    } else if is_repr_attr(repr, "u16") {
        quote! {u16}
    } else if is_repr_attr(repr, "u32") {
        quote! {u32}
    } else if is_repr_attr(repr, "u64") {
        quote! {u64}
    } else {
        abort!(enum_name, "Enum doesn't have a valid representation")
    }
}
