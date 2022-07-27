#![allow(clippy::str_to_string, missing_docs)]

use impl_visitor::{FnDescriptor, ImplDescriptor};
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

/// Derive implementations of traits required to convert to and from an FFI-compatible type
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn ffi(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input as FfiItems).0;

    #[cfg(feature = "client")]
    let items = items.iter().map(|item| {
        if is_opaque(item) {
            wrapper::wrap_as_opaque(item)
        } else {
            quote! {#item}
        }
    });

    quote! { #(#items)* }.into()
}

/// Derive implementations of traits required to convert to and from an FFI-compatible type
#[proc_macro_derive(IntoFfi)]
#[proc_macro_error::proc_macro_error]
pub fn into_ffi_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);
    let into_ffi_derive = derive_into_ffi(&item);

    if !matches!(item.vis, syn::Visibility::Public(_)) {
        abort!(item.vis, "Only public items are supported");
    }

    if !item.generics.params.is_empty() {
        abort!(item.generics, "Generics are not supported");
    }

    quote! { #into_ffi_derive }.into()
}

/// Derive implementation of [`TryFromReprC`] trait
#[proc_macro_derive(TryFromReprC)]
#[proc_macro_error::proc_macro_error]
pub fn try_from_repr_c_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);
    let try_from_ffi_derive = derive_try_from_ffi(&item);

    if !matches!(item.vis, syn::Visibility::Public(_)) {
        abort!(item.vis, "Only public items are supported");
    }

    if !item.generics.params.is_empty() {
        abort!(item.generics, "Generics are not supported");
    }

    quote! { #try_from_ffi_derive }.into()
}

/// Generate FFI functions
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_export(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(ffi_fn::generate);

            // TODO: Should be fixed in https://github.com/hyperledger/iroha/issues/2231
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

            // TODO: Remove getset attributes to prevent code generation
            // Should be fixed in https://github.com/hyperledger/iroha/issues/2231
            //#[cfg(feature = "client")]
            //let impl_block = Some(wrapper::wrap_impl_item(&derived_methods));
            //#[cfg(not(feature = "client"))]
            //let impl_block: Option<TokenStream2> = None;

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        Item::Fn(item) => {
            if item.sig.asyncness.is_some() {
                abort!(item.sig.asyncness, "Async functions are not supported");
            }

            if item.sig.unsafety.is_some() {
                abort!(item.sig.unsafety, "You shouldn't specify function unsafety");
            }

            if item.sig.abi.is_some() {
                abort!(item.sig.abi, "You shouldn't specify function ABI");
            }

            if !item.sig.generics.params.is_empty() {
                abort!(item.sig.generics, "Generics are not supported");
            }

            let fn_descriptor = FnDescriptor::from(&item);
            let ffi_fn = ffi_fn::generate(&fn_descriptor);
            quote! {
                #item

                #ffi_fn
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

fn is_opaque(input: &syn::DeriveInput) -> bool {
    let repr = &find_attr(&input.attrs, "repr");

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
    repr.iter().any(|meta| {
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
