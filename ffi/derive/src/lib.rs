#![allow(
    clippy::str_to_string,
    missing_docs,
    clippy::arithmetic,
    clippy::std_instead_of_core
)]

use impl_visitor::{FnDescriptor, ImplDescriptor};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, Item, NestedMeta};

use crate::convert::{derive_into_ffi, derive_try_from_repr_c};

mod convert;
mod ffi_fn;
mod impl_visitor;
mod util;
// TODO: Should be enabled in https://github.com/hyperledger/iroha/issues/2231
//mod wrapper;

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

/// Replace struct/enum definition with opaque pointer. This applies to structs/enums that
/// are converted to an opaque pointer when sent across FFI but does not affect any other
/// item wrapped with this macro (e.g. fieldless enums). This is so that most of the time
/// users can safely wrap all of their structs with this macro and not be concerned with the
/// cognitive load of figuring out which structs are converted to opaque pointers.
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn ffi(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input as FfiItems).0;

    // TODO: Should be fixed in https://github.com/hyperledger/iroha/issues/2231
    //items
    //    .iter_mut()
    //    .filter(|item| is_opaque(item))
    //    .for_each(|item| item.attrs.push(syn::parse_quote! {#[opaque_wrapper]}));
    //let items = items.iter().map(|item| {
    //    if is_opaque(item) {
    //        wrapper::wrap_as_opaque(item)
    //    } else {
    //        quote! {#item}
    //    }
    //});

    quote! { #(#items)* }.into()
}

/// Derive implementations of traits required to convert to and from an FFI-compatible type
#[proc_macro_derive(IntoFfi, attributes(opaque_wrapper))]
#[proc_macro_error::proc_macro_error]
pub fn into_ffi_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);
    let into_ffi_derive = derive_into_ffi(&item);
    quote! { #into_ffi_derive }.into()
}

/// Derive implementation of [`TryFromReprC`] trait
#[proc_macro_derive(TryFromReprC, attributes(opaque_wrapper))]
#[proc_macro_error::proc_macro_error]
pub fn try_from_repr_c_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);
    let try_from_repr_c_derive = derive_try_from_repr_c(&item);
    quote! { #try_from_repr_c_derive }.into()
}

/// Generate FFI functions
///
/// # Example:
/// ```rust
/// use std::alloc::alloc;
///
/// use getset::Getters;
/// use iroha_ffi::{slice::OutSliceRef, FfiReturn, IntoFfi, TryFromReprC};
///
/// // For a struct such as:
/// #[derive(Clone, Getters, IntoFfi, TryFromReprC)]
/// #[iroha_ffi::ffi_export]
/// #[getset(get = "pub")]
/// pub struct Foo {
///     /// Id of the struct
///     id: u8,
///     #[getset(skip)]
///     bar: Vec<u8>,
/// }
///
/// #[iroha_ffi::ffi_export]
/// impl Foo {
///     /// Construct new type
///     pub fn new(id: u8) -> Self {
///         Self {id, bar: Vec::new()}
///     }
///     /// Return bar
///     pub fn bar(&self) -> &[u8] {
///         &self.bar
///     }
/// }
///
/// /* The following functions will be derived:
/// extern "C" fn Foo__new(id: u8, output: *mut Foo) -> FfiReturn {
///     /* function implementation */
///     FfiReturn::Ok
/// }
/// extern "C" fn Foo__bar(handle: *const Foo, output: OutSliceRef<u8>) -> FfiReturn {
///     /* function implementation */
///     FfiReturn::Ok
/// }
/// extern "C" fn Foo__id(handle: *const Foo, output: *mut u8) -> FfiReturn {
///     /* function implementation */
///     FfiReturn::Ok
/// } */
/// ```
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_export(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(ffi_fn::gen_definition);

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        Item::Struct(item) => {
            let derived_methods = util::gen_derived_methods(&item);
            let ffi_fns = derived_methods.iter().map(ffi_fn::gen_definition);

            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics are not supported");
            }

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

            let fn_descriptor = FnDescriptor::from_fn(&item);
            let ffi_fn = ffi_fn::gen_definition(&fn_descriptor);
            quote! {
                #item

                #ffi_fn
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_import(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(ffi_fn::gen_declaration);

            // TODO: Should be fixed in https://github.com/hyperledger/iroha/issues/2231
            //let item = wrapper::wrap_impl_item(&impl_descriptor.fns);

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        Item::Struct(item) => {
            let derived_methods = util::gen_derived_methods(&item);
            let ffi_fns = derived_methods.iter().map(ffi_fn::gen_declaration);

            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics are not supported");
            }

            // TODO: Remove getset attributes to prevent code generation
            // Should be fixed in https://github.com/hyperledger/iroha/issues/2231
            //let impl_block = Some(wrapper::wrap_impl_item(&derived_methods));
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

            let fn_descriptor = FnDescriptor::from_fn(&item);
            let ffi_fn = ffi_fn::gen_declaration(&fn_descriptor);
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

    !is_repr_attr(repr, "C") && !is_repr_attr(repr, "transparent")
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
                return meta_list.path.is_ident(name).then_some(meta_list.nested);
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
