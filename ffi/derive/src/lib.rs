#![allow(
    clippy::str_to_string,
    missing_docs,
    clippy::arithmetic,
    clippy::std_instead_of_core
)]

use impl_visitor::{FnDescriptor, ImplDescriptor};
use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Item, NestedMeta};

use crate::convert::derive_ffi_type;

mod convert;
mod ffi_fn;
mod impl_visitor;
mod util;
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

/// Replace struct/enum/union definition with opaque pointer. This applies to types that
/// are converted to an opaque pointer when sent across FFI but does not affect any other
/// item wrapped with this macro (e.g. fieldless enums). This is so that most of the time
/// users can safely wrap all of their structs with this macro and not be concerned with the
/// cognitive load of figuring out which structs are converted to opaque pointers.
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn ffi(input: TokenStream) -> TokenStream {
    let mut items = parse_macro_input!(input as FfiItems).0;

    items
        .iter_mut()
        .filter(|item| is_opaque(item))
        .map(|item| &mut item.attrs)
        .for_each(|attrs| attrs.push(parse_quote! {#[ffi_type(r#extern)]}));

    let items = items.iter().map(|item| {
        if is_extern(&item.attrs) {
            wrapper::wrap_as_opaque(item)
        } else {
            quote! {#item}
        }
    });

    quote! { #(#items)* }.into()
}

/// Derive implementations of traits required to convert to and from an FFI-compatible type
#[proc_macro_derive(FfiType, attributes(ffi_type))]
#[proc_macro_error::proc_macro_error]
pub fn ffi_type_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);
    let ffi_type_derive = derive_ffi_type(item);
    quote! { #ffi_type_derive }.into()
}

/// Generate FFI functions
///
/// # Example:
/// ```rust
/// use std::alloc::alloc;
///
/// use getset::Getters;
/// use iroha_ffi::{FfiReturn, FfiType};
///
/// // For a struct such as:
/// #[derive(Clone, Getters, FfiType)]
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
/// extern "C" fn Foo__bar(handle: *const Foo, output: *mut SliceRef<u8>) -> FfiReturn {
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
pub fn ffi_export(attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            if !attr.is_empty() {
                abort!(item, "Unknown tokens in the attribute");
            }

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

            let repr = find_attr(&item.attrs, "repr");
            if is_repr_attr(&repr, "C") {
                abort!(item.ident, "Only opaque structs can export FFI bindings");
            }
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
            if !attr.is_empty() {
                abort!(item, "Unknown tokens in the attribute");
            }

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
            let wrapped_item = wrapper::wrap_impl_item(&impl_descriptor.fns);

            quote! {
                #wrapped_item
                #(#ffi_fns)*
            }
        }
        Item::Struct(item) => {
            let derived_methods = util::gen_derived_methods(&item);
            let ffi_fns = derived_methods.iter().map(ffi_fn::gen_declaration);
            let impl_block = wrapper::wrap_impl_item(&derived_methods);

            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics are not supported");
            }

            quote! {
                #item
                #impl_block
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

fn is_extern(attrs: &[syn::Attribute]) -> bool {
    let opaque_attr = parse_quote! {#[ffi_type(r#extern)]};
    attrs.iter().any(|a| *a == opaque_attr)
}

fn is_opaque(input: &syn::DeriveInput) -> bool {
    if is_opaque_attr(&input.attrs) {
        return true;
    }

    // NOTE: Enums without defined representation, by default, are not opaque
    !matches!(&input.data, syn::Data::Enum(_)) && without_repr(&input.attrs)
}

fn is_opaque_attr(attrs: &[syn::Attribute]) -> bool {
    let opaque_attr = parse_quote! {#[ffi_type(opaque)]};
    attrs.iter().any(|a| *a == opaque_attr)
}

fn without_repr(attrs: &[syn::Attribute]) -> bool {
    find_attr(attrs, "repr").is_empty()
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

fn find_attr(attrs: &[syn::Attribute], name: &str) -> syn::AttributeArgs {
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
