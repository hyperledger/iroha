//! Crate containing FFI related macro functionality
#![allow(clippy::arithmetic_side_effects)]

use impl_visitor::{FnDescriptor, ImplDescriptor};
use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Item, NestedMeta};
use wrapper::wrap_method;

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

fn has_getset_attr(attrs: &[syn::Attribute]) -> bool {
    for derive in find_attr(attrs, "derive") {
        if let syn::NestedMeta::Meta(syn::Meta::Path(path)) = &derive {
            if path.segments.first().expect("Must have one segment").ident == "getset" {
                return true;
            }
            if path.is_ident("Setters") || path.is_ident("Getters") || path.is_ident("MutGetters") {
                return true;
            }
        }
    }

    false
}

/// Replace struct/enum/union definition with opaque pointer. This applies to types that
/// are converted to an opaque pointer when sent across FFI but does not affect any other
/// item wrapped with this macro (e.g. fieldless enums). This is so that most of the time
/// users can safely wrap all of their structs with this macro and not be concerned with the
/// cognitive load of figuring out which structs are converted to opaque pointers.
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn ffi(input: TokenStream) -> TokenStream {
    let items = parse_macro_input!(input as FfiItems).0;

    let items = items.into_iter().map(|item| {
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            abort!(item, "Only public types are allowed in FFI");
        }

        if !is_opaque(&item) {
            return quote! {
                #[derive(iroha_ffi::FfiType)]
                #item
            };
        }

        if let syn::Data::Struct(struct_) = &item.data {
            if has_getset_attr(&item.attrs) {
                let derived_methods: Vec<_> =
                    util::gen_derived_methods(&item.ident, &item.attrs, &struct_.fields).collect();

                let ffi_fns: Vec<_> = derived_methods
                    .iter()
                    .map(|fn_| ffi_fn::gen_declaration(fn_, None))
                    .collect();

                let impl_block = wrapper::wrap_impl_items(&ImplDescriptor {
                    attrs: Vec::new(),
                    trait_name: None,
                    associated_types: Vec::new(),
                    fns: derived_methods,
                });
                let opaque = wrapper::wrap_as_opaque(item);

                return quote! {
                    #opaque

                    #impl_block
                    #(#ffi_fns)*
                };
            }
        }

        let opaque = wrapper::wrap_as_opaque(item);
        quote! { #opaque }
    });

    quote! { #(#items)* }.into()
}

// TODO: ffi_type(`local`) is a workaround for https://github.com/rust-lang/rust/issues/48214
// because some derived types cannot derive `NonLocal` othwerise. Should be removed in future
/// Derive implementations of traits required to convert to and from an FFI-compatible type
///
/// # Attributes
///
/// * `#[ffi_type(opaque)]`
/// serialize the type as opaque. If automatically derived type doesn't work just
/// attach this attribute and force the type to be serialized as opaque across FFI
///
/// * `#[ffi_type(unsafe {robust})]`
/// serialize the type as transparent with respect to the wrapped type where every
/// valid bit pattern of the underlying type must be valid for the wrapper type.
///
/// Only applicable to `#[repr(transparent)]` types
///
/// # Safety
///
/// type must not have trap representations in the serialized form
///
/// * `#[ffi_type(local)]`
/// marks the type as local, meaning it contains references to the local frame. If a type
/// contains references to the local frame you won't be able to return it from an FFI function
/// because the frame is destroyed on function return which would invalidate your type's references.
///
/// Only applicable to data-carrying enums.
///
/// NOTE: This attribute is likely to be removed in future versions
///
/// * `#[ffi_type(unsafe {robust_non_owning})]`
/// when a type contains a raw pointer (e.g. `*const T`/*mut T`) it's not possible to figure out
/// whether it carries ownership of the data pointed to. Place this attribute on the field to
/// indicate pointer doesn't own the data and is robust in the type. Alternatively, if the type
/// is carrying ownership mark entire type as opaque with `#[ffi_type(opque)]`. If the type
/// is not carrying ownership, but is not robust convert it into an equivalent [`iroha_ffi::ReprC`]
/// type that is validated when crossing the FFI boundary. It is also ok to mark non-owning,
/// non-robust type as opaque
///
/// # Safety
///
/// * wrapping type must allow for all possible values of the pointer including `null` (it's robust)
/// * the wrapping types's field of the pointer type must not carry ownership (it's non owning)
#[proc_macro_derive(FfiType, attributes(ffi_type))]
#[proc_macro_error::proc_macro_error]
pub fn ffi_type_derive(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::DeriveInput);

    if !matches!(item.vis, syn::Visibility::Public(_)) {
        abort!(item, "Only public types are allowed in FFI");
    }

    let ffi_derive = derive_ffi_type(item);
    quote! { #ffi_derive }.into()
}

/// Generate FFI functions
///
/// When placed on a structure, it integrates with [`getset`] to export derived getter/setter methods.
/// To be visible this attribute must be placed before/on top of any [`getset`] derive macro attributes
///
/// # Example:
/// ```rust
/// use std::alloc::alloc;
///
/// use getset::Getters;
///
/// // For a struct such as:
/// #[iroha_ffi::ffi_export]
/// #[derive(iroha_ffi::FfiType)]
/// #[derive(Clone, Getters)]
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
            let ffi_fns = impl_descriptor
                .fns
                .iter()
                .map(|fn_| ffi_fn::gen_definition(fn_, impl_descriptor.trait_name()));

            quote! {
                #item
                #(#ffi_fns)*
            }
        }
        Item::Fn(item) => {
            let fn_descriptor = FnDescriptor::from_fn(&item);
            let ffi_fn = ffi_fn::gen_definition(&fn_descriptor, None);

            quote! {
                #item
                #ffi_fn
            }
        }
        Item::Struct(item) => {
            if !is_opaque_struct(&item) || !has_getset_attr(&item.attrs) {
                return quote! { #item }.into();
            }

            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics on derived methods not supported");
            }
            let derived_ffi_fns = util::gen_derived_methods(&item.ident, &item.attrs, &item.fields)
                .map(|fn_| ffi_fn::gen_definition(&fn_, None));

            quote! {
                #item
                #(#derived_ffi_fns)*
            }
        }
        Item::Enum(item) => quote! { #item },
        Item::Union(item) => quote! { #item },
        item => abort!(item, "Item not supported"),
    }
    .into()
}

/// Replace the function's body with a call to FFI function. Counterpart of [`ffi_export`]
///
/// When placed on a structure, it integrates with [`getset`] to import derived getter/setter methods.
///
/// # Example:
/// ```rust
/// #[iroha_ffi::ffi_import]
/// pub fn return_first_elem_from_arr(arr: [u8; 8]) -> u8 {
///    // The body of this function is replaced with something like the following:
///    // let mut store = Default::default();
///    // let arr = iroha_ffi::FfiConvert::into_ffi(arr, &mut store);
///    // let output = MaybeUninit::uninit();
///    //
///    // let call_res = __return_first_elem_from_arr(arr, output.as_mut_ptr());
///    // if iroha_ffi::FfiReturn::Ok != call_res {
///    //     panic!("Function call failed");
///    // }
///    //
///    // iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid type")
/// }
///
/// /* The following functions will be declared:
/// extern {
///     fn __return_first_elem_from_arr(arr: *const [u8; 8]) -> u8;
/// } */
/// ```
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_import(attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            if !attr.is_empty() {
                abort!(item, "Unknown tokens in the attribute");
            }

            let attrs = &item.attrs;
            let impl_desc = ImplDescriptor::from_impl(&item);
            let wrapped_items = wrapper::wrap_impl_items(&impl_desc);

            let is_shared_fn = impl_desc
                .trait_name
                .filter(|name| {
                    name.is_ident("Clone")
                        || name.is_ident("PartialEq")
                        || name.is_ident("PartialOrd")
                        || name.is_ident("Eq")
                        || name.is_ident("Ord")
                })
                .is_some();

            let ffi_fns = if is_shared_fn {
                Vec::new()
            } else {
                impl_desc
                    .fns
                    .iter()
                    .map(|fn_| ffi_fn::gen_declaration(fn_, impl_desc.trait_name()))
                    .collect()
            };

            quote! {
                #(#attrs)*
                #wrapped_items
                #(#ffi_fns)*
            }
        }
        Item::Fn(item) => {
            let fn_descriptor = FnDescriptor::from_fn(&item);
            let ffi_fn = ffi_fn::gen_declaration(&fn_descriptor, None);
            let wrapped_item = wrap_method(&fn_descriptor, None);

            quote! {
                #wrapped_item
                #ffi_fn
            }
        }
        Item::Struct(item) => quote! { #item },
        Item::Enum(item) => quote! { #item },
        Item::Union(item) => quote! { #item },
        item => abort!(item, "Item not supported"),
    }
    .into()
}

fn is_opaque_struct(input: &syn::ItemStruct) -> bool {
    if is_opaque_attr(&input.attrs) {
        return true;
    }

    without_repr(&find_attr(&input.attrs, "repr"))
}

fn is_opaque(input: &syn::DeriveInput) -> bool {
    if is_opaque_attr(&input.attrs) {
        return true;
    }

    let repr = find_attr(&input.attrs, "repr");

    // NOTE: Enums without defined representation, by default, are not opaque
    !matches!(&input.data, syn::Data::Enum(_)) && without_repr(&repr)
}

fn is_opaque_attr(attrs: &[syn::Attribute]) -> bool {
    let opaque_attr = parse_quote! {#[ffi_type(opaque)]};
    attrs.iter().any(|a| *a == opaque_attr)
}

fn without_repr(repr: &[NestedMeta]) -> bool {
    repr.is_empty()
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
