//! Crate containing FFI related macro functionality
#![allow(clippy::arithmetic_side_effects)]

use darling::FromDeriveInput;
use impl_visitor::{FnDescriptor, ImplDescriptor};
use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;
use quote::quote;
use syn2::Item;
use wrapper::wrap_method;

use crate::{
    attr_parse::derive::Derive,
    convert::{derive_ffi_type, FfiTypeData, FfiTypeInput},
};

mod attr_parse;
mod convert;
mod ffi_fn;
mod getset_gen;
mod impl_visitor;
mod wrapper;

struct FfiItems(Vec<FfiTypeInput>);

impl syn2::parse::Parse for FfiItems {
    fn parse(input: syn2::parse::ParseStream) -> syn2::Result<Self> {
        let mut items = Vec::new();

        while !input.is_empty() {
            let input = input.parse::<syn2::DeriveInput>()?;
            let input = FfiTypeInput::from_derive_input(&input)?;

            items.push(input);
        }

        Ok(Self(items))
    }
}

/// A test utility function that parses multiple attributes
#[cfg(test)]
fn parse_attributes(ts: TokenStream) -> Vec<syn2::Attribute> {
    struct Attributes(Vec<syn2::Attribute>);
    impl syn2::parse::Parse for Attributes {
        fn parse(input: syn2::parse::ParseStream) -> syn2::Result<Self> {
            syn2::Attribute::parse_outer(input).map(Attributes)
        }
    }

    syn2::parse2::<Attributes>(ts)
        .expect("Failed to parse attributes")
        .0
}

/// Replace struct/enum/union definition with opaque pointer. This applies to types that
/// are converted to an opaque pointer when sent across FFI but does not affect any other
/// item wrapped with this macro (e.g. fieldless enums). This is so that most of the time
/// users can safely wrap all of their structs with this macro and not be concerned with the
/// cognitive load of figuring out which structs are converted to opaque pointers.
///
/// ## A note on `#[derive(...)]` limitations
///
/// This proc-macro crate parses the `#[derive(...)]` attributes.
/// Due to technical limitations of proc macros, it does not have access to the resolved path of the macro, only to what is written in the derive.
/// As such, it cannot support derives that are used through aliases, such as
///
/// ```ignore
/// use getset::Getters as GettersAlias;
/// #[derive(GettersAlias)]
/// pub struct Hello {
///     // ...
/// }
/// ```
///
/// It assumes that the derive is imported and referred to by its original name.
#[manyhow]
#[proc_macro]
pub fn ffi(input: TokenStream) -> TokenStream {
    let items = match syn2::parse2::<FfiItems>(input) {
        Ok(items) => items.0,
        Err(err) => return err.to_compile_error(),
    };

    let mut emitter = Emitter::new();

    let items = items
        .into_iter()
        .map(|item| {
            if !matches!(item.vis, syn2::Visibility::Public(_)) {
                emit!(emitter, item.span, "Only public types are allowed in FFI");
            }

            if !item.is_opaque() {
                let item = item.ast;
                return quote! {
                    #[derive(iroha_ffi::FfiType)]
                    #item
                };
            }

            if let FfiTypeData::Struct(fields) = &item.data {
                if item
                    .derive_attr
                    .derives
                    .iter()
                    .any(|d| matches!(d, Derive::GetSet(_)))
                {
                    let derived_methods: Vec<_> = getset_gen::gen_derived_methods(
                        &mut emitter,
                        &item.ident,
                        &item.derive_attr,
                        &item.getset_attr,
                        fields,
                    )
                    .collect();

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
                    let opaque = wrapper::wrap_as_opaque(&mut emitter, item);

                    return quote! {
                        #opaque

                        #impl_block
                        #(#ffi_fns)*
                    };
                }
            }

            wrapper::wrap_as_opaque(&mut emitter, item)
        })
        .collect::<Vec<_>>();

    emitter.finish_token_stream_with(quote! { #(#items)* })
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
/// is carrying ownership mark entire type as opaque with `#[ffi_type(opaque)]`. If the type
/// is not carrying ownership, but is not robust convert it into an equivalent [`iroha_ffi::ReprC`]
/// type that is validated when crossing the FFI boundary. It is also ok to mark non-owning,
/// non-robust type as opaque
///
/// # Safety
///
/// * wrapping type must allow for all possible values of the pointer including `null` (it's robust)
/// * the wrapping types's field of the pointer type must not carry ownership (it's non owning)
///
/// ## A note on `#[derive(...)]` limitations
///
/// This proc-macro crate parses the `#[derive(...)]` attributes.
/// Due to technical limitations of proc macros, it does not have access to the resolved path of the macro, only to what is written in the derive.
/// As such, it cannot support derives that are used through aliases, such as
///
/// ```ignore
/// use getset::Getters as GettersAlias;
/// #[derive(GettersAlias)]
/// pub struct Hello {
///     // ...
/// }
/// ```
///
/// It assumes that the derive is imported and referred to by its original name.
#[manyhow]
#[proc_macro_derive(FfiType, attributes(ffi_type))]
pub fn ffi_type_derive(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(item) = emitter.handle(syn2::parse2::<syn2::DeriveInput>(input)) else {
        return emitter.finish_token_stream();
    };

    if !matches!(item.vis, syn2::Visibility::Public(_)) {
        emit!(emitter, item, "Only public types are allowed in FFI");
    }

    let result = derive_ffi_type(&mut emitter, &item);
    emitter.finish_token_stream_with(result)
}

/// Generate FFI functions
///
/// When placed on a structure, it integrates with [`getset`] to export derived getter/setter methods.
/// To be visible this attribute must be placed before/on top of any [`getset`] derive macro attributes
///
/// It also works on impl blocks (by visiting all methods in the impl block) and on enums and unions (as a no-op)
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
///
/// ## A note on `#[derive(...)]` limitations
///
/// This proc-macro crate parses the `#[derive(...)]` attributes.
/// Due to technical limitations of proc macros, it does not have access to the resolved path of the macro, only to what is written in the derive.
/// As such, it cannot support derives that are used through aliases, such as
///
/// ```ignore
/// use getset::Getters as GettersAlias;
/// #[derive(GettersAlias)]
/// pub struct Hello {
///     // ...
/// }
/// ```
///
/// It assumes that the derive is imported and referred to by its original name.
#[manyhow]
#[proc_macro_attribute]
pub fn ffi_export(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = match syn2::parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };

    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(emitter, item, "Unknown tokens in the attribute");
    }

    let result = match item {
        Item::Impl(item) => {
            let Some(impl_descriptor) = ImplDescriptor::from_impl(&mut emitter, &item) else {
                // continuing here creates a lot of dubious errors
                return emitter.finish_token_stream();
            };
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
            let Some(fn_descriptor) = FnDescriptor::from_fn(&mut emitter, &item) else {
                // continuing here creates a lot of dubious errors
                return emitter.finish_token_stream();
            };
            let ffi_fn = ffi_fn::gen_definition(&fn_descriptor, None);

            quote! {
                #item
                #ffi_fn
            }
        }
        Item::Struct(item) => {
            // re-parse as a DeriveInput to utilize darling
            let input = syn2::parse2(quote!(#item)).unwrap();
            let Some(input) = emitter.handle(FfiTypeInput::from_derive_input(&input)) else {
                return emitter.finish_token_stream();
            };

            // we don't need ffi fns for getset accessors if the type is not opaque or there are no accessors
            if !input.is_opaque()
                || !input
                    .derive_attr
                    .derives
                    .iter()
                    .any(|d| matches!(d, Derive::GetSet(_)))
            {
                let input = input.ast;
                return emitter.finish_token_stream_with(quote! { #input });
            }

            let darling::ast::Data::Struct(fields) = &input.data else {
                unreachable!("We parsed struct above");
            };

            if !input.generics.params.is_empty() {
                emit!(
                    emitter,
                    input.generics,
                    "Generics on derived methods not supported"
                );
                // continuing codegen results in a lot of spurious errors
                return emitter.finish_token_stream();
            }
            let derived_ffi_fns = getset_gen::gen_derived_methods(
                &mut emitter,
                &input.ident,
                &input.derive_attr,
                &input.getset_attr,
                fields,
            )
            .map(|fn_| ffi_fn::gen_definition(&fn_, None));

            quote! {
                #item
                #(#derived_ffi_fns)*
            }
        }
        Item::Enum(item) => quote! { #item },
        Item::Union(item) => quote! { #item },
        item => {
            emit!(emitter, item, "Item not supported");
            quote!()
        }
    };

    emitter.finish_token_stream_with(result)
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
///
/// ## A note on `#[derive(...)]` limitations
///
/// This proc-macro crate parses the `#[derive(...)]` attributes.
/// Due to technical limitations of proc macros, it does not have access to the resolved path of the macro, only to what is written in the derive.
/// As such, it cannot support derives that are used through aliases, such as
///
/// ```ignore
/// use getset::Getters as GettersAlias;
/// #[derive(GettersAlias)]
/// pub struct Hello {
///     // ...
/// }
/// ```
///
/// It assumes that the derive is imported and referred to by its original name.
#[manyhow]
#[proc_macro_attribute]
pub fn ffi_import(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = match syn2::parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };
    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(emitter, item, "Unknown tokens in the attribute");
    }

    let result = match item {
        Item::Impl(item) => {
            let attrs = &item.attrs;
            let Some(impl_desc) = ImplDescriptor::from_impl(&mut emitter, &item) else {
                // continuing codegen results in a lot of spurious errors
                return emitter.finish_token_stream();
            };
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
            let Some(fn_descriptor) = FnDescriptor::from_fn(&mut emitter, &item) else {
                // continuing here creates a lot of dubious errors
                return emitter.finish_token_stream();
            };
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
        item => {
            emit!(emitter, item, "Item not supported");
            quote!()
        }
    };

    emitter.finish_token_stream_with(result)
}
