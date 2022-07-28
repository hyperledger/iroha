#![allow(clippy::str_to_string, missing_docs)]

use derive::gen_fns_from_derives;
use export::gen_ffi_fn;
use impl_visitor::{FnDescriptor, ImplDescriptor};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Attribute, Ident, Item};

mod derive;
mod export;
mod impl_visitor;

/// Generate FFI functions
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn ffi_export(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_macro_input!(item) {
        Item::Impl(item) => {
            let impl_descriptor = ImplDescriptor::from_impl(&item);
            let ffi_fns = impl_descriptor.fns.iter().map(gen_ffi_fn);

            quote! {
                #item

                #( #ffi_fns )*
            }
        }
        Item::Struct(item) => {
            if !matches!(item.vis, syn::Visibility::Public(_)) {
                abort!(item.vis, "Only public structs allowed in FFI");
            }
            if !item.generics.params.is_empty() {
                abort!(item.generics, "Generics are not supported");
            }

            let ffi_fns = gen_fns_from_derives(&item);

            quote! {
                #item

                #( #ffi_fns )*
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
            let ffi_fn = gen_ffi_fn(&fn_descriptor);
            quote! {
                #item

                #ffi_fn
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

/// Derive implementations of traits required to convert into an FFI compatible type
#[proc_macro_derive(IntoFfi)]
#[proc_macro_error::proc_macro_error]
pub fn into_ffi_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }

    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    match input.data {
        syn::Data::Struct(_) => derive_into_ffi_for_struct(&input.ident, &input.attrs),
        syn::Data::Enum(item) => derive_into_ffi_for_enum(&input.ident, &item, &input.attrs),
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
    .into()
}

/// Derive implementations of traits required to convert from an FFI compatible type
#[proc_macro_derive(TryFromFfi)]
#[proc_macro_error::proc_macro_error]
pub fn try_from_ffi_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items supported");
    }

    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    match input.data {
        syn::Data::Struct(_) => derive_try_from_ffi_for_struct(&input.ident, &input.attrs),
        syn::Data::Enum(item) => derive_try_from_ffi_for_enum(&input.ident, &item, &input.attrs),
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
    .into()
}

fn derive_try_from_ffi_for_struct(name: &Ident, attrs: &[Attribute]) -> TokenStream2 {
    let repr: Vec<_> = find_repr(attrs).collect();

    if !is_repr(&repr, "C") {
        return derive_try_from_ffi_for_opaque_item(name);
    }

    derive_try_from_ffi_for_item(name)
}

fn derive_into_ffi_for_struct(name: &Ident, attrs: &[Attribute]) -> TokenStream2 {
    let repr: Vec<_> = find_repr(attrs).collect();

    if !is_repr(&repr, "C") {
        return derive_into_ffi_for_opaque_item(name);
    }

    derive_into_ffi_for_item(name)
}

fn derive_into_ffi_for_enum(
    name: &Ident,
    item: &syn::DataEnum,
    attrs: &[Attribute],
) -> TokenStream2 {
    let repr: Vec<_> = find_repr(attrs).collect();

    let is_fieldless = !item
        .variants
        .iter()
        .any(|variant| !matches!(variant.fields, syn::Fields::Unit));

    // NOTE: Verifies that repr(Int) is defined
    enum_size(name, &repr);

    if is_fieldless {
        return gen_fieldless_enum_into_ffi(name, &repr);
    }
    if !is_repr(&repr, "C") {
        return derive_into_ffi_for_opaque_item(name);
    }

    derive_into_ffi_for_item(name)
}

fn derive_try_from_ffi_for_enum(
    name: &Ident,
    item: &syn::DataEnum,
    attrs: &[Attribute],
) -> TokenStream2 {
    let repr: Vec<_> = find_repr(attrs).collect();

    let is_fieldless = !item
        .variants
        .iter()
        .any(|variant| !matches!(variant.fields, syn::Fields::Unit));

    // NOTE: Verifies that repr(Int) is defined
    enum_size(name, &repr);

    if is_fieldless {
        return gen_fieldless_enum_try_from_ffi(name, item, &repr);
    }
    if !is_repr(&repr, "C") {
        return derive_try_from_ffi_for_opaque_item(name);
    }

    derive_try_from_ffi_for_item(name)
}

fn is_repr(repr: &[syn::NestedMeta], name: &str) -> bool {
    repr.iter().any(|meta| {
        if let syn::NestedMeta::Meta(item) = meta {
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

fn find_repr(attrs: &[Attribute]) -> impl Iterator<Item = syn::NestedMeta> + '_ {
    attrs
        .iter()
        .filter_map(|attr| {
            if let Ok(syn::Meta::List(meta_list)) = attr.parse_meta() {
                return meta_list.path.is_ident("repr").then(|| meta_list.nested);
            }

            None
        })
        .flatten()
}

fn derive_into_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    quote! {
        impl iroha_ffi::IntoFfi for #name {
            type Target = *mut Self;

            fn into_ffi(self) -> Self::Target {
                Box::into_raw(Box::new(self))
            }
        }

        impl iroha_ffi::IntoFfi for &#name {
            type Target = *const #name;

            fn into_ffi(self) -> Self::Target {
                <*const _>::from(self)
            }
        }

        impl iroha_ffi::IntoFfi for &mut #name {
            type Target = *mut #name;

            fn into_ffi(self) -> Self::Target {
                <*mut _>::from(self)
            }
        }

        impl iroha_ffi::slice::IntoFfiSliceRef<'_> for #name {
            type Target = iroha_ffi::owned::LocalSlice<*const #name>;

            fn into_ffi(source: &[Self]) -> Self::Target {
                source.iter().map(IntoFfi::into_ffi).collect()
            }
        }
    }
}

fn derive_try_from_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    quote! {
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for #name {
            type Source = *mut #name;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiResult::ArgIsNull);
                }

                Ok(*Box::from_raw(source))
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #name {
            type Source = *const #name;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                source.as_ref().ok_or(iroha_ffi::FfiResult::ArgIsNull)
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #name {
            type Source = *mut #name;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                source.as_mut().ok_or(iroha_ffi::FfiResult::ArgIsNull)
            }
        }

        impl<'itm> iroha_ffi::slice::TryFromReprCSliceRef<'itm> for #name {
            type Source = iroha_ffi::slice::SliceRef<'itm, <&'itm Self as iroha_ffi::TryFromReprC<'itm>>::Source>;
            type Store = Vec<Self>;

            unsafe fn try_from_repr_c(source: Self::Source, store: &'itm mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'itm>>::Store) -> Result<&'itm [Self], iroha_ffi::FfiResult> {
                let source = source.into_rust().ok_or(iroha_ffi::FfiResult::ArgIsNull)?;

                for elem in source {
                    store.push(Clone::clone(iroha_ffi::TryFromReprC::try_from_repr_c(*elem, &mut ())?));
                }

                Ok(store)
            }
        }
    }
}

#[allow(clippy::restriction)]
fn derive_into_ffi_for_item(_: &Ident) -> TokenStream2 {
    unimplemented!("https://github.com/hyperledger/iroha/issues/2510")
}

#[allow(clippy::restriction)]
fn derive_try_from_ffi_for_item(_: &Ident) -> TokenStream2 {
    unimplemented!("https://github.com/hyperledger/iroha/issues/2510")
}

fn gen_fieldless_enum_into_ffi(enum_name: &Ident, repr: &[syn::NestedMeta]) -> TokenStream2 {
    let ffi_type = enum_size(enum_name, repr);

    quote! {
        impl iroha_ffi::IntoFfi for #enum_name {
            type Target = #ffi_type;

            fn into_ffi(self) -> Self::Target {
                self as #ffi_type
            }
        }

        impl iroha_ffi::IntoFfi for &#enum_name {
            type Target = *const #ffi_type;

            fn into_ffi(self) -> Self::Target {
                self as *const #enum_name as *const #ffi_type
            }
        }

        impl iroha_ffi::IntoFfi for &mut #enum_name {
            type Target = *mut #ffi_type;

            fn into_ffi(self) -> Self::Target {
                self as *mut #enum_name as *mut #ffi_type
            }
        }
    }
}

fn gen_fieldless_enum_try_from_ffi(
    enum_name: &Ident,
    enum_: &syn::DataEnum,
    repr: &[syn::NestedMeta],
) -> TokenStream2 {
    let variant_names: Vec<_> = enum_.variants.iter().map(|v| &v.ident).collect();
    let discriminant_values = variant_discriminants(enum_);

    let ffi_type = enum_size(enum_name, repr);
    let (discriminants, discriminant_names) =
        variant_names.iter().zip(discriminant_values.iter()).fold(
            <(Vec<_>, Vec<_>)>::default(),
            |mut acc, (variant_name, discriminant_value)| {
                let discriminant_name = Ident::new(
                    &format!("{}__{}", enum_name, variant_name).to_uppercase(),
                    proc_macro2::Span::call_site(),
                );

                acc.0.push(quote! {
                    const #discriminant_name: #ffi_type = #discriminant_value;
                });
                acc.1.push(discriminant_name);

                acc
            },
        );

    quote! {
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for #enum_name {
            type Source = #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                match source {
                    #( #discriminant_names => Ok(#enum_name::#variant_names), )*
                    _ => Err(iroha_ffi::FfiResult::TrapRepresentation),
                }
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #enum_name {
            type Source = *const #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&*(source as *const _ as *const _)),
                    _ => Err(iroha_ffi::FfiResult::TrapRepresentation),
                }}
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #enum_name {
            type Source = *mut #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store) -> Result<Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&mut *(source as *mut _ as *mut _)),
                    _ => Err(iroha_ffi::FfiResult::TrapRepresentation),
                }}
            }
        }

        impl<'itm> iroha_ffi::slice::TryFromReprCSliceRef<'itm> for #enum_name {
            type Source = iroha_ffi::slice::SliceRef<'itm, Self>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'itm>>::Store) -> Result<&'itm [Self], iroha_ffi::FfiResult> {
                source.into_rust().ok_or(iroha_ffi::FfiResult::ArgIsNull)
            }
        }
        impl<'slice> iroha_ffi::slice::TryFromReprCSliceMut<'slice> for #enum_name {
            type Source = iroha_ffi::slice::SliceMut<'slice, #enum_name>;
            type Store = ();

            unsafe fn try_from_repr_c(source: Self::Source, _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceMut>::Store) -> Result<&'slice mut [Self], iroha_ffi::FfiResult> {
                source.into_rust().ok_or(iroha_ffi::FfiResult::ArgIsNull)
            }
        }
    }
}

fn variant_discriminants(enum_: &syn::DataEnum) -> Vec<syn::Expr> {
    let mut curr_discriminant: syn::Expr = parse_quote! {0};

    enum_.variants.iter().fold(Vec::new(), |mut acc, variant| {
        let discriminant = variant.discriminant.as_ref().map_or_else(
            || curr_discriminant.clone(),
            |discriminant| discriminant.1.clone(),
        );

        acc.push(discriminant.clone());
        curr_discriminant = parse_quote! {
            1 + #discriminant
        };

        acc
    })
}

fn enum_size(enum_name: &Ident, repr: &[syn::NestedMeta]) -> TokenStream2 {
    if is_repr(repr, "u8") {
        quote! {u8}
    } else if is_repr(repr, "u16") {
        quote! {u16}
    } else if is_repr(repr, "u32") {
        quote! {u32}
    } else if is_repr(repr, "u64") {
        quote! {u64}
    } else {
        abort!(enum_name, "Enum doesn't have a valid representation")
    }
}
