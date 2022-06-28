#![allow(clippy::str_to_string, missing_docs)]

use derive::gen_fns_from_derives;
use export::gen_ffi_fn;
use impl_visitor::ImplDescriptor;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_macro_input, parse_quote, visit_mut::VisitMut, Attribute, Ident, Item};

mod derive;
mod export;
mod impl_visitor;

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
                abort!(item.generics, "Generic structs not supported");
            }

            let ffi_fns = gen_fns_from_derives(&item);

            quote! {
                #item

                #( #ffi_fns )*
            }
        }
        item => abort!(item, "Item not supported"),
    }
    .into()
}

#[proc_macro_derive(IntoFfi)]
#[proc_macro_error::proc_macro_error]
pub fn into_ffi_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items supported");
    }

    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics not supported");
    }

    match input.data {
        syn::Data::Struct(_) => derive_into_ffi_for_struct(&input.ident, &input.attrs),
        syn::Data::Enum(item) => derive_into_ffi_for_enum(&input.ident, &item, &input.attrs),
        syn::Data::Union(item) => abort!(item.union_token, "Unions not supported"),
    }
    .into()
}

#[proc_macro_derive(TryFromFfi)]
#[proc_macro_error::proc_macro_error]
pub fn try_from_ffi_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items supported");
    }

    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics not supported");
    }

    match input.data {
        syn::Data::Struct(_) => derive_try_from_ffi_for_struct(&input.ident, &input.attrs),
        syn::Data::Enum(item) => derive_try_from_ffi_for_enum(&input.ident, &item, &input.attrs),
        syn::Data::Union(item) => abort!(item.union_token, "Unions not supported"),
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
        return gen_fieldless_enum_try_from_ffi(name, item);
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
        impl iroha_ffi::Opaque for #name {}

        impl iroha_ffi::OptionWrapped for #name {
            type FfiType = <Self as iroha_ffi::FfiType>::FfiType;
        }

        //impl<'store> iroha_ffi::FromOption<'store> for #name {
        //    type Store = <Self as iroha_ffi::IntoFfi>::Store;

        //    fn into_ffi(source: Option<Self>, store: &'store mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::OptionWrapped>::FfiType {
        //        source.map_or_else(core::ptr::null_mut, |item| iroha_ffi::IntoFfi::into_ffi(item, store))
        //    }
        //}
    }
}

fn derive_try_from_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    quote! {
    }
}

fn derive_into_ffi_for_item(name: &Ident) -> TokenStream2 {
    quote! {
        //impl iroha_ffi::IntoFfi for #name {
        //    type FfiType = Self;
        //    type Store = ();

        //    fn into_ffi(self, _: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        self
        //    }
        //}

        //impl iroha_ffi::IntoFfi for &#name {
        //    type FfiType = *const #name::FfiType;
        //    type Store = ();

        //    fn into_ffi(self, _: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        self as <Self as IntoFfi>::FfiType
        //    }
        //}

        //impl iroha_ffi::IntoFfi for &mut #name {
        //    type FfiType = *mut #name::FfiType;
        //    type Store = ();

        //    fn into_ffi(self, _: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        self as <Self as IntoFfi>::FfiType
        //    }
        //}

        //impl FromOption for #name {
        //    fn into_ffi(source: Option<Self>, store: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
        //    }
        //}

        //impl FromOption for &#name {
        //    fn into_ffi(source: Option<Self>, store: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        source.map_or_else(core::ptr::null, |item| IntoFfi::into_ffi(item, store))
        //    }
        //}

        //impl FromOption for &mut @name {
        //    fn into_ffi(source: Option<Self>, store: &mut <Self as IntoFfi>::Store) -> <Self as IntoFfi>::FfiType {
        //        source.map_or_else(core::ptr::null_mut, |item| IntoFfi::into_ffi(item, store))
        //    }
        //}

    };
    // TODO: Implementation is faulty
    unimplemented!("Difficult to implement");
}

fn derive_try_from_ffi_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        //impl iroha_ffi::TryFromFfi<'_> for #name {
        //    unsafe fn try_from_ffi(source: <Self as iroha_ffi::IntoFfi>::FfiType, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> Result<Self, iroha_ffi::FfiResult> {
        //        Ok(source)
        //    }
        //}

        //impl<'a> iroha_ffi::TryFromFfi<'_> for &'a #name {
        //    unsafe fn try_from_ffi(source: <Self as iroha_ffi::IntoFfi>::FfiType, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> Result<Self, iroha_ffi::FfiResult> {
        //        source.as_ref().ok_or(iroha_ffi::FfiResult::ArgIsNull)
        //    }
        //}

        //impl<'a> iroha_ffi::TryFromFfi<'_> for &'a mut #name {
        //    unsafe fn try_from_ffi(source: <Self as iroha_ffi::IntoFfi>::FfiType, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> Result<Self, iroha_ffi::FfiResult> {
        //        source.as_mut().ok_or(iroha_ffi::FfiResult::ArgIsNull)
        //    }
        //}
    };
    unimplemented!("Difficult to implement");
}

fn gen_fieldless_enum_into_ffi(enum_name: &Ident, repr: &[syn::NestedMeta]) -> TokenStream2 {
    let ffi_type = enum_size(enum_name, repr);

    quote! {
        impl iroha_ffi::FfiType for #enum_name {
            type FfiType = #ffi_type;
        }

        impl iroha_ffi::FfiRef for #enum_name {
            type FfiRef = *const #ffi_type;
            type FfiMut = *mut #ffi_type;
        }

        impl iroha_ffi::IntoFfi for #enum_name {
            fn into_ffi(self) -> <Self as iroha_ffi::FfiType>::FfiType {
                self as <Self as iroha_ffi::FfiType>::FfiType
            }
        }

        impl iroha_ffi::AsFfi for #enum_name {
            type Store = ();

            fn as_ffi_ref(&self, _: &mut <Self as iroha_ffi::AsFfi>::Store) -> Self::FfiRef {
                self as *const #enum_name as *const #ffi_type
            }
            fn as_ffi_mut(&mut self, _: &mut <Self as iroha_ffi::AsFfi>::Store) -> Self::FfiMut {
                self as *mut #enum_name as *mut #ffi_type
            }
        }

        impl iroha_ffi::OptionWrapped for #enum_name {
            type FfiType = *mut #ffi_type;
        }

        //impl<'store> iroha_ffi::FromOption<'store> for #enum_name {
        //    type Store = #ffi_type;

        //    // TODO: Rely on trap representation to represent None values
        //    fn into_ffi(source: Option<Self>, store: &'store mut <Self as iroha_ffi::FromOption<'store>>::Store) -> <Self as iroha_ffi::OptionWrapped>::FfiType {
        //        source.map_or_else(core::ptr::null_mut, |item| {
        //            *store = item as #ffi_type;
        //            iroha_ffi::IntoFfi::into_ffi(store, &mut ())
        //        })
        //    }
        //}
    }
}

fn gen_fieldless_enum_try_from_ffi(enum_name: &Ident, enum_: &syn::DataEnum) -> TokenStream2 {
    let variant_names: Vec<_> = enum_.variants.iter().map(|v| &v.ident).collect();
    let discriminant_values = variant_discriminants(enum_);

    let (discriminants, discriminant_names) =
        variant_names.iter().zip(discriminant_values.iter()).fold(
            <(Vec<_>, Vec<_>)>::default(),
            |mut acc, (variant_name, discriminant_value)| {
                let discriminant_name = Ident::new(
                    &format!("{}__{}", enum_name, variant_name).to_uppercase(),
                    proc_macro2::Span::call_site(),
                );

                acc.0.push(quote! {
                    const #discriminant_name: <#enum_name as iroha_ffi::FfiType>::FfiType = #discriminant_value;
                });
                acc.1.push(discriminant_name);

                acc
            },
        );

    quote! {
        impl iroha_ffi::TryFromFfi for #enum_name {
            unsafe fn try_from_ffi(source: <Self as iroha_ffi::FfiType>::FfiType) -> Result<Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                match source {
                    #( #discriminant_names => Ok(#enum_name::#variant_names), )*
                    // TODO: More appropriate error?
                    _ => Err(iroha_ffi::FfiResult::UnknownHandle),
                }
            }
        }

        impl iroha_ffi::TryAsRust for #enum_name {
            type Store = ();

            unsafe fn try_as_rust_ref(
                source: Self::FfiRef,
                _: &mut <Self as iroha_ffi::TryAsRust>::Store,
            ) -> Result<&Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                match *source.as_ref().ok_or(iroha_ffi::FfiResult::ArgIsNull)? {
                    #( | #discriminant_names )* => Ok(&*(source as *const #enum_name)),
                    // TODO: More appropriate error?
                    _ => Err(iroha_ffi::FfiResult::UnknownHandle),
                }
            }

            unsafe fn try_as_rust_mut(
                source: Self::FfiMut,
                _: &mut <Self as iroha_ffi::TryAsRust>::Store,
            ) -> Result<&mut Self, iroha_ffi::FfiResult> {
                #( #discriminants )*

                match *source.as_ref().ok_or(iroha_ffi::FfiResult::ArgIsNull)? {
                    #( | #discriminant_names )* => Ok(&mut *(source as *mut #enum_name)),
                    // TODO: More appropriate error?
                    _ => Err(iroha_ffi::FfiResult::UnknownHandle),
                }
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

fn get_ident(path: &syn::Path) -> &Ident {
    &path.segments.last().expect_or_abort("Defined").ident
}

/// Visitor for path types which replaces all occurrences of `Self` with a fully qualified type
struct SelfResolver<'ast> {
    self_ty: &'ast syn::Path,
}

impl<'ast> SelfResolver<'ast> {
    pub fn new(self_ty: &'ast syn::Path) -> Self {
        Self { self_ty }
    }
}

impl VisitMut for SelfResolver<'_> {
    fn visit_path_mut(&mut self, node: &mut syn::Path) {
        if node.leading_colon.is_some() {
            // NOTE: It's irrelevant
        }
        for segment in &mut node.segments {
            self.visit_path_arguments_mut(&mut segment.arguments);
        }

        if node.segments[0].ident == "Self" {
            let mut node_segments = self.self_ty.segments.clone();

            for segment in core::mem::take(&mut node.segments).into_iter().skip(1) {
                node_segments.push(segment);
            }

            node.segments = node_segments;
        }
    }
}
