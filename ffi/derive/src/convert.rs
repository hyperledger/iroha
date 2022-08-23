use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident};

use crate::{enum_size, find_attr, is_fieldless_enum, is_opaque, is_repr_attr};

pub fn derive_try_from_repr_c(input: &DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }

    if is_opaque(input) {
        if is_opaque_wrapper(input) {
            return derive_try_from_repr_c_for_opaque_item_wrapper(input);
        }

        return derive_try_from_repr_c_for_opaque_item(input);
    }

    match &input.data {
        syn::Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if is_fieldless_enum(&input.ident, item, &repr) {
                derive_try_from_repr_c_for_fieldless_enum(&input.ident, item, &repr)
            } else {
                derive_try_from_repr_c_for_item(&input.ident)
            }
        }
        syn::Data::Struct(item) => {
            if is_transparent(input) {
                derive_try_from_repr_c_for_transparent_item(&input.ident, &input.generics, item)
            } else {
                derive_try_from_repr_c_for_item(&input.ident)
            }
        }
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
}

pub fn derive_into_ffi(input: &DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }

    if is_opaque(input) {
        if is_opaque_wrapper(input) {
            return derive_into_ffi_for_opaque_item_wrapper(input);
        }

        return derive_into_ffi_for_opaque_item(input);
    }

    match &input.data {
        syn::Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if is_fieldless_enum(&input.ident, item, &repr) {
                derive_into_ffi_for_fieldless_enum(&input.ident, &repr)
            } else {
                derive_into_ffi_for_item(&input.ident)
            }
        }
        syn::Data::Struct(item) => {
            if is_transparent(input) {
                derive_into_ffi_for_transparent_item(&input.ident, &input.generics, item)
            } else {
                derive_into_ffi_for_item(&input.ident)
            }
        }
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
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

fn derive_try_from_repr_c_for_opaque_item_wrapper(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let lifetimes = &[lifetime.clone()];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, &[], &[]);

    let opaque_item_slice_try_from_repr_c_derive =
        derive_try_from_repr_c_for_opaque_item_slice(input);
    let opaque_item_vec_try_from_repr_c_derive = derive_try_from_repr_c_for_opaque_item_vec(input);

    quote! {
        impl #generic_params iroha_ffi::TryFromReprC<#lifetime> for #name #ty_generics #where_clause {
            type Source = *mut iroha_ffi::Opaque;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(Self{__opaque_ptr: source})
            }
        }

        impl #generic_params iroha_ffi::TryFromReprC<#lifetime> for &#lifetime #name #ty_generics #where_clause {
            type Source = *const iroha_ffi::Opaque;
            type Store = Option<#name>;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return iroha_ffi::FfiReturn::ArgIsNull;
                }

                *store = Some(#name{__opaque_ptr: source});
                store.as_ref().unwrap()
            }
        }

        impl #generic_params iroha_ffi::TryFromReprC<#lifetime> for &#lifetime mut #name #ty_generics #where_clause {
            type Source = *mut iroha_ffi::Opaque;
            type Store = Option<#name>;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return iroha_ffi::FfiReturn::ArgIsNull;
                }

                *store = Some(#name{__opaque_ptr: source});
                store.as_mut().unwrap()
            }
        }

        #opaque_item_slice_try_from_repr_c_derive
        #opaque_item_vec_try_from_repr_c_derive
    }
}

fn derive_try_from_repr_c_for_opaque_item(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let lifetimes = &[lifetime.clone()];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, &[], &[]);

    let opaque_item_slice_try_from_repr_c_derive =
        derive_try_from_repr_c_for_opaque_item_slice(input);
    let opaque_item_vec_try_from_repr_c_derive = derive_try_from_repr_c_for_opaque_item_vec(input);

    quote! {
        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for #name #ty_generics #where_clause {
            type Source = *mut Self;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(*Box::from_raw(source))
            }
        }

        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for &#lifetime #name #ty_generics #where_clause {
            type Source = *const #name #ty_generics;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                source.as_ref().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
            }
        }

        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for &#lifetime mut #name #ty_generics #where_clause {
            type Source = *mut #name #ty_generics;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                source.as_mut().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
            }
        }

        #opaque_item_slice_try_from_repr_c_derive
        #opaque_item_vec_try_from_repr_c_derive
    }
}

fn derive_try_from_repr_c_for_opaque_item_slice(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_slice);
    let lifetimes = &[lifetime.clone()];
    let trait_bounds = &[syn::parse_quote!(core::clone::Clone)];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, &[], trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::slice::TryFromReprCSliceRef<#lifetime> for #name #ty_generics #where_clause {
            type Source = iroha_ffi::slice::SliceRef<#lifetime, <&#lifetime Self as iroha_ffi::TryFromReprC<#lifetime>>::Source>;
            type Store = Vec<Self>;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>>::Store
            ) -> iroha_ffi::Result<&#lifetime [Self]> {
                let source = source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)?;

                for elem in source {
                    store.push(Clone::clone(iroha_ffi::TryFromReprC::try_from_repr_c(*elem, &mut ())?));
                }

                Ok(store)
            }
        }
    }
}

fn derive_try_from_repr_c_for_opaque_item_vec(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let lifetimes = &[lifetime.clone()];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, &[], &[]);

    quote! {
        impl<#generic_params> iroha_ffi::owned::TryFromReprCVec<#lifetime> for #name #ty_generics #where_clause {
            type Source = iroha_ffi::slice::SliceRef<#lifetime, <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source>;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: Self::Source,
                _: &#lifetime mut <Self as iroha_ffi::owned::TryFromReprCVec<#lifetime>>::Store,
            ) -> iroha_ffi::Result<Vec<Self>> {
                let slice = source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)?;
                let mut res = Vec::with_capacity(slice.len());

                for elem in slice {
                    res.push(iroha_ffi::TryFromReprC::try_from_repr_c(*elem, &mut ())?);
                }

                Ok(res)
            }
        }
    }
}

fn derive_try_from_repr_c_for_transparent_item(
    name: &Ident,
    generics: &syn::Generics,
    item: &syn::DataStruct,
) -> TokenStream2 {
    let transparent = derive_transparent(name, generics, item);
    let try_from_repr_c_transparent_slice =
        derive_try_from_repr_c_transparent_item_slice(name, generics);
    let try_from_repr_c_transparent_vec =
        derive_try_from_repr_c_transparent_item_vec(name, generics);

    let mut generics = generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let lifetimes = &[lifetime.clone()];
    let types = &[syn::parse_quote!(__iroha_ffi_T: iroha_ffi::TryFromReprC<#lifetime>)];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::Transparent<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, types, self_trait_bounds);

    quote! {
        #transparent

        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for #name #ty_generics #where_clause {
            type Source = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Source;
            type Store = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Store;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                let inner = unsafe { iroha_ffi::TryFromReprC::try_from_repr_c(source, store)? };
                Ok(<Self as iroha_ffi::Transparent>::from_inner(inner))
            }
        }

        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for &#lifetime #name #ty_generics #where_clause {
            type Source = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Source;
            type Store = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Store;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                let inner = unsafe { iroha_ffi::TryFromReprC::try_from_repr_c(source, store)? };
                Ok(<Self as iroha_ffi::Transparent>::from_inner(inner))
            }

        }

        impl<#generic_params> iroha_ffi::TryFromReprC<#lifetime> for &#lifetime mut #name #ty_generics #where_clause {
            type Source = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Source;
            type Store = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::TryFromReprC<#lifetime>>::Store;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<Self> {
                let inner = unsafe { iroha_ffi::TryFromReprC::try_from_repr_c(source, store)? };
                Ok(<Self as iroha_ffi::Transparent>::from_inner(inner))
            }
        }

        #try_from_repr_c_transparent_slice
        #try_from_repr_c_transparent_vec
    }
}

fn derive_try_from_repr_c_transparent_item_slice(
    name: &Ident,
    generics: &syn::Generics,
) -> TokenStream2 {
    let mut generics = generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_slice);
    let lifetimes = &[lifetime.clone()];
    let types =
        &[syn::parse_quote!(__iroha_ffi_T: iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>)];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::TransparentVec<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, types, self_trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::slice::TryFromReprCSliceRef<#lifetime> for #name #ty_generics #where_clause {
            type Source = <<Self as iroha_ffi::TransparentSlice>::Inner as iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>>::Source;
            type Store = <<Self as iroha_ffi::TransparentSlice>::Inner as iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>>::Store;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::slice::TryFromReprCSliceRef<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::TryFromReprC<#lifetime>>::Store
            ) -> iroha_ffi::Result<&#lifetime [Self]> {
                let inner = unsafe { iroha_ffi::slice::TryFromReprCSliceRef::try_from_repr_c(source, store)? };
                Ok(<Self as iroha_ffi::TransparentSlice>::from_inner(inner))
            }
        }
    }
}

fn derive_try_from_repr_c_transparent_item_vec(
    name: &Ident,
    generics: &syn::Generics,
) -> TokenStream2 {
    let mut generics = generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let lifetimes = &[lifetime.clone()];
    let types = &[syn::parse_quote!(__iroha_ffi_T: iroha_ffi::owned::TryFromReprCVec<#lifetime>)];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::TransparentVec<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, types, self_trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::owned::TryFromReprCVec<#lifetime> for #name #ty_generics #where_clause {
            type Source = <<Self as iroha_ffi::TransparentVec>::Inner as iroha_ffi::owned::TryFromReprCVec<#lifetime>>::Source;
            type Store = <<Self as iroha_ffi::TransparentVec>::Inner as iroha_ffi::owned::TryFromReprCVec<#lifetime>>::Store;

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::owned::TryFromReprCVec<#lifetime>>::Source,
                store: &#lifetime mut <Self as iroha_ffi::owned::TryFromReprCVec<#lifetime>>::Store
            ) -> iroha_ffi::Result<Vec<Self>> {
                let inner = unsafe { iroha_ffi::owned::TryFromReprCVec::try_from_repr_c(source, store)? };
                Ok(<Self as iroha_ffi::TransparentVec>::from_inner(inner))
            }
        }
    }
}

fn derive_try_from_repr_c_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        // TODO:
    }
}

fn derive_try_from_repr_c_for_fieldless_enum(
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
        impl<'__iroha_ffi_itm> iroha_ffi::TryFromReprC<'__iroha_ffi_itm> for #enum_name {
            type Source = <#ffi_type as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Source;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Source,
                store: &mut <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                let source: #ffi_type = iroha_ffi::TryFromReprC::try_from_repr_c(source, store)?;

                match source {
                    #( #discriminant_names => Ok(#enum_name::#variant_names), )*
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }
            }
        }
        impl<'__iroha_ffi_itm> iroha_ffi::TryFromReprC<'__iroha_ffi_itm> for &'__iroha_ffi_itm #enum_name {
            type Source = *const #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&*(source as *const _ as *const _)),
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }}
            }
        }
        impl<'__iroha_ffi_itm> iroha_ffi::TryFromReprC<'__iroha_ffi_itm> for &'__iroha_ffi_itm mut #enum_name {
            type Source = *mut #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<'__iroha_ffi_itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&mut *(source as *mut _ as *mut _)),
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }}
            }
        }

        impl<'__iroha_ffi_slice> iroha_ffi::slice::TryFromReprCSliceRef<'__iroha_ffi_slice> for #enum_name {
            type Source = iroha_ffi::slice::SliceRef<'__iroha_ffi_slice, Self>;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::slice::TryFromReprCSliceRef<'__iroha_ffi_slice>>::Source,
                _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'__iroha_ffi_slice>>::Store
            ) -> iroha_ffi::Result<&'__iroha_ffi_slice [Self]> {
                source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
            }
        }
        impl<'__iroha_ffi_slice> iroha_ffi::slice::TryFromReprCSliceMut<'__iroha_ffi_slice> for #enum_name {
            type Source = iroha_ffi::slice::SliceMut<'__iroha_ffi_slice, #enum_name>;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::slice::TryFromReprCSliceMut<'__iroha_ffi_slice>>::Source,
                _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceMut>::Store
            ) -> iroha_ffi::Result<&'__iroha_ffi_slice mut [Self]> {
                source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
            }
        }
    }
}

fn derive_into_ffi_for_opaque_item_wrapper(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let opaque_item_slice_into_ffi_derive = derive_into_ffi_for_opaque_item_slice(input);
    let opaque_item_vec_into_ffi_derive = derive_into_ffi_for_opaque_item_vec(input);

    let (impl_generics, ty_generics, where_clause) = &input.generics.split_for_impl();

    quote! {
        impl #impl_generics iroha_ffi::IntoFfi for #name #ty_generics #where_clause {
            type Target = *mut iroha_ffi::Opaque;

            fn into_ffi(self) -> Self::Target {
                core::mem::ManuallyDrop::new(self).__opaque_ptr
            }
        }

        impl #impl_generics iroha_ffi::IntoFfi for &#name #ty_generics #where_clause {
            type Target = *const iroha_ffi::Opaque;

            fn into_ffi(self) -> Self::Target {
                self.__opaque_ptr
            }
        }

        impl #impl_generics iroha_ffi::IntoFfi for &mut #name #ty_generics #where_clause {
            type Target = *mut iroha_ffi::Opaque;

            fn into_ffi(self) -> Self::Target {
                self.__opaque_ptr
            }
        }

        #opaque_item_slice_into_ffi_derive
        #opaque_item_vec_into_ffi_derive
    }
}

fn derive_into_ffi_for_opaque_item(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let opaque_item_slice_into_ffi_derive = derive_into_ffi_for_opaque_item_slice(input);
    let opaque_item_vec_into_ffi_derive = derive_into_ffi_for_opaque_item_vec(input);

    let (impl_generics, ty_generics, where_clause) = &input.generics.split_for_impl();

    quote! {
        impl #impl_generics iroha_ffi::IntoFfi for #name #ty_generics #where_clause {
            type Target = *mut Self;

            fn into_ffi(self) -> Self::Target {
                let layout = core::alloc::Layout::for_value(&self);

                unsafe {
                    let ptr: Self::Target = alloc(layout).cast();
                    ptr.write(self);
                    ptr
                }
            }
        }

        impl #impl_generics iroha_ffi::IntoFfi for &#name #ty_generics #where_clause {
            type Target = *const #name #ty_generics;

            fn into_ffi(self) -> Self::Target {
                <*const _>::from(self)
            }
        }

        impl #impl_generics iroha_ffi::IntoFfi for &mut #name #ty_generics #where_clause {
            type Target = *mut #name #ty_generics;

            fn into_ffi(self) -> Self::Target {
                <*mut _>::from(self)
            }
        }

        #opaque_item_slice_into_ffi_derive
        #opaque_item_vec_into_ffi_derive
    }
}

fn derive_into_ffi_for_opaque_item_slice(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_slice);
    let lifetimes = &[lifetime.clone()];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, &[], &[]);

    quote! {
        impl<#generic_params> iroha_ffi::slice::IntoFfiSliceRef<#lifetime> for #name #ty_generics #where_clause {
            type Target = iroha_ffi::owned::LocalSlice<<&#lifetime Self as IntoFfi>::Target>;

            fn into_ffi(source: &[Self]) -> Self::Target {
                source.iter().map(iroha_ffi::IntoFfi::into_ffi).collect()
            }
        }
    }
}

fn derive_into_ffi_for_opaque_item_vec(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = &input.generics.split_for_impl();

    quote! {
        impl #impl_generics iroha_ffi::owned::IntoFfiVec for #name #ty_generics #where_clause {
            type Target = iroha_ffi::owned::LocalSlice<<Self as iroha_ffi::IntoFfi>::Target>;

            fn into_ffi(source: Vec<Self>) -> Self::Target {
                source.into_iter().map(IntoFfi::into_ffi).collect()
            }
        }
    }
}

fn derive_into_ffi_for_transparent_item(
    name: &Ident,
    generics: &syn::Generics,
    _: &syn::DataStruct,
) -> TokenStream2 {
    let into_ffi_transparent_slice = derive_into_ffi_transparent_item_slice(name, generics);
    let into_ffi_transparent_vec = derive_into_ffi_transparent_item_vec(name, generics);

    let mut generics = generics.clone();
    let types = &[syn::parse_quote!(__iroha_ffi_T: iroha_ffi::IntoFfi)];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::Transparent<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, &[], types, self_trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::IntoFfi for #name #ty_generics #where_clause {
            type Target = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::IntoFfi>::Target;

            fn into_ffi(self) -> Self::Target {
                let inner = <Self as iroha_ffi::Transparent>::into_inner(self);
                iroha_ffi::IntoFfi::into_ffi(inner)
            }
        }

        impl<#generic_params> iroha_ffi::IntoFfi for &#name #ty_generics #where_clause {
            type Target = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::IntoFfi>::Target;

            fn into_ffi(self) -> Self::Target {
                let inner = <Self as iroha_ffi::Transparent>::into_inner(self);
                iroha_ffi::IntoFfi::into_ffi(inner)
            }
        }

        impl<#generic_params> iroha_ffi::IntoFfi for &mut #name #ty_generics #where_clause {
            type Target = <<Self as iroha_ffi::Transparent>::Inner as iroha_ffi::IntoFfi>::Target;

            fn into_ffi(self) -> Self::Target {
                let inner = <Self as iroha_ffi::Transparent>::into_inner(self);
                iroha_ffi::IntoFfi::into_ffi(inner)
            }
        }

        #into_ffi_transparent_slice
        #into_ffi_transparent_vec
    }
}

fn derive_into_ffi_transparent_item_slice(name: &Ident, generics: &syn::Generics) -> TokenStream2 {
    let mut generics = generics.clone();
    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_slice);
    let lifetimes = &[lifetime.clone()];
    let types = &[syn::parse_quote!(__iroha_ffi_T: iroha_ffi::slice::IntoFfiSliceRef<#lifetime>)];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::TransparentVec<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, lifetimes, types, self_trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::slice::IntoFfiSliceRef<#lifetime> for #name #ty_generics #where_clause {
            type Target = <<Self as iroha_ffi::TransparentSlice>::Inner as iroha_ffi::slice::IntoFfiSliceRef<#lifetime>>::Target;

            fn into_ffi(outer: &#lifetime [Self]) -> <Self as iroha_ffi::slice::IntoFfiSliceRef>::Target {
                let inner = <Self as iroha_ffi::TransparentSlice>::into_inner(outer);
                iroha_ffi::slice::IntoFfiSliceRef::into_ffi(inner)
            }
        }
    }
}

fn derive_into_ffi_transparent_item_vec(name: &Ident, generics: &syn::Generics) -> TokenStream2 {
    let mut generics = generics.clone();
    let types = &[syn::parse_quote!(
        __iroha_ffi_T: iroha_ffi::owned::IntoFfiVec
    )];
    let self_trait_bounds = &[syn::parse_quote!(
        iroha_ffi::TransparentVec<Inner = __iroha_ffi_T>
    )];
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, &[], types, self_trait_bounds);

    quote! {
        impl<#generic_params> iroha_ffi::owned::IntoFfiVec for #name #ty_generics #where_clause {
            type Target = <<Self as iroha_ffi::TransparentVec>::Inner as iroha_ffi::owned::IntoFfiVec>::Target;

            fn into_ffi(outer: Vec<Self>) -> <Self as iroha_ffi::owned::IntoFfiVec>::Target {
                let inner = <Self as iroha_ffi::TransparentVec>::into_inner(outer);
                iroha_ffi::owned::IntoFfiVec::into_ffi(inner)
            }
        }
    }
}

fn derive_into_ffi_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        // TODO:
    }
}

fn derive_into_ffi_for_fieldless_enum(enum_name: &Ident, repr: &[syn::NestedMeta]) -> TokenStream2 {
    let ffi_type = enum_size(enum_name, repr);

    quote! {
        impl iroha_ffi::IntoFfi for #enum_name {
            type Target = <#ffi_type as iroha_ffi::IntoFfi>::Target;

            fn into_ffi(self) -> Self::Target {
                (self as #ffi_type).into_ffi()
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

fn derive_transparent(
    name: &Ident,
    generics: &syn::Generics,
    item: &syn::DataStruct,
) -> TokenStream2 {
    let inner = item
        .fields
        .iter()
        .next()
        .map(|field| &field.ty)
        .expect_or_abort("transparent struct must have at least one field");

    let lifetime: syn::Lifetime = syn::parse_quote!('__iroha_ffi_itm);
    let mut generics = generics.clone();
    let (generic_params, ty_generics, where_clause) =
        add_bounds_and_split_generics(&mut generics, &[], &[], &[]);

    quote! {
        // Note: if `#inner` is generic or doesn't have the same layout with `#name` this won't compile
        // SAFETY: `Self` and `Self::Inner` have the same size because from macro generation `Self::Inner` is the inner field of transparent `Self` with the same size.
        unsafe impl <#generic_params> iroha_ffi::Transparent for #name #ty_generics #where_clause {
            type Inner = #inner;

            fn into_inner(outer: Self) -> Self::Inner {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { core::mem::transmute(outer) }
            }

            fn from_inner(inner: Self::Inner) -> Self {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { core::mem::transmute(inner) }
            }
        }

        unsafe impl <#lifetime, #generic_params> iroha_ffi::Transparent for &#lifetime #name #ty_generics #where_clause {
            type Inner = &#lifetime #inner;

            fn into_inner(outer: Self) -> Self::Inner {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { & *(outer as *const _ as *const _) }
            }

            fn from_inner(inner: Self::Inner) -> Self {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { & *(inner as *const _ as *const _) }
            }
        }

        unsafe impl <#lifetime, #generic_params> iroha_ffi::Transparent for &#lifetime mut #name #ty_generics #where_clause {
            type Inner = &#lifetime mut #inner;

            fn into_inner(outer: Self) -> Self::Inner {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { &mut *(outer as *mut _ as *mut _) }
            }

            fn from_inner(inner: Self::Inner) -> Self {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { &mut *(inner as *mut _ as *mut _) }
            }
        }

        unsafe impl <#generic_params> iroha_ffi::TransparentSlice for #name #ty_generics #where_clause {
            type Inner = #inner;

            fn into_inner(outer: &[Self]) -> &[Self::Inner] {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { core::mem::transmute(outer) }
            }

            fn from_inner(inner: &[Self::Inner]) -> &[Self] {
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe { core::mem::transmute(inner) }
            }
        }

        unsafe impl <#generic_params> iroha_ffi::TransparentVec for #name #ty_generics #where_clause {
            type Inner = #inner;

            fn into_inner(outer: Vec<Self>) -> Vec<Self::Inner> {
                let mut outer = core::mem::ManuallyDrop::new(outer);
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe {
                    Vec::from_raw_parts(
                        outer.as_mut_ptr() as *mut _,
                        outer.len(),
                        outer.capacity()
                    )
                }
            }

            fn from_inner(inner: Vec<Self::Inner>) -> Vec<Self> {
                let mut inner = core::mem::ManuallyDrop::new(inner);
                // SAFETY: `Self` and `Self::Inner` have the same memory layout
                unsafe {
                    Vec::from_raw_parts(
                        inner.as_mut_ptr() as *mut _,
                        inner.len(),
                        inner.capacity()
                    )
                }
            }
        }
    }
}

fn is_opaque_wrapper(input: &DeriveInput) -> bool {
    let opaque_attr = parse_quote! {#[opaque_wrapper]};
    input.attrs.iter().any(|a| *a == opaque_attr)
}

fn is_transparent(input: &DeriveInput) -> bool {
    let repr = &find_attr(&input.attrs, "repr");
    is_repr_attr(repr, "transparent")
}

fn add_bounds_and_split_generics<'generics>(
    generics: &'generics mut syn::Generics,
    lifetimes: &'generics [syn::Lifetime],
    types: &'generics [syn::TypeParam],
    self_trait_bounds: &'generics [syn::TraitBound],
) -> (
    syn::punctuated::Punctuated<syn::GenericParam, syn::Token![,]>,
    syn::TypeGenerics<'generics>,
    Option<&'generics syn::WhereClause>,
) {
    let where_predicate: syn::WherePredicate =
        syn::parse_quote!(Self: #(#lifetimes +)* #(#self_trait_bounds)+*);
    generics
        .make_where_clause()
        .predicates
        .push(where_predicate);
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    let params = &generics.params;
    // NOTE: Put lifetimes first
    let generic_params = syn::parse_quote!(#(#lifetimes,)* #(#types,)* #params);
    (generic_params, ty_generics, where_clause)
}
