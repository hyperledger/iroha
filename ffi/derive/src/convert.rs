use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{DeriveInput, Ident};

use crate::{find_attr, is_opaque};

pub fn derive_try_from_repr_c(input: &DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }
    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    match &input.data {
        syn::Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if enum_::is_fieldless_enum(item) {
                enum_::derive_try_from_repr_c_for_fieldless_enum(&input.ident, item, &repr)
            } else {
                enum_::derive_try_from_repr_c_for_data_carrying_enum(&input.ident, &item)
            }
        }
        syn::Data::Struct(_) => {
            if struct_::is_opaque_wrapper(input) {
                return struct_::derive_try_from_repr_c_for_opaque_struct_wrapper(&input.ident);
            }
            if is_opaque(input) {
                return struct_::derive_try_from_repr_c_for_opaque_struct(&input.ident);
            }

            derive_try_from_repr_c_for_item(&input.ident)
        }
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
}

pub fn derive_into_ffi(input: &DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }
    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    match &input.data {
        syn::Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if enum_::is_fieldless_enum(item) {
                enum_::derive_into_ffi_for_fieldless_enum(&input.ident, &repr)
            } else {
                enum_::derive_into_ffi_for_data_carrying_enum(&input.ident, &item)
            }
        }
        syn::Data::Struct(_) => {
            if struct_::is_opaque_wrapper(input) {
                return struct_::derive_into_ffi_for_opaque_struct_wrapper(&input.ident);
            }
            if is_opaque(input) {
                return struct_::derive_into_ffi_for_opaque_struct(&input.ident);
            }

            derive_into_ffi_for_item(&input.ident)
        }
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
}

fn derive_try_from_repr_c_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        // TODO:
    }
}

fn derive_into_ffi_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        // TODO:
    }
}

mod struct_ {
    use proc_macro2::TokenStream as TokenStream2;
    use quote::quote;
    use syn::{parse_quote, DeriveInput, Ident};

    pub fn derive_try_from_repr_c_for_opaque_struct_wrapper(name: &Ident) -> TokenStream2 {
        let opaque_struct_slice_try_from_repr_c_derive =
            derive_try_from_repr_c_for_opaque_struct_slice(name);
        let opaque_struct_vec_try_from_repr_c_derive =
            derive_try_from_repr_c_for_opaque_struct_vec(name);

        quote! {
            impl<'itm> iroha_ffi::TryFromReprC<'itm> for #name {
                type Source = *mut iroha_ffi::Opaque;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    if source.is_null() {
                        return Err(iroha_ffi::FfiReturn::ArgIsNull);
                    }

                    Ok(Self{__opaque_ptr: source})
                }
            }

            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #name {
                type Source = *const iroha_ffi::Opaque;
                type Store = Option<#name>;

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    store: &'itm mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    if source.is_null() {
                        return iroha_ffi::FfiReturn::ArgIsNull;
                    }

                    *store = Some(#name{__opaque_ptr: source});
                    store.as_ref().unwrap()
                }
            }

            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #name {
                type Source = *mut iroha_ffi::Opaque;
                type Store = Option<#name>;

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    store: &'itm mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    if source.is_null() {
                        return iroha_ffi::FfiReturn::ArgIsNull;
                    }

                    *store = Some(#name{__opaque_ptr: source});
                    store.as_mut().unwrap()
                }
            }

            #opaque_struct_slice_try_from_repr_c_derive
            #opaque_struct_vec_try_from_repr_c_derive
        }
    }

    pub fn derive_try_from_repr_c_for_opaque_struct(name: &Ident) -> TokenStream2 {
        let opaque_struct_slice_try_from_repr_c_derive =
            derive_try_from_repr_c_for_opaque_struct_slice(name);
        let opaque_struct_vec_try_from_repr_c_derive =
            derive_try_from_repr_c_for_opaque_struct_vec(name);

        quote! {
            impl<'itm> iroha_ffi::TryFromReprC<'itm> for #name {
                type Source = *mut Self;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    if source.is_null() {
                        return Err(iroha_ffi::FfiReturn::ArgIsNull);
                    }

                    Ok(*Box::from_raw(source))
                }
            }

            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #name {
                type Source = *const #name;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    source.as_ref().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
                }
            }

            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #name {
                type Source = *mut #name;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    source.as_mut().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
                }
            }

            #opaque_struct_slice_try_from_repr_c_derive
            #opaque_struct_vec_try_from_repr_c_derive
        }
    }

    fn derive_try_from_repr_c_for_opaque_struct_slice(name: &Ident) -> TokenStream2 {
        quote! {
            impl<'slice> iroha_ffi::slice::TryFromReprCSliceRef<'slice> for #name {
                type Source = iroha_ffi::slice::SliceRef<'slice, <&'slice Self as iroha_ffi::TryFromReprC<'slice>>::Source>;
                type Store = Vec<Self>;

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::slice::TryFromReprCSliceRef<'slice>>::Source,
                    store: &'slice mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'slice>>::Store
                ) -> iroha_ffi::Result<&'slice [Self]> {
                    let source = source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)?;

                    for elem in source {
                        store.push(Clone::clone(iroha_ffi::TryFromReprC::try_from_repr_c(*elem, &mut ())?));
                    }

                    Ok(store)
                }
            }
        }
    }

    fn derive_try_from_repr_c_for_opaque_struct_vec(name: &Ident) -> TokenStream2 {
        quote! {
            impl<'itm> iroha_ffi::owned::TryFromReprCVec<'itm> for #name {
                type Source = iroha_ffi::slice::SliceRef<'itm, <Self as iroha_ffi::TryFromReprC<'itm>>::Source>;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: Self::Source,
                    _: &'itm mut <Self as iroha_ffi::owned::TryFromReprCVec<'itm>>::Store,
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

    pub fn derive_into_ffi_for_opaque_struct_wrapper(name: &Ident) -> TokenStream2 {
        let opaque_struct_slice_into_ffi_derive = derive_into_ffi_for_opaque_struct_slice(name);
        let opaque_struct_vec_into_ffi_derive = derive_into_ffi_for_opaque_struct_vec(name);

        quote! {
            impl iroha_ffi::IntoFfi for #name {
                type Target = *mut iroha_ffi::Opaque;

                fn into_ffi(self) -> Self::Target {
                    core::mem::ManuallyDrop::new(self).__opaque_ptr
                }
            }

            impl iroha_ffi::IntoFfi for &#name {
                type Target = *const iroha_ffi::Opaque;

                fn into_ffi(self) -> Self::Target {
                    self.__opaque_ptr
                }
            }

            impl iroha_ffi::IntoFfi for &mut #name {
                type Target = *mut iroha_ffi::Opaque;

                fn into_ffi(self) -> Self::Target {
                    self.__opaque_ptr
                }
            }

            #opaque_struct_slice_into_ffi_derive
            #opaque_struct_vec_into_ffi_derive
        }
    }

    pub fn derive_into_ffi_for_opaque_struct(name: &Ident) -> TokenStream2 {
        let opaque_struct_slice_into_ffi_derive = derive_into_ffi_for_opaque_struct_slice(name);
        let opaque_struct_vec_into_ffi_derive = derive_into_ffi_for_opaque_struct_vec(name);

        quote! {
            impl iroha_ffi::IntoFfi for #name {
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

            #opaque_struct_slice_into_ffi_derive
            #opaque_struct_vec_into_ffi_derive
        }
    }

    fn derive_into_ffi_for_opaque_struct_slice(name: &Ident) -> TokenStream2 {
        quote! {
            impl<'slice> iroha_ffi::slice::IntoFfiSliceRef<'slice> for #name {
                type Target = iroha_ffi::owned::LocalSlice<<&'slice Self as IntoFfi>::Target>;

                fn into_ffi(source: &[Self]) -> Self::Target {
                    source.iter().map(iroha_ffi::IntoFfi::into_ffi).collect()
                }
            }
        }
    }

    fn derive_into_ffi_for_opaque_struct_vec(name: &Ident) -> TokenStream2 {
        quote! {
            impl iroha_ffi::owned::IntoFfiVec for #name {
                type Target = iroha_ffi::owned::LocalSlice<<#name as iroha_ffi::IntoFfi>::Target>;

                fn into_ffi(source: Vec<Self>) -> Self::Target {
                    source.into_iter().map(IntoFfi::into_ffi).collect()
                }
            }
        }
    }

    pub fn is_opaque_wrapper(input: &DeriveInput) -> bool {
        let opaque_attr = parse_quote! {#[opaque_wrapper]};
        input.attrs.iter().any(|a| *a == opaque_attr)
    }
}

mod enum_ {
    use std::str::FromStr as _;

    use proc_macro2::TokenStream as TokenStream2;
    use proc_macro_error::abort;
    use quote::quote;
    use syn::{parse_quote, Ident};

    pub fn derive_try_from_repr_c_for_fieldless_enum(
        enum_name: &Ident,
        enum_: &syn::DataEnum,
        repr: &[syn::NestedMeta],
    ) -> TokenStream2 {
        let tag_type = enum_size(enum_name, repr);

        let (discriminants, discriminant_decls) = gen_discriminants(enum_name, enum_, &tag_type);
        let variant_names: Vec<_> = enum_.variants.iter().map(|v| &v.ident).collect();

        quote! {
            impl<'itm> iroha_ffi::TryFromReprC<'itm> for #enum_name {
                type Source = <#tag_type as iroha_ffi::TryFromReprC<'itm>>::Source;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    store: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    let source: #tag_type = iroha_ffi::TryFromReprC::try_from_repr_c(source, store)?;

                    #( #discriminant_decls )*

                    match source {
                        #( #discriminants => Ok(#enum_name::#variant_names), )*
                        _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                    }
                }
            }
            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #enum_name {
                type Source = *const #tag_type;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    #( #discriminant_decls )*

                    unsafe { match *source {
                        #( | #discriminants )* => Ok(&*(source as *const _ as *const _)),
                        _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                    }}
                }
            }
            impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #enum_name {
                type Source = *mut #tag_type;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    #( #discriminant_decls )*

                    unsafe { match *source {
                        #( | #discriminants )* => Ok(&mut *(source as *mut _ as *mut _)),
                        _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                    }}
                }
            }

            impl<'slice> iroha_ffi::slice::TryFromReprCSliceRef<'slice> for #enum_name {
                type Source = iroha_ffi::slice::SliceRef<'slice, Self>;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::slice::TryFromReprCSliceRef<'slice>>::Source,
                    _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'slice>>::Store
                ) -> iroha_ffi::Result<&'slice [Self]> {
                    source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
                }
            }
            impl<'slice> iroha_ffi::slice::TryFromReprCSliceMut<'slice> for #enum_name {
                type Source = iroha_ffi::slice::SliceMut<'slice, #enum_name>;
                type Store = ();

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::slice::TryFromReprCSliceMut<'slice>>::Source,
                    _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceMut>::Store
                ) -> iroha_ffi::Result<&'slice mut [Self]> {
                    source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)
                }
            }
        }
    }

    pub fn derive_into_ffi_for_fieldless_enum(
        enum_name: &Ident,
        repr: &[syn::NestedMeta],
    ) -> TokenStream2 {
        let tag_type = enum_size(enum_name, repr);

        quote! {
            impl iroha_ffi::IntoFfi for #enum_name {
                type Target = <#tag_type as iroha_ffi::IntoFfi>::Target;

                fn into_ffi(self) -> Self::Target {
                    (self as #tag_type).into_ffi()
                }
            }

            impl iroha_ffi::IntoFfi for &#enum_name {
                type Target = *const #tag_type;

                fn into_ffi(self) -> Self::Target {
                    self as *const #enum_name as *const #tag_type
                }
            }

            impl iroha_ffi::IntoFfi for &mut #enum_name {
                type Target = *mut #tag_type;

                fn into_ffi(self) -> Self::Target {
                    self as *mut #enum_name as *mut #tag_type
                }
            }
        }
    }

    pub fn derive_try_from_repr_c_for_data_carrying_enum(
        enum_name: &Ident,
        enum_: &syn::DataEnum,
    ) -> TokenStream2 {
        let (repr_c_enum_name, repr_c_enum) = gen_repr_c_enum(enum_name, enum_, false);
        let tag_type = gen_enum_tag_type(enum_name, enum_);

        let enum_variants = enum_.variants.iter().enumerate().map(|(i, variant)| {
            let variant_name = &variant.ident;

            match &variant.fields {
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                    let idx = TokenStream2::from_str(&format!("{i}")).expect("Valid");

                    quote! {
                        #enum_name::#variant_name(iroha_ffi::TryFromReprC::<'itm>::try_from_repr_c(
                            core::mem::ManuallyDrop::into_inner(source.payload.#variant_name), &mut store.#idx
                        )?)
                    }
                }
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
                    abort!(unnamed, "Only 1-sized variants are supported")
                }
                syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
                    abort!(named, "Named variants are not supported")
                }
                syn::Fields::Unit => quote! {#enum_name::#variant_name},
            }
        });

        let store = enum_.variants.iter().map(|variant| match &variant.fields {
            syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                let variant_ty = &unnamed[0].ty;
                quote! {<#variant_ty as iroha_ffi::TryFromReprC<'itm>>::Store}
            }
            syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
                abort!(unnamed, "Only 1-sized variants are supported")
            }
            syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
                abort!(named, "Named variants are not supported")
            }
            syn::Fields::Unit => quote! {()},
        });

        let (discriminants, discriminant_decls) = gen_discriminants(enum_name, enum_, &tag_type);

        quote! {
            #repr_c_enum

            impl<'itm> iroha_ffi::TryFromReprC<'itm> for #enum_name {
                type Source = #repr_c_enum_name<'itm>;
                type Store = (#(#store),*);

                unsafe fn try_from_repr_c(
                    source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                    store: &'itm mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
                ) -> iroha_ffi::Result<Self> {
                    #( #discriminant_decls )*

                    match source.tag {
                        #( #discriminants => Ok(#enum_variants), )*
                        _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                    }
                }
            }
        }
    }

    pub fn derive_into_ffi_for_data_carrying_enum(
        enum_name: &Ident,
        enum_: &syn::DataEnum,
    ) -> TokenStream2 {
        let (repr_c_enum_name, repr_c_enum) = gen_repr_c_enum(enum_name, enum_, true);

        let enum_variants = enum_.variants.iter().enumerate().map(|(i, variant)| {
            let idx = TokenStream2::from_str(&format!("{i}")).expect("Valid");
            let variant_name = &variant.ident;

            match &variant.fields {
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                    let payload_name = gen_repr_c_enum_payload_name(enum_name, true);

                    quote! {
                        #enum_name::#variant_name(x) => {
                            let payload = #payload_name {
                                #variant_name: core::mem::ManuallyDrop::new(
                                    iroha_ffi::IntoFfi::into_ffi(x)
                                )
                            };

                            #repr_c_enum_name { tag: #idx, payload }
                        },
                    }
                }
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
                    abort!(unnamed, "Only 1-sized variants are supported")
                }
                syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
                    abort!(named, "Named variants are not supported")
                }
                syn::Fields::Unit => {
                    quote! { #enum_name::#variant_name => #repr_c_enum_name { tag: #idx }, }
                }
            }
        });

        quote! {
            #repr_c_enum

            impl iroha_ffi::IntoFfi for #enum_name {
                type Target = #repr_c_enum_name;

                fn into_ffi(self) -> Self::Target {
                    match self {
                        #(#enum_variants)*
                    }
                }
            }

            impl iroha_ffi::Output for #repr_c_enum_name {
                type OutPtr = *mut Self;
            }
        }
    }

    fn gen_discriminants(
        enum_name: &Ident,
        enum_: &syn::DataEnum,
        tag_type: &TokenStream2,
    ) -> (Vec<Ident>, Vec<TokenStream2>) {
        let variant_names: Vec<_> = enum_.variants.iter().map(|v| &v.ident).collect();
        let discriminant_values = variant_discriminants(enum_);

        variant_names.iter().zip(discriminant_values.iter()).fold(
            <(Vec<_>, Vec<_>)>::default(),
            |mut acc, (variant_name, discriminant_value)| {
                let discriminant_name = Ident::new(
                    &format!("{}__{}", enum_name, variant_name).to_uppercase(),
                    proc_macro2::Span::call_site(),
                );

                acc.1.push(quote! {
                    const #discriminant_name: #tag_type = #discriminant_value;
                });
                acc.0.push(discriminant_name);

                acc
            },
        )
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

    fn enum_size(enum_name: &syn::Ident, repr: &[syn::NestedMeta]) -> TokenStream2 {
        use crate::is_repr_attr;

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

    pub fn is_fieldless_enum(item: &syn::DataEnum) -> bool {
        !item
            .variants
            .iter()
            .any(|variant| !matches!(variant.fields, syn::Fields::Unit))
    }

    fn gen_repr_c_enum(
        enum_name: &syn::Ident,
        enum_: &syn::DataEnum,
        is_target: bool,
    ) -> (Ident, TokenStream2) {
        let (payload_name, payload) = gen_enum_payload(enum_name, &enum_, is_target);
        let repr_c_enum_name = gen_repr_c_enum_name(enum_name, is_target);
        let enum_tag_type = gen_enum_tag_type(enum_name, &enum_);

        let lifetime_param = if is_target {
            quote! {}
        } else {
            quote! { <'itm> }
        };

        let derives = if is_target {
            quote! {}
        } else {
            quote! {#[derive(Clone, Copy)]}
        };

        (
            repr_c_enum_name.clone(),
            quote! {
                #payload

                #derives
                #[repr(C)]
                #[allow(non_camel_case_types)]
                pub struct #repr_c_enum_name #lifetime_param {
                    tag: #enum_tag_type,
                    payload: #payload_name #lifetime_param,
                }

                unsafe impl #lifetime_param iroha_ffi::ReprC for #repr_c_enum_name #lifetime_param {}
            },
        )
    }

    fn gen_enum_payload(
        enum_name: &Ident,
        enum_: &syn::DataEnum,
        is_target: bool,
    ) -> (Ident, TokenStream2) {
        let payload_name = gen_repr_c_enum_payload_name(enum_name, is_target);

        let variants = enum_.variants.iter().map(|variant| {
            let variant_ident = &variant.ident;

            match &variant.fields {
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                    let variant_ty = &unnamed[0].ty;

                    if is_target {
                        quote! { #variant_ident: core::mem::ManuallyDrop<<#variant_ty as iroha_ffi::IntoFfi>::Target> }
                    } else {
                        quote! { #variant_ident: core::mem::ManuallyDrop<<#variant_ty as iroha_ffi::TryFromReprC<'itm>>::Source> }
                    }
                }
                syn::Fields::Unnamed(syn::FieldsUnnamed { unnamed, .. }) => {
                    abort!(unnamed, "Only 1-sized variants are supported")
                }
                syn::Fields::Named(syn::FieldsNamed { named, .. }) => {
                    abort!(named, "Named variants are not supported")
                }
                syn::Fields::Unit => quote! {}
            }
        });

        let lifetime_param = if is_target {
            quote! {}
        } else {
            quote! { <'itm> }
        };

        let derives = if is_target {
            quote! {}
        } else {
            quote! {#[derive(Clone, Copy)]}
        };

        (
            payload_name.clone(),
            quote! {
                #derives
                #[repr(C)]
                #[allow(non_snake_case)]
                #[allow(non_camel_case_types)]
                union #payload_name #lifetime_param {
                    #(#variants),*
                }
            },
        )
    }

    fn gen_enum_tag_type(enum_name: &syn::Ident, enum_: &syn::DataEnum) -> TokenStream2 {
        const U8_MAX: usize = u8::MAX as usize;
        const U16_MAX: usize = u16::MAX as usize;
        const U32_MAX: usize = u32::MAX as usize;

        // NOTE: Arms are matched in the order of declaration
        #[allow(overlapping_range_endpoints)]
        match enum_.variants.len() {
            0..=U8_MAX => quote! {u8},
            0..=U16_MAX => quote! {u16},
            0..=U32_MAX => quote! {u32},
            _ => abort!(enum_name, "Too many variants"),
        }
    }

    fn gen_repr_c_enum_name(enum_name: &Ident, is_target: bool) -> Ident {
        let target = if is_target {
            "IntoFfiTarget"
        } else {
            "TryFromReprCSource"
        };

        syn::Ident::new(
            &format!("__iroha_ffi__ReprC{}{}", enum_name, target),
            proc_macro2::Span::call_site(),
        )
    }

    fn gen_repr_c_enum_payload_name(enum_name: &Ident, is_target: bool) -> Ident {
        let target = if is_target {
            "IntoFfiTarget"
        } else {
            "TryFromReprCSource"
        };

        syn::Ident::new(
            &format!("__iroha_ffi__{}{}Payload", enum_name, target),
            proc_macro2::Span::call_site(),
        )
    }
}
