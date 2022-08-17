use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident};

use crate::{enum_size, find_attr, is_fieldless_enum, is_opaque};

pub fn derive_try_from_repr_c(input: &DeriveInput) -> TokenStream2 {
    if !matches!(input.vis, syn::Visibility::Public(_)) {
        abort!(input.vis, "Only public items are supported");
    }
    if !input.generics.params.is_empty() {
        abort!(input.generics, "Generics are not supported");
    }

    if is_opaque(input) {
        if is_opaque_wrapper(input) {
            return derive_try_from_repr_c_for_opaque_item_wrapper(&input.ident);
        }

        return derive_try_from_repr_c_for_opaque_item(&input.ident);
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
        syn::Data::Struct(_) => derive_try_from_repr_c_for_item(&input.ident),
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

    if is_opaque(input) {
        if is_opaque_wrapper(input) {
            return derive_into_ffi_for_opaque_item_wrapper(&input.ident);
        }

        return derive_into_ffi_for_opaque_item(&input.ident);
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
        syn::Data::Struct(_) => derive_into_ffi_for_item(&input.ident),
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

fn derive_try_from_repr_c_for_opaque_item_wrapper(name: &Ident) -> TokenStream2 {
    let opaque_item_slice_try_from_repr_c_derive =
        derive_try_from_repr_c_for_opaque_item_slice(name);
    let opaque_item_vec_try_from_repr_c_derive = derive_try_from_repr_c_for_opaque_item_vec(name);

    quote! {
        unsafe impl iroha_ffi::NonLocal for #name {}

        impl iroha_ffi::FfiType for #name {
            type ReprC = *mut iroha_ffi::Opaque;
        }
        impl iroha_ffi::FfiType for &#name {
            type ReprC = *const iroha_ffi::Opaque;
        }
        impl iroha_ffi::FfiType for &mut #name {
            type ReprC = *mut iroha_ffi::Opaque;
        }

        impl<'itm> iroha_ffi::TryFromReprC<'itm> for #name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::FfiType>::ReprC,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(Self{__opaque_ptr: source})
            }
        }

        #opaque_item_slice_try_from_repr_c_derive
        #opaque_item_vec_try_from_repr_c_derive
    }
}

fn derive_try_from_repr_c_for_opaque_item(name: &Ident) -> TokenStream2 {
    let opaque_item_slice_try_from_repr_c_derive =
        derive_try_from_repr_c_for_opaque_item_slice(name);
    let opaque_item_vec_try_from_repr_c_derive = derive_try_from_repr_c_for_opaque_item_vec(name);

    quote! {
        unsafe impl iroha_ffi::NonLocal for #name {}

        impl iroha_ffi::FfiType for #name {
            type ReprC = *mut Self;
        }
        impl iroha_ffi::FfiType for &#name {
            type ReprC = *const #name;
        }
        impl iroha_ffi::FfiType for &mut #name {
            type ReprC = *mut #name;
        }

        impl<'itm> iroha_ffi::TryFromReprC<'itm> for #name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::FfiType>::ReprC,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(*Box::from_raw(source))
            }
        }

        #opaque_item_slice_try_from_repr_c_derive
        #opaque_item_vec_try_from_repr_c_derive
    }
}

fn derive_try_from_repr_c_for_opaque_item_slice(name: &Ident) -> TokenStream2 {
    quote! {
        impl iroha_ffi::slice::FfiSliceRef for #name {
            type ReprC = *const #name;
        }

        impl<'slice> iroha_ffi::slice::TryFromReprCSliceRef<'slice> for #name {
            type Store = Vec<Self>;

            unsafe fn try_from_repr_c(
                source: iroha_ffi::slice::SliceRef<<Self as iroha_ffi::slice::FfiSliceRef>::ReprC>,
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

fn derive_try_from_repr_c_for_opaque_item_vec(name: &Ident) -> TokenStream2 {
    quote! {
        impl iroha_ffi::owned::FfiVec for #name {
            type ReprC = *mut Self;
        }
        impl iroha_ffi::owned::FfiVec for &#name {
            type ReprC = *const #name;
        }

        impl<'itm> iroha_ffi::owned::TryFromReprCVec<'itm> for #name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: iroha_ffi::Local<iroha_ffi::slice::SliceRef<<Self as iroha_ffi::owned::FfiVec>::ReprC>>,
                _: &'itm mut <Self as iroha_ffi::owned::TryFromReprCVec<'itm>>::Store,
            ) -> iroha_ffi::Result<Vec<Self>> {
                let slice = source.0.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)?;
                let mut res = Vec::with_capacity(slice.len());

                for elem in slice {
                    res.push(iroha_ffi::TryFromReprC::try_from_repr_c(*elem, &mut ())?);
                }

                Ok(res)
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
        unsafe impl iroha_ffi::NonLocal for #enum_name {}

        impl iroha_ffi::FfiType for #enum_name {
            type ReprC = <#ffi_type as iroha_ffi::FfiType>::ReprC;
        }
        impl iroha_ffi::FfiType for &#enum_name {
            type ReprC = *const #ffi_type;
        }
        impl iroha_ffi::FfiType for &mut #enum_name {
            type ReprC = *mut #ffi_type;
        }
        impl iroha_ffi::slice::FfiSliceRef for #enum_name {
            type ReprC = #ffi_type;
        }

        impl<'itm> iroha_ffi::TryFromReprC<'itm> for #enum_name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::FfiType>::ReprC,
                store: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                match iroha_ffi::TryFromReprC::try_from_repr_c(source, store)? {
                    #( #discriminant_names => Ok(#enum_name::#variant_names), )*
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #enum_name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::FfiType>::ReprC,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                match *source {
                    #( | #discriminant_names )* => Ok(&*(source as *const _ as *const _)),
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #enum_name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::FfiType>::ReprC,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                match *source {
                    #( | #discriminant_names )* => Ok(&mut *(source as *mut _ as *mut _)),
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }
            }
        }

        impl<'slice> iroha_ffi::slice::TryFromReprCSliceRef<'slice> for #enum_name {
            type Store = ();

            unsafe fn try_from_repr_c(
                source: iroha_ffi::slice::SliceRef<<Self as iroha_ffi::slice::FfiSliceRef>::ReprC>,
                _: &mut <Self as iroha_ffi::slice::TryFromReprCSliceRef<'slice>>::Store
            ) -> iroha_ffi::Result<&'slice [Self]> {
                let source = source.into_rust().ok_or(iroha_ffi::FfiReturn::ArgIsNull)?;

                #( #discriminants )*
                for item in source {
                    match *item {
                        #(| #discriminant_names )* => {},
                        _ => return Err(iroha_ffi::FfiReturn::TrapRepresentation),
                    }
                }

                Ok(&*(source as *const [#ffi_type] as *const [#enum_name]))
            }
        }
    }
}

fn derive_into_ffi_for_opaque_item_wrapper(name: &Ident) -> TokenStream2 {
    let opaque_item_slice_into_ffi_derive = derive_into_ffi_for_opaque_item_slice(name);
    let opaque_item_vec_into_ffi_derive = derive_into_ffi_for_opaque_item_vec(name);

    quote! {
        impl iroha_ffi::IntoFfi for #name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                core::mem::ManuallyDrop::new(self).__opaque_ptr
            }
        }
        impl iroha_ffi::IntoFfi for &#name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                self.__opaque_ptr
            }
        }
        impl iroha_ffi::IntoFfi for &mut #name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                self.__opaque_ptr
            }
        }

        #opaque_item_slice_into_ffi_derive
        #opaque_item_vec_into_ffi_derive
    }
}

fn derive_into_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    let opaque_item_slice_into_ffi_derive = derive_into_ffi_for_opaque_item_slice(name);
    let opaque_item_vec_into_ffi_derive = derive_into_ffi_for_opaque_item_vec(name);

    quote! {
        impl iroha_ffi::IntoFfi for #name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                let layout = core::alloc::Layout::for_value(&self);

                unsafe {
                    let ptr: <Self as iroha_ffi::FfiType>::ReprC = alloc(layout).cast();
                    ptr.write(self);
                    ptr
                }
            }
        }

        #opaque_item_slice_into_ffi_derive
        #opaque_item_vec_into_ffi_derive
    }
}

fn derive_into_ffi_for_opaque_item_slice(name: &Ident) -> TokenStream2 {
    quote! {
        impl iroha_ffi::slice::IntoFfiSliceRef for #name {
            type Store = Vec<*const #name>;

            fn into_ffi(
                source: &[Self],
                store: &mut <Self as iroha_ffi::slice::IntoFfiSliceRef>::Store
            ) -> iroha_ffi::slice::SliceRef<<Self as iroha_ffi::slice::FfiSliceRef>::ReprC> {
                *store = source.iter().enumerate().map(|(i, item)|
                    iroha_ffi::IntoFfi::into_ffi(item, &mut ())
                ).collect();

                iroha_ffi::slice::SliceRef::from_slice(store)
            }
        }
    }
}

fn derive_into_ffi_for_opaque_item_vec(name: &Ident) -> TokenStream2 {
    quote! {
        impl iroha_ffi::owned::IntoFfiVec for #name {
            type Store = Vec<<#name as iroha_ffi::owned::FfiVec>::ReprC>;

            fn into_ffi(
                source: Vec<Self>,
                store: &mut <Self as iroha_ffi::owned::IntoFfiVec>::Store
            ) -> iroha_ffi::Local<iroha_ffi::slice::SliceRef<<Self as iroha_ffi::owned::FfiVec>::ReprC>> {
                *store = source.into_iter().map(|item|
                    iroha_ffi::IntoFfi::into_ffi(item, &mut ())
                ).collect();

                iroha_ffi::Local(iroha_ffi::slice::SliceRef::from_slice(store))
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
            type Store = <#ffi_type as iroha_ffi::IntoFfi>::Store;

            fn into_ffi(self, store: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                (self as #ffi_type).into_ffi(store)
            }
        }
        impl iroha_ffi::IntoFfi for &#enum_name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                self as *const #enum_name as *const #ffi_type
            }
        }
        impl iroha_ffi::IntoFfi for &mut #enum_name {
            type Store = ();

            fn into_ffi(self, _: &mut <Self as iroha_ffi::IntoFfi>::Store) -> <Self as iroha_ffi::FfiType>::ReprC {
                self as *mut #enum_name as *mut #ffi_type
            }
        }
        impl iroha_ffi::slice::IntoFfiSliceRef for #enum_name {
            type Store = ();

            fn into_ffi(source: &[Self], store: &mut ()) -> iroha_ffi::slice::SliceRef<<Self as iroha_ffi::slice::FfiSliceRef>::ReprC> {
                iroha_ffi::slice::SliceRef::from_slice(unsafe {
                    &*(source as *const [#enum_name] as *const [#ffi_type])
                })
            }
        }
    }
}

fn is_opaque_wrapper(input: &DeriveInput) -> bool {
    let opaque_attr = parse_quote! {#[opaque_wrapper]};
    input.attrs.iter().any(|a| *a == opaque_attr)
}
