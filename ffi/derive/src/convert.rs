use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::abort;
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident};

use crate::{enum_size, find_attr, is_fieldless_enum, is_opaque};

pub fn derive_try_from_ffi(input: &DeriveInput) -> TokenStream2 {
    if is_opaque(input) {
        return derive_try_from_ffi_for_opaque_item(&input.ident);
    }

    match &input.data {
        syn::Data::Enum(item) => {
            let repr = find_attr(&input.attrs, "repr");

            if is_fieldless_enum(&input.ident, item, &repr) {
                derive_try_from_ffi_for_fieldless_enum(&input.ident, item, &repr)
            } else {
                derive_try_from_ffi_for_item(&input.ident)
            }
        }
        syn::Data::Struct(_) => derive_try_from_ffi_for_item(&input.ident),
        syn::Data::Union(item) => abort!(item.union_token, "Unions are not supported"),
    }
}

pub fn derive_into_ffi(input: &DeriveInput) -> TokenStream2 {
    if is_opaque(input) {
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

fn derive_try_from_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    #[cfg(not(feature = "client"))]
    let owned_try_from_repr_c = quote! {
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
    };
    #[cfg(feature = "client")]
    let owned_try_from_repr_c = quote! {
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

                // TODO: Casting from non opaque to opaque.
                Ok(Self(source.cast()))
            }
        }
    };

    quote! {
        #owned_try_from_repr_c

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

fn derive_try_from_ffi_for_item(_: &Ident) -> TokenStream2 {
    quote! {
        // TODO:
    }
}

fn derive_try_from_ffi_for_fieldless_enum(
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

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                match source {
                    #( #discriminant_names => Ok(#enum_name::#variant_names), )*
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm #enum_name {
            type Source = *const #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&*(source as *const _ as *const _)),
                    _ => Err(iroha_ffi::FfiReturn::TrapRepresentation),
                }}
            }
        }
        impl<'itm> iroha_ffi::TryFromReprC<'itm> for &'itm mut #enum_name {
            type Source = *mut #ffi_type;
            type Store = ();

            unsafe fn try_from_repr_c(
                source: <Self as iroha_ffi::TryFromReprC<'itm>>::Source,
                _: &mut <Self as iroha_ffi::TryFromReprC<'itm>>::Store
            ) -> iroha_ffi::Result<Self> {
                #( #discriminants )*

                unsafe { match *source {
                    #( | #discriminant_names )* => Ok(&mut *(source as *mut _ as *mut _)),
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

fn derive_into_ffi_for_opaque_item(name: &Ident) -> TokenStream2 {
    #[cfg(not(feature = "client"))]
    let owned_into_ffi = quote! {
        impl iroha_ffi::IntoFfi for #name {
            type Target = *mut Self;

            fn into_ffi(self) -> Self::Target {
                Box::into_raw(Box::new(self))
            }
        }
    };
    #[cfg(feature = "client")]
    let owned_into_ffi = quote! {
        impl iroha_ffi::IntoFfi for #name {
            type Target = *mut Self;

            fn into_ffi(self) -> Self::Target {
                // TODO: Casting from non opaque to opaque.
                (*core::mem::ManuallyDrop::new(self)).ptr
            }
        }
    };

    quote! {
        #owned_into_ffi

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
                source.iter().map(iroha_ffi::IntoFfi::into_ffi).collect()
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
