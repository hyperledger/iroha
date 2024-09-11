//! Module with [`derive_permission`](crate::derive_permission) macro implementation

use proc_macro2::TokenStream;
use quote::quote;

/// [`derive_permission`](crate::derive_permission()) macro implementation
pub fn impl_derive_permission(input: &syn::DeriveInput) -> TokenStream {
    let generics = &input.generics;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl iroha_executor_data_model::permission::Permission for #ident #ty_generics #where_clause {}

        impl #impl_generics TryFrom<&::iroha_data_model::permission::Permission> for #ident #ty_generics #where_clause {
            type Error = ::iroha_executor_data_model::TryFromDataModelObjectError;

            fn try_from(value: &::iroha_data_model::permission::Permission) -> core::result::Result<Self, Self::Error> {
                use alloc::borrow::ToOwned as _;

                if *value.name() != <Self as ::iroha_executor_data_model::permission::Permission>::name() {
                    return Err(Self::Error::UnknownIdent(value.name().to_owned()));
                }

                serde_json::from_str::<Self>(value.payload().as_ref()).map_err(Self::Error::Deserialize)
            }
        }

        impl #impl_generics From<#ident #ty_generics> for ::iroha_data_model::permission::Permission #where_clause {
            fn from(value: #ident #ty_generics) -> Self {
                ::iroha_data_model::permission::Permission::new(
                    <#ident as ::iroha_executor_data_model::permission::Permission>::name(),
                    ::serde_json::to_value::<#ident #ty_generics>(value)
                        .expect("INTERNAL BUG: Failed to serialize executor data model entity"),
                )
            }
        }
    }
}
