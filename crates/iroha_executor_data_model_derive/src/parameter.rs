//! Module with [`derive_parameter`](crate::derive_parameter) macro implementation

use proc_macro2::TokenStream;
use quote::quote;

/// [`derive_parameter`](crate::derive_parameter()) macro implementation
pub fn impl_derive_parameter(input: &syn::DeriveInput) -> TokenStream {
    let generics = &input.generics;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_executor_data_model::parameter::Parameter for #ident #ty_generics #where_clause {}

        impl #impl_generics TryFrom<&::iroha_executor_data_model::parameter::CustomParameter> for #ident #ty_generics #where_clause {
            type Error = ::iroha_executor_data_model::TryFromDataModelObjectError;

            fn try_from(value: &::iroha_executor_data_model::parameter::CustomParameter) -> core::result::Result<Self, Self::Error> {
                let value_id = iroha_data_model::Identifiable::id(value);

                if *value_id != <Self as ::iroha_executor_data_model::parameter::Parameter>::id() {
                    return Err(Self::Error::UnknownIdent(alloc::string::ToString::to_string(value_id.name().as_ref())));
                }

                serde_json::from_str::<Self>(value.payload().as_ref()).map_err(Self::Error::Deserialize)
            }
        }

        impl #impl_generics From<#ident #ty_generics> for ::iroha_executor_data_model::parameter::CustomParameter #where_clause {
            fn from(value: #ident #ty_generics) -> Self {
                ::iroha_executor_data_model::parameter::CustomParameter::new(
                    <#ident as ::iroha_executor_data_model::parameter::Parameter>::id(),
                    ::serde_json::to_value::<#ident #ty_generics>(value)
                        .expect("INTERNAL BUG: Failed to serialize Executor data model entity"),
                )
            }
        }

        impl #impl_generics From<#ident #ty_generics> for ::iroha_data_model::parameter::Parameter #where_clause {
            fn from(value: #ident #ty_generics) -> Self {
                Self::Custom(value.into())
            }
        }
    }
}
