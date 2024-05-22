//! Module with [`derive_token`](crate::derive_token) macro implementation

use proc_macro2::TokenStream;
use quote::quote;

/// [`derive_token`](crate::derive_token()) macro implementation
pub fn impl_derive_token(input: &syn::DeriveInput) -> TokenStream {
    let generics = &input.generics;
    let ident = &input.ident;

    let impl_token = impl_token(ident, generics);
    let impl_try_from_permission = impl_try_from_permission(ident, generics);

    quote! {
        #impl_token
        #impl_try_from_permission
    }
}

fn impl_token(ident: &syn::Ident, generics: &syn::Generics) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_executor::permission::Token for #ident #ty_generics #where_clause {
            fn is_owned_by(&self, account_id: &::iroha_executor::data_model::account::AccountId) -> bool {
                let account_tokens_cursor = ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                    ::iroha_executor::smart_contract::ExecuteQueryOnHost::execute(
                        &::iroha_executor::data_model::query::permission::FindPermissionsByAccountId::new(
                            account_id.clone(),
                        )
                    ),
                    "Failed to execute `FindPermissionsByAccountId` query"
                );

                account_tokens_cursor
                    .into_iter()
                    .map(|res| ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                        res,
                        "Failed to get permission token from cursor"
                    ))
                    .filter_map(|token| Self::try_from(&token).ok())
                    .any(|token| self == &token)
            }
        }
    }
}

fn impl_try_from_permission(ident: &syn::Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let token_id = quote! { <#ident #ty_generics as ::iroha_executor::permission::Token>::name() };

    quote! {
        impl #impl_generics ::core::convert::TryFrom<&::iroha_executor::data_model::permission::Permission> for #ident #ty_generics #where_clause {
            type Error = ::iroha_executor::permission::PermissionConversionError;

            fn try_from(token: &::iroha_executor::data_model::permission::Permission) -> ::core::result::Result<Self, Self::Error> {
                if #token_id != *token.definition_id() {
                    return Err(::iroha_executor::permission::PermissionConversionError::Id(
                        ToOwned::to_owned(token.definition_id())
                    ));
                }
                ::serde_json::from_str::<Self>(token.payload())
                    .map_err(::iroha_executor::permission::PermissionConversionError::Deserialize)
            }
        }

        impl #impl_generics ::core::convert::From<#ident #ty_generics> for ::iroha_executor::data_model::permission::Permission #where_clause {
            fn from(token: #ident #ty_generics) -> Self {
                let definition_id = #token_id;

                let payload = ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                    ::serde_json::to_value::<#ident #ty_generics>(token),
                    "failed to serialize concrete permission token type. This is a bug."
                );

                ::iroha_executor::data_model::permission::Permission::new(definition_id, &payload)
            }
        }
    }
}
