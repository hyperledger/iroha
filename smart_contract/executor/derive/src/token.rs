//! Module with [`derive_token`](crate::derive_token) macro implementation

use super::*;

/// [`derive_token`](crate::derive_token()) macro implementation
pub fn impl_derive_token(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let generics = &input.generics;
    let ident = &input.ident;

    let impl_token = impl_token(ident, generics);
    let impl_try_from_permission_token = impl_try_from_permission_token(ident, generics);

    quote! {
        #impl_token
        #impl_try_from_permission_token
    }
    .into()
}

fn impl_token(ident: &syn::Ident, generics: &syn::Generics) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_executor::permission::Token for #ident #ty_generics #where_clause {
            fn is_owned_by(&self, account_id: &::iroha_executor::data_model::account::AccountId) -> bool {
                let account_tokens_cursor = ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                    ::iroha_executor::smart_contract::ExecuteQueryOnHost::execute(
                        ::iroha_executor::data_model::query::permission::FindPermissionTokensByAccountId::new(
                            account_id.clone(),
                        )
                    ),
                    "Failed to execute `FindPermissionTokensByAccountId` query"
                );

                account_tokens_cursor
                    .into_iter()
                    .map(|res| ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                        res,
                        "Failed to get permission token from cursor"
                    ))
                    .filter_map(|token| Self::try_from(token).ok())
                    .any(|token| self == &token)
            }
        }
    }
}

fn impl_try_from_permission_token(
    ident: &syn::Ident,
    generics: &syn::Generics,
) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let token_id = quote! { <Self as ::iroha_executor::permission::Token>::name() };

    quote! {
        impl #impl_generics ::core::convert::TryFrom<::iroha_executor::data_model::permission::PermissionToken> for #ident #ty_generics #where_clause {
            type Error = ::iroha_executor::permission::PermissionTokenConversionError;

            fn try_from(token: ::iroha_executor::data_model::permission::PermissionToken) -> ::core::result::Result<Self, Self::Error> {
                if #token_id != *token.definition_id() {
                    return Err(::iroha_executor::permission::PermissionTokenConversionError::Id(
                        ToOwned::to_owned(token.definition_id())
                    ));
                }
                ::serde_json::from_str::<Self>(token.payload())
                    .map_err(::iroha_executor::permission::PermissionTokenConversionError::Deserialize)
            }
        }
    }
}
