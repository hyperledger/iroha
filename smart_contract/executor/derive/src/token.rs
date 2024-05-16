//! Module with [`derive_token`](crate::derive_token) macro implementation

use proc_macro2::TokenStream;
use quote::quote;

/// [`derive_token`](crate::derive_token()) macro implementation
pub fn impl_derive_token(input: &syn::DeriveInput) -> TokenStream {
    let generics = &input.generics;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_executor::permission::Token for #ident #ty_generics #where_clause {
            fn is_owned_by(&self, account_id: &::iroha_executor::data_model::account::AccountId) -> bool {
                let account_tokens_cursor = ::iroha_executor::smart_contract::debug::DebugExpectExt::dbg_expect(
                    ::iroha_executor::smart_contract::ExecuteQueryOnHost::execute(
                        &::iroha_executor::data_model::query::permission::FindPermissionTokensByAccountId::new(
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
                    .filter_map(|token| Self::try_from_object(&token).ok())
                    .any(|token| self == &token)
            }
        }
    }
}
