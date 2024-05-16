//! Module with [`derive_permission`](crate::derive_permission) macro implementation

use proc_macro2::TokenStream;
use quote::quote;

/// [`derive_permission`](crate::derive_permission()) macro implementation
pub fn impl_derive_permission(input: &syn::DeriveInput) -> TokenStream {
    let generics = &input.generics;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics ::iroha_executor::permission::Permission for #ident #ty_generics #where_clause {
            fn is_owned_by(&self, account_id: &::iroha_executor::data_model::account::AccountId) -> bool {
                let account_tokens_cursor =
                    ::iroha_executor::smart_contract::ExecuteQueryOnHost::execute(
                        &::iroha_executor::data_model::query::permission::FindPermissionsByAccountId::new(
                            account_id.clone(),
                        )
                    )
                    .expect("`FindPermissionsByAccountId` query should never fail, it's a bug");

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
