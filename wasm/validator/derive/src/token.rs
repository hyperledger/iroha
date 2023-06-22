//! Module with [`derive_token`](crate::derive_token) macro implementation

#![allow(clippy::arithmetic_side_effects)] // Triggers on quote! side

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

fn gen_token_definition_id() -> proc_macro2::TokenStream {
    quote! { <Self as ::iroha_schema::IntoSchema>::type_name() }
}

fn impl_token(ident: &syn::Ident, generics: &syn::Generics) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let token_definition_id = gen_token_definition_id();

    quote! {
        impl #impl_generics ::iroha_validator::permission::Token for #ident #ty_generics #where_clause {
            fn is_owned_by(&self, account_id: &::iroha_validator::data_model::prelude::AccountId) -> bool {
                let permission_token = ::iroha_validator::data_model::permission::PermissionToken::new(
                    #token_definition_id, self
                );

                let value = ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                    ::iroha_validator::iroha_wasm::QueryHost::execute(
                        &::iroha_validator::iroha_wasm::data_model::prelude::DoesAccountHavePermissionToken::new(
                            account_id.clone(), permission_token,
                        )
                    ),
                    "Failed to execute `DoesAccountHavePermissionToken` query"
                );
                ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                    value.try_into(),
                    "Failed to convert `DoesAccountHavePermissionToken` query result into `bool`"
                )
            }
        }
    }
}

fn impl_try_from_permission_token(
    ident: &syn::Ident,
    generics: &syn::Generics,
) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let token_definition_id = gen_token_definition_id();

    quote! {
        impl #impl_generics ::core::convert::TryFrom<::iroha_validator::data_model::permission::PermissionToken> for #ident #ty_generics #where_clause {
            type Error = ::iroha_validator::permission::PermissionTokenConversionError;

            fn try_from(token: ::iroha_validator::data_model::permission::PermissionToken) -> ::core::result::Result<Self, Self::Error> {
                if #token_definition_id != *token.definition_id() {
                    return Err(::iroha_validator::permission::PermissionTokenConversionError::Id(
                        ::alloc::borrow::ToOwned::to_owned(token.definition_id())
                    ));
                }

                Ok(<Self as ::parity_scale_codec::DecodeAll>::decode_all(&mut token.payload()).unwrap())
            }
        }
    }
}
