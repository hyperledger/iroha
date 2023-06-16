//! Module with [`derive_token`](crate::derive_token) macro implementation

#![allow(clippy::arithmetic_side_effects)] // Triggers on quote! side

use super::*;

/// [`derive_token`](crate::derive_token()) macro implementation
pub fn impl_derive_token(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let syn::Data::Struct(syn::DataStruct { fields, .. }) = input.data else {
        panic!("`Token` can be derived only for structs");
    };
    let extracted_fields = match fields {
        syn::Fields::Named(syn::FieldsNamed { named, .. }) => named,
        syn::Fields::Unit => syn::punctuated::Punctuated::default(),
        _ => panic!("`Token` can be derived only for structs with named fields or unit structs"),
    };

    let impl_token = impl_token(
        &impl_generics,
        &ty_generics,
        where_clause,
        &ident,
        &extracted_fields,
    );
    let impl_try_from_permission_token = impl_try_from_permission_token(
        &impl_generics,
        &ty_generics,
        where_clause,
        &ident,
        &extracted_fields,
    );

    quote! {
        #impl_token
        #impl_try_from_permission_token
    }
    .into()
}

fn impl_token(
    impl_generics: &syn::ImplGenerics<'_>,
    ty_generics: &syn::TypeGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
    ident: &syn::Ident,
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> proc_macro2::TokenStream {
    let definition = gen_definition(ident, fields);
    let permission_token_conversion_code = permission_token_conversion(fields);

    quote! {
        impl #impl_generics ::iroha_validator::permission::Token for #ident #ty_generics
        #where_clause
        {
            fn definition() -> ::iroha_validator::data_model::permission::PermissionTokenDefinition {
                #definition
            }

            fn is_owned_by(
                &self,
                account_id: &<
                    ::iroha_validator::data_model::prelude::Account
                    as
                    ::iroha_validator::data_model::prelude::Identifiable
                >::Id
            ) -> bool {
                let permission_token = #permission_token_conversion_code;

                let value = ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                    ::iroha_validator::iroha_wasm::QueryHost::execute(
                        &::iroha_validator::iroha_wasm::data_model::prelude::DoesAccountHavePermissionToken::new(
                            account_id.clone(),
                            permission_token,
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

fn gen_definition(
    ident: &syn::Ident,
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> proc_macro2::TokenStream {
    use heck::ToSnakeCase as _;

    let definition_id = proc_macro2::Literal::string(&ident.to_string().to_snake_case());

    let params = fields.iter().map(|field| {
        let ident = field.ident.as_ref().expect("Field must have an identifier");
        let name = proc_macro2::Literal::string(&ident.to_string().to_snake_case());
        let ty = &field.ty;

        quote! {
            (
                ::iroha_validator::parse!(#name as ::iroha_validator::data_model::prelude::Name),
                <#ty as ::iroha_validator::data_model::AssociatedConstant<
                    ::iroha_validator::data_model::ValueKind
                >>::VALUE
            )
        }
    });

    quote! {
        ::iroha_validator::data_model::permission::PermissionTokenDefinition::new(
            ::iroha_validator::parse!(
                #definition_id as <
                    ::iroha_validator::data_model::permission::PermissionTokenDefinition
                    as
                    ::iroha_validator::data_model::prelude::Identifiable
                >::Id
            )
        )
        .with_params([#(#params),*])
    }
}

fn impl_try_from_permission_token(
    impl_generics: &syn::ImplGenerics<'_>,
    ty_generics: &syn::TypeGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
    ident: &syn::Ident,
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> proc_macro2::TokenStream {
    let field_initializers = fields.iter().map(|field| {
        let field_ident = field.ident.as_ref().expect("Field must have an identifier");
        let field_literal = proc_macro2::Literal::string(&field_ident.to_string());
        let field_type = &field.ty;

        let code = quote! {
            #field_ident: <
                #field_type
                as
                ::core::convert::TryFrom<::iroha_validator::data_model::prelude::Value>
            >::try_from(token
                .param(&::iroha_validator::parse!(#field_literal as ::iroha_validator::data_model::prelude::Name))
                .ok_or(
                    ::iroha_validator::permission::PermissionTokenConversionError::Param(#field_literal)
                )?
                .clone()
            )
            .map_err(|err| {
                ::iroha_validator::permission::PermissionTokenConversionError::Value(
                    ::alloc::string::ToString::to_string(&err)
                )
            })?
        };
        code
    });

    quote! {
        impl #impl_generics ::core::convert::TryFrom<::iroha_validator::data_model::permission::PermissionToken> for #ident #ty_generics
        #where_clause
        {
            type Error = ::iroha_validator::permission::PermissionTokenConversionError;

            #[allow(unused)] // `params` can be unused if token has none
            fn try_from(
                token: ::iroha_validator::data_model::permission::PermissionToken
            ) -> ::core::result::Result<Self, Self::Error> {
                if token.definition_id() !=
                    <Self as::iroha_validator::permission::Token>::definition().id()
                {
                    return Err(::iroha_validator::permission::PermissionTokenConversionError::Id(
                        token.definition_id().clone()
                    ));
                }

                Ok(Self {
                    #(#field_initializers),*
                })
            }
        }
    }
}

#[allow(clippy::arithmetic_side_effects)] // Triggers on quote! side
fn permission_token_conversion(
    fields: &syn::punctuated::Punctuated<syn::Field, syn::token::Comma>,
) -> proc_macro2::TokenStream {
    let params = fields.iter().cloned().map(|field| {
        let field_ident = field.ident.as_ref().expect("Field must have an identifier");
        let field_literal = proc_macro2::Literal::string(&field_ident.to_string());
        quote! {(
            ::iroha_validator::parse!(#field_literal as ::iroha_validator::data_model::prelude::Name),
            self.#field_ident.clone().into(),
        )}
    });

    quote! {
        ::iroha_validator::data_model::permission::PermissionToken::new(
            <Self as ::iroha_validator::permission::Token>::definition().id().clone()
        )
        .with_params([
            #(#params),*
        ])
    }
}
