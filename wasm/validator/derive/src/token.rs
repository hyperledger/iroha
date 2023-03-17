//! Module with [`derive_token`](crate::derive_token) macro implementation

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
    use heck::ToSnakeCase as _;

    let definition_id = proc_macro2::Literal::string(&ident.to_string().to_snake_case());
    let permission_token_conversion_code = permission_token_conversion(fields);

    quote! {
        impl #impl_generics ::iroha_validator::traits::Token for #ident #ty_generics
        #where_clause
        {
            fn definition_id() -> ::iroha_validator::data_model::permission::token::Id {
                ::iroha_validator::parse!(
                    #definition_id as <
                        ::iroha_validator::data_model::permission::token::Definition
                        as
                        ::iroha_validator::data_model::prelude::Identifiable
                    >::Id
                )
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

                ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                    ::iroha_validator::iroha_wasm::ExecuteOnHost::execute(
                        &::iroha_validator::iroha_wasm::data_model::prelude::QueryBox::from(
                            ::iroha_validator::iroha_wasm::data_model::prelude::DoesAccountHavePermissionToken::new(
                                account_id.clone(),
                                permission_token,
                            )
                        )
                    ).try_into(),
                    "Failed to convert `DoesAccountHavePermissionToken` query result into `bool`"
                )
            }
        }
    }
}

#[allow(clippy::arithmetic_side_effects)] // Triggers on quote! side
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
        let syn::Type::Path(field_type) = &field.ty else {
            panic!("Field must have a type path");
        };

        let code = quote! {
            #field_ident: <
                #field_type
                as
                ::core::convert::TryFrom<::iroha_validator::data_model::prelude::Value>
            >::try_from(token
                .param(&::iroha_validator::parse!(#field_literal as ::iroha_validator::data_model::prelude::Name))
                .ok_or(
                    ::iroha_validator::PermissionTokenConversionError::Param(#field_literal)
                )?
                .clone()
            )
            .map_err(|err| {
                ::iroha_validator::PermissionTokenConversionError::Value(
                    ::alloc::string::ToString::to_string(&err)
                )
            })?
        };
        code
    });

    quote! {
        impl #impl_generics ::core::convert::TryFrom<::iroha_validator::data_model::permission::Token> for #ident #ty_generics
        #where_clause
        {
            type Error = ::iroha_validator::PermissionTokenConversionError;

            #[allow(unused)] // `params` can be unused if token has none
            fn try_from(
                token: ::iroha_validator::data_model::permission::Token
            ) -> ::core::result::Result<Self, Self::Error> {
                if token.definition_id() !=
                    &<Self as::iroha_validator::traits::Token>::definition_id()
                {
                    return Err(::iroha_validator::PermissionTokenConversionError::Id(
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
            ::iroha_validator::parse!(#field_literal
                as ::iroha_validator::data_model::prelude::Name),
            self.#field_ident.clone().into()
        )}
    });

    quote! {
        ::iroha_validator::data_model::permission::Token::new(
            <Self as ::iroha_validator::traits::Token>::definition_id()
        )
        .with_params([
            #(#params),*
        ])
    }
}
