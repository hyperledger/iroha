//! Module with conversion derive macros implementation

use proc_macro2::TokenStream;
use quote::quote;
use syn2::DeriveInput;

/// [`derive_ref_into_asset_owner`](crate::derive_ref_into_asset_owner) macro implementation
pub fn impl_derive_ref_into_asset_owner(input: &DeriveInput) -> TokenStream {
    impl_from(
        &input.ident,
        &input.generics,
        &syn2::parse_quote!(::iroha_executor::permission::asset::Owner),
        &syn2::parse_quote!(asset_id),
    )
}

/// [`derive_ref_into_asset_definition_creator`](crate::derive_ref_into_asset_definition_creator)
/// macro implementation
pub fn impl_derive_ref_into_asset_definition_owner(input: &DeriveInput) -> TokenStream {
    impl_from(
        &input.ident,
        &input.generics,
        &syn2::parse_quote!(::iroha_executor::permission::asset_definition::Owner),
        &syn2::parse_quote!(asset_definition_id),
    )
}

/// [`derive_ref_into_account_owner`](crate::derive_ref_into_account_owner) macro implementation
pub fn impl_derive_ref_into_account_owner(input: &DeriveInput) -> TokenStream {
    impl_from(
        &input.ident,
        &input.generics,
        &syn2::parse_quote!(::iroha_executor::permission::account::Owner),
        &syn2::parse_quote!(account_id),
    )
}

/// [`derive_ref_into_domain_owner`](crate::derive_ref_into_domain_owner) macro implementation
pub fn impl_derive_ref_into_domain_owner(input: &DeriveInput) -> TokenStream {
    impl_from(
        &input.ident,
        &input.generics,
        &syn2::parse_quote!(::iroha_executor::permission::domain::Owner),
        &syn2::parse_quote!(domain_id),
    )
}

fn impl_from(
    ident: &syn2::Ident,
    generics: &syn2::Generics,
    pass_condition_type: &syn2::Type,
    field: &syn2::Ident,
) -> TokenStream {
    use quote::ToTokens;

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut generics: TokenStream = syn2::parse_str("<'token, ").unwrap();

    let impl_generics_tokens = impl_generics.into_token_stream();
    if impl_generics_tokens.is_empty() {
        generics.extend(core::iter::once(proc_macro2::TokenTree::Punct(
            syn2::parse_str(">").unwrap(),
        )));
    } else {
        generics.extend(impl_generics_tokens.into_iter().skip(1));
    }

    quote! {
        impl #generics ::core::convert::From<&'token #ident #ty_generics> for
            #pass_condition_type<'token>
        #where_clause
        {
            fn from(token: &'token #ident #ty_generics) -> Self {
                Self {
                    #field: &token.#field,
                }
            }
        }
    }
}
