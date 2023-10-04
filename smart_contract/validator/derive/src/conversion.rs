//! Module with conversion derive macros implementation

use super::*;

/// [`derive_ref_into_asset_owner`](crate::derive_ref_into_asset_owner) macro implementation
pub fn impl_derive_ref_into_asset_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_validator::permission::asset::Owner),
        &syn::parse_quote!(asset_id),
    )
    .into()
}

/// [`derive_ref_into_asset_definition_creator`](crate::derive_ref_into_asset_definition_creator)
/// macro implementation
pub fn impl_derive_ref_into_asset_definition_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_validator::permission::asset_definition::Owner),
        &syn::parse_quote!(asset_definition_id),
    )
    .into()
}

/// [`derive_ref_into_account_owner`](crate::derive_ref_into_account_owner) macro implementation
pub fn impl_derive_ref_into_account_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_validator::permission::account::Owner),
        &syn::parse_quote!(account_id),
    )
    .into()
}

/// [`derive_ref_into_domain_owner`](crate::derive_ref_into_domain_owner) macro implementation
pub fn impl_derive_ref_into_domain_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_validator::permission::domain::Owner),
        &syn::parse_quote!(domain_id),
    )
    .into()
}

fn impl_from(
    ident: &syn::Ident,
    generics: &syn::Generics,
    pass_condition_type: &syn::Type,
    field: &syn::Ident,
) -> proc_macro2::TokenStream {
    use quote::ToTokens;

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut generics: proc_macro2::TokenStream = syn::parse_str("<'token, ").unwrap();

    let impl_generics_tokens = impl_generics.into_token_stream();
    if impl_generics_tokens.is_empty() {
        generics.extend(core::iter::once(proc_macro2::TokenTree::Punct(
            syn::parse_str(">").unwrap(),
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
