//! Module with conversion derive macros implementation

use super::*;

pub mod account;
pub mod asset;
pub mod asset_definition;

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
