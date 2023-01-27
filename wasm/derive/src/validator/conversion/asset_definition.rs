//! Module with implementation of macros deriving conversion from
//! strongly-typed token to asset definition related pass condition.

use super::*;

/// [`derive_ref_into_asset_definition_creator`](crate::derive_ref_into_asset_definition_creator)
/// macro implementation
pub fn impl_derive_ref_into_asset_definition_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_wasm::validator::pass_conditions::asset_definition::Owner),
        &syn::parse_quote!(asset_definition_id),
    )
    .into()
}
