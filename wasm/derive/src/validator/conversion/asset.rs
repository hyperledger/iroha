//! Module with implementation of macros deriving conversion from
//! strongly-typed token to asset-related pass condition.

use super::*;

/// [`derive_ref_into_asset_owner`](crate::derive_ref_into_asset_owner) macro implementation
pub fn impl_derive_ref_into_asset_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_wasm::validator::pass_conditions::asset::Owner),
        &syn::parse_quote!(asset_id),
    )
    .into()
}
