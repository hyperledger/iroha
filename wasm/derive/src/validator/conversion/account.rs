//! Module with implementation of macros deriving conversion from
//! strongly-typed token to account-related pass condition.

use super::*;

/// [`derive_ref_into_account_owner`](crate::derive_ref_into_account_owner) macro implementation
pub fn impl_derive_ref_into_account_owner(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_from(
        &input.ident,
        &input.generics,
        &syn::parse_quote!(::iroha_wasm::validator::pass_conditions::account::Owner),
        &syn::parse_quote!(account_id),
    )
    .into()
}
