//! Crate with executor-related derive macros.

mod parameter;
mod permission;

use manyhow::{manyhow, Result};
use proc_macro2::TokenStream;

/// Derive macro for `Parameter` trait.
#[manyhow]
#[proc_macro_derive(Parameter)]
pub fn derive_parameter(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(parameter::impl_derive_parameter(&input))
}

/// Derive macro for `Permission` trait.
///
/// # Example
///
/// ```ignore
/// use iroha_executor::{permission, prelude::*};
///
/// #[derive(Permission, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
/// #[validate(permission::asset::Owner)]
/// struct CanDoSomethingWithAsset {
///     some_data: String,
///     asset: AssetId,
/// }
///
/// #[entrypoint(params = "[authority, operation]")]
/// fn validate(authority: AccountId, operation: NeedsValidationBox) -> Result {
///     let NeedsValidationBox::Instruction(instruction) = operation else {
///         pass!();
///     };
///
///     validate_grant_revoke!(<CanDoSomethingWithAsset>, (authority, instruction));
///
///     CanDoSomethingWithAsset {
///        some_data: "some data".to_owned(),
///        asset: "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland".parse().unwrap(),
///     }.is_owned_by(&authority)
/// }
/// ```
#[manyhow]
#[proc_macro_derive(Permission)]
pub fn derive_permission(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(permission::impl_derive_permission(&input))
}
