//! Crate with validator-related derive macros.

#![allow(clippy::panic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput};

mod conversion;
mod entrypoint;
mod token;
mod validate;

/// Annotate the user-defined function that starts the execution of a validator.
///
/// There are 4 acceptable forms of this macro usage. See examples.
///
/// # Examples
///
/// ```ignore
/// use iroha_validator::prelude::*;
///
/// #[entrypoint]
/// pub fn migrate(block_height: u64) -> MigrationResult {
///     todo!()
/// }
///
/// #[entrypoint]
/// pub fn validate_transaction(
///     authority: AccountId,
///     transaction: VersionedSignedTransaction,
///     block_height: u64,
/// ) -> Result {
///     todo!()
/// }
///
/// #[entrypoint]
/// pub fn validate_instruction(authority: AccountId, instruction: InstructionBox, block_height: u64) -> Result {
///     todo!()
/// }
///
/// #[entrypoint]
/// pub fn validate_query(authority: AccountId, query: QueryBox, block_height: u64) -> Result {
///     todo!()
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}

/// Derive macro for `Token` trait.
///
/// # Example
///
/// ```ignore
/// use iroha_validator::{permission, prelude::*};
///
/// #[derive(Token, ValidateGrantRevoke, permission::derive_conversions::asset::Owner)]
/// #[validate(permission::asset::Owner)]
/// struct CanDoSomethingWithAsset {
///     some_data: String,
///     asset_id: AssetId,
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
///        asset_id: parse!("rose#wonderland" as AssetId),
///     }.is_owned_by(&authority)
/// }
/// ```
#[proc_macro_derive(Token)]
pub fn derive_token(input: TokenStream) -> TokenStream {
    token::impl_derive_token(input)
}

/// Derive macro for `ValidateGrantRevoke` trait.
///
/// # Attributes
///
/// This macro requires `validate` or a group of `validate_grant` and `validate_revoke` attributes.
///
/// ## `validate` attribute
///
/// Use `validate` to specify [*Pass Condition*](#permission) for both `Grant` and `Revoke`
/// instructions validation.
///
/// ## `validate_grant` and `validate_revoke` attributes
///
/// Use `validate_grant` together with `validate_revoke` to specify *pass condition* for
/// `Grant` and `Revoke` instructions validation separately.
///
/// # Pass conditions
///
/// You can pass any type implementing `iroha_validator::permission::PassCondition`
/// and `From<&YourToken>` traits.
///
/// ## Builtin
///
/// There are some builtin pass conditions:
///
/// - `asset_definition::Owner` - checks if the authority is the asset definition owner;
/// - `asset::Owner` - checks if the authority is the asset owner;
/// - `account::Owner` - checks if the authority is the account owner.
/// - `AlwaysPass` - checks nothing and always passes.
/// - `OnlyGenesis` - checks that block height is 0.
///
///
/// Also check out `iroha_validator::permission::derive_conversion` module
/// for conversion derive macros from your token to this *Pass Conditions*.
///
/// ## Why *Pass Conditions*?
///
/// With that you can easily derive one of most popular implementations to remove boilerplate code.
///
/// ## Manual `ValidateGrantRevoke` implementation VS Custom *Pass Condition*
///
/// General advice is to use custom *Pass Condition* if you need this custom validation
/// multiple times in different tokens. Otherwise, you can implement `ValidateGrantRevoke` trait manually.
///
/// In future there will be combinators like `&&` and `||` to combine multiple *Pass Conditions*.
///
/// # Example
///
/// See [`Token`] derive macro example.
//
// TODO: Add combinators (#3255).
// Example:
//
// ```
// #[derive(Token, ValidateGrantRevoke)]
// #[validate(Creator || Admin)]
// pub struct CanDoSomethingWithAsset {
//     ...
// }
// ```
#[proc_macro_derive(
    ValidateGrantRevoke,
    attributes(validate, validate_grant, validate_revoke)
)]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    validate::impl_derive_validate(input)
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::asset_definition::Owner` type.
///
/// Requires `asset_definition_id` field in the token.
///
/// Implements [`From`] for `permission::asset_definition::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAssetDefinitionOwner)]
pub fn derive_ref_into_asset_definition_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_asset_definition_owner(input)
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::asset::Owner` type.
///
/// Requires `asset_id` field in the token.
///
/// Implements [`From`] for `permission::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAssetOwner)]
pub fn derive_ref_into_asset_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_asset_owner(input)
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::account::Owner` type.
///
/// Requires `account_id` field in the token.
///
/// Implements [`From`] for `permission::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAccountOwner)]
pub fn derive_ref_into_account_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_account_owner(input)
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::domain::Owner` type.
///
/// Requires `domain_id` field in the token.
///
/// Implements [`From`] for `permission::domain::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoDomainOwner)]
pub fn derive_ref_into_domain_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_domain_owner(input)
}
