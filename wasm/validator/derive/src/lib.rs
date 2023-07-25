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
/// Validators are only checking if an operation is **invalid**, not if it is valid.
/// A validator can either deny the operation or pass it to the next validator if there is one.
///
/// # Attributes
///
/// This macro must have an attribute describing entrypoint parameters.
///
/// The syntax is:
///
/// ```ignore
/// #[iroha_validator::entrypoint(params = "[<type>,*]")]
/// ```
///
/// where `<type>` is one of:
///
/// - `authority`: optional, represents a signer account id who submits an operation
/// - `operation`: mandatory, represents an operation that is being validated
///
/// Parameters will be passed to the entrypoint function in the order they are specified.
///
/// ## Authority
///
/// A real function parameter type corresponding to the `authority` should have
/// `iroha_validator::data_model::prelude::AccountId` type.
///
/// ## Operation
///
/// A real function parameter type corresponding to the `transaction` should have
/// `iroha_validator::data_model::prelude::NeedsValidationBox` type.
///
/// # Panics
///
/// - If got unexpected syntax of attribute
/// - If the function does not have a return type
///
/// # Examples
///
/// Using only `query` parameter:
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// ```ignore
/// use iroha_validator::prelude::*;
///
/// #[entrypoint(params = "[operation]")]
/// pub fn validate(operation: NeedsValidationBox) -> Result {
///     if let NeedsValidationBox::Query(_) = operation {
///         deny!("No queries are allowed")
///     }
///
///     pass!()
/// }
/// ```
///
/// Using both `authority` and `operation` parameters:
///
/// ```ignore
/// use iroha_validator::prelude::*;
///
/// #[entrypoint(params = "[authority, operation]")]
/// pub fn validate(authority: AccountId, _: NeedsValidationBox) -> Result {
///     let admin_domain = parse!("admin_domain" as AccountId);
///
///     if authority.domain_id != admin_domain {
///         deny!("No operations are allowed")
///     }
///
///     pass!()
/// }
/// ```
///
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
