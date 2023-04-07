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
/// - `authority` is a signer account id who submits an operation
/// - `transaction` is a transaction that is being validated
/// - `instruction` is an instruction that is being validated
/// - `query` is a query that is being validated
/// - `expression` is an expression that is being validated
///
/// Exactly one parameter of *operation to validate* kind must be specified.
/// `authority` is optional.
/// Parameters will be passed to the entrypoint function in the order they are specified.
///
/// ## Authority
///
/// A real function parameter type corresponding to the `authority` should have
/// `iroha_validator::data_model::prelude::AccountId` type.
///
/// ## Transaction
///
/// A real function parameter type corresponding to the `transaction` should have
/// `iroha_validator::data_model::prelude::Transaction` type.
///
/// ## Instruction
///
/// A real function parameter type corresponding to the `instruction` should have
/// `iroha_validator::data_model::prelude::InstructionBox` type.
///
/// ## Query
///
/// A real function parameter type corresponding to the `query` should have
/// `iroha_validator::data_model::prelude::QueryBox` type.
///
/// ## Expression
///
/// A real function parameter type corresponding to the `expression` should have
/// `iroha_validator::data_model::prelude::Expression` type.
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
/// #[entrypoint(params = "[query]")]
/// pub fn validate(_: QueryBox) -> Verdict {
///     Verdict::Deny("No queries are allowed".to_owned())
/// }
/// ```
///
/// Using both `authority` and `instruction` parameters:
///
/// ```ignore
/// use iroha_validator::prelude::*;
///
/// #[entrypoint(params = "[authority, instruction]")]
/// pub fn validate(authority: AccountId, _: InstructionBox) -> Verdict {
///     let admin_domain = "admin_domain".parse()
///         .dbg_expect("Failed to parse `admin_domain` as a domain id");
///
///     if authority.domain_id != admin_domain {
///         Verdict::Deny("No queries are allowed".to_owned())
///     }
///
///     Verdict::Pass
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
/// use iroha_validator::{pass_conditions, prelude::*};
///
/// #[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
/// #[validate(pass_conditions::asset::Owner)]
/// struct CanDoSomethingWithAsset {
///     some_data: String,
///     asset_id: <Asset as Identifiable>::Id,
/// }
///
/// #[entrypoint(params = "[authority, instruction]")]
/// fn validate(authority: <Account as Identifiable>::Id, instruction: InstructionBox) -> Verdict {
///     validate_grant_revoke!(<CanDoSomethingWithAsset>, (authority, instruction));
///
///     CanDoSomethingWithAsset {
///        some_data: "some data".to_owned(),
///        asset_id: parse!("rose#wonderland" as <Asset as Identifiable>::Id),
///     }.is_owned_by(&authority)
/// }
/// ```
#[proc_macro_derive(Token)]
pub fn derive_token(input: TokenStream) -> TokenStream {
    token::impl_derive_token(input)
}

/// Derive macro for `Validate` trait.
///
/// # Attributes
///
/// This macro requires `validate` or a group of `validate_grant` and `validate_revoke` attributes.
///
/// ## `validate` attribute
///
/// Use `validate` to specify [*Pass Condition*](#pass_conditions) for both `Grant` and `Revoke`
/// instructions validation.
///
/// ## `validate_grant` and `validate_revoke` attributes
///
/// Use `validate_grant` together with `validate_revoke` to specify *pass condition* for
/// `Grant` and `Revoke` instructions validation separately.
///
/// # Pass conditions
///
/// You can pass any type implementing `iroha_validator::pass_conditions::PassCondition`
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
/// Also check out `iroha_validator::pass_conditions::derive_conversion` module
/// for conversion derive macros from your token to this *Pass Conditions*.
///
/// ## Why *Pass Conditions*?
///
/// With that you can easily derive one of most popular implementations to remove boilerplate code.
///
/// ## Manual `Validate` implementation VS Custom *Pass Condition*
///
/// General advice is to use custom *Pass Condition* if you need this custom validation
/// multiple times in different tokens. Otherwise, you can implement `Validate` trait manually.
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
// #[derive(Token, Validate)]
// #[validate(Creator || Admin)]
// pub struct CanDoSomethingWithAsset {
//     ...
// }
// ```
#[proc_macro_derive(Validate, attributes(validate, validate_grant, validate_revoke))]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    validate::impl_derive_validate(input)
}

/// Should be used together with [`Validate`] derive macro to derive a conversion
/// from your token to a `pass_conditions::asset_definition::Owner` type.
///
/// Requires `asset_definition_id` field in the token.
///
/// Implements [`From`] for `pass_conditions::asset_definition::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAssetDefinitionOwner)]
pub fn derive_ref_into_asset_definition_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_asset_definition_owner(input)
}

/// Should be used together with [`Validate`] derive macro to derive a conversion
/// from your token to a `pass_conditions::asset::Owner` type.
///
/// Requires `asset_id` field in the token.
///
/// Implements [`From`] for `pass_conditions::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAssetOwner)]
pub fn derive_ref_into_asset_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_asset_owner(input)
}

/// Should be used together with [`Validate`] derive macro to derive a conversion
/// from your token to a `pass_conditions::account::Owner` type.
///
/// Requires `account_id` field in the token.
///
/// Implements [`From`] for `pass_conditions::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[proc_macro_derive(RefIntoAccountOwner)]
pub fn derive_ref_into_account_owner(input: TokenStream) -> TokenStream {
    conversion::impl_derive_ref_into_account_owner(input)
}
