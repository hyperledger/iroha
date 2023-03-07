//! Macros for writing smart contracts and validators

use proc_macro::TokenStream;

mod entrypoint;
mod validator;

/// Annotate the user-defined function that starts the execution of a smart contract.
///
/// # Attributes
///
/// This macro can have an attribute describing entrypoint parameters.
///
/// The syntax is:
/// `#[iroha_wasm::entrypoint(params = "[<type>,*]")]`, where `<type>` is one of:
/// - `authority` is an account id of the smart contract authority
/// - `triggering_event` is an event that triggers the execution of the smart contract
///
/// None, one or both parameters in any order can be specified.
/// Parameters will be passed to the entrypoint function in the order they are specified.
///
/// ## Authority
///
/// A function parameter type corresponding to the `authority` should have
/// `iroha_wasm::data_model::prelude::AccountId` type.
///
/// ## Triggering event
///
/// A function parameter type corresponding to the `triggering_event` should have
/// type implementing `TryFrom<iroha_data_model::prelude::Event>`.
///
/// So any subtype of `Event` can be specified, i.e. `TimeEvent` or `DataEvent`.
/// For details see `iroha_wasm::data_model::prelude::Event`.
///
/// If conversion will fail in runtime then an error message will be printed,
/// if `debug` feature is enabled.
///
/// # Panics
///
/// - If got unexpected syntax of attribute
/// - If function has a return type
///
/// # Examples
///
// `ignore` because this macro idiomatically should be imported from `iroha_wasm` crate.
//
/// Using without parameters:
/// ```ignore
/// #[iroha_wasm::entrypoint]
/// fn trigger_entrypoint() {
///     // do stuff
/// }
/// ```
///
/// Using only `authority` parameter:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id) {
///     dbg(&format!("Trigger authority: {authority}"));
/// }
/// ```
///
/// Using both `authority` and `triggering_event` parameters:
/// ```ignore
/// use iroha_wasm::{data_model::prelude::*, dbg};
///
/// #[iroha_wasm::entrypoint(params = "[authority, triggering_event]")]
/// fn trigger_entrypoint(authority: <Account as Identifiable>::Id, event: DataEvent) {
///     dbg(&format!(
///         "Trigger authority: {authority};\n\
///          Triggering event: {event:?}"
///     ));
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    entrypoint::impl_entrypoint(attr, item)
}

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
/// `#[iroha_wasm::validator_entrypoint(params = "[<type>,*]")]`, where `<type>` is one of:
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
/// `iroha_wasm::data_model::prelude::AccountId` type.
///
/// ## Transaction
///
/// A real function parameter type corresponding to the `transaction` should have
/// `iroha_wasm::data_model::prelude::SignedTransaction` type.
///
/// ## Instruction
///
/// A real function parameter type corresponding to the `instruction` should have
/// `iroha_wasm::data_model::prelude::Instruction` type.
///
/// ## Query
///
/// A real function parameter type corresponding to the `query` should have
/// `iroha_wasm::data_model::prelude::QueryBox` type.
///
/// ## Expression
///
/// A real function parameter type corresponding to the `expression` should have
/// `iroha_wasm::data_model::prelude::Expression` type.
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
/// use iroha_wasm::validator::prelude::*;
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
/// use iroha_wasm::validator::prelude::*;
///
/// #[entrypoint(params = "[authority, instruction]")]
/// pub fn validate(authority: AccountId, _: Instruction) -> Verdict {
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
pub fn validator_entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    validator::entrypoint::impl_entrypoint(attr, item)
}

/// Derive macro for `Token` trait.
///
/// # Example
///
/// ```ignore
/// use iroha_wasm::{parse, validator::{pass_conditions, prelude::*}};
///
/// #[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
/// #[validate(pass_conditions::asset::Owner)]
/// struct CanDoSomethingWithAsset {
///     some_data: String,
///     asset_id: <Asset as Identifiable>::Id,
/// }
///
/// #[entrypoint(params = "[authority, instruction]")]
/// fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
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
    validator::token::impl_derive_token(input)
}

/// Derive macro for `Validate` trait.
///
/// # Attributes
///
/// This macro requires `validate` or a group of `validate_grant` and `validate_revoke` attributes.
///
/// ## `validate` attribute
///
/// Use `validate` to specify *Pass Condition* (see below) for both `Grant` and `Revoke`
/// instructions validation.
///
/// ## `validate_grant` and `validate_revoke` attributes
///
/// Use `validate_grant` together with `validate_revoke` to specify *pass condition* for
/// `Grant` and `Revoke` instructions validation separately.
///
/// # Pass conditions
///
/// You can pass any type implementing `iroha_wasm::validator::pass_conditions::PassCondition`
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
/// Also check out `iroha_wasm::validator::pass_conditions::derive_conversion` module
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
    validator::validate::impl_derive_validate(input)
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
    validator::conversion::asset_definition::impl_derive_ref_into_asset_definition_owner(input)
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
    validator::conversion::asset::impl_derive_ref_into_asset_owner(input)
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
    validator::conversion::account::impl_derive_ref_into_account_owner(input)
}
