//! Crate with executor-related derive macros.

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow, Result};
use proc_macro2::TokenStream;

mod conversion;
mod default;
mod entrypoint;
mod permission;
mod validate;

/// Annotate the user-defined function that starts the execution of a executor.
///
/// There are 4 acceptable forms of this macro usage. See examples.
///
/// # Examples
///
/// ```ignore
/// use iroha_executor::prelude::*;
///
/// #[entrypoint]
/// pub fn migrate(block_height: u64) -> MigrationResult {
///     todo!()
/// }
///
/// #[entrypoint]
/// pub fn validate_transaction(
///     authority: AccountId,
///     transaction: SignedTransaction,
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
#[manyhow]
#[proc_macro_attribute]
pub fn entrypoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(
            emitter,
            "`#[entrypoint]` macro for Executor entrypoints accepts no attributes"
        );
    }

    let Some(item) = emitter.handle(syn::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let result = entrypoint::impl_entrypoint(&mut emitter, item);

    emitter.finish_token_stream_with(result)
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
///        asset_id: parse!(AssetId, "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"),
///     }.is_owned_by(&authority)
/// }
/// ```
#[manyhow]
#[proc_macro_derive(Permission)]
pub fn derive_permission(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(permission::impl_derive_permission(&input))
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
/// You can pass any type implementing `iroha_executor::permission::PassCondition`
/// and `From<&YourToken>` traits.
///
/// ## Builtin
///
/// There are some builtin pass conditions:
///
/// - `asset_definition::Owner` - checks if the authority is the asset definition owner;
/// - `asset::Owner` - checks if the authority is the asset owner;
/// - `account::Owner` - checks if the authority is the account owner.
/// - `domain::Owner` - checks if the authority is the domain owner.
/// - `AlwaysPass` - checks nothing and always passes.
/// - `OnlyGenesis` - checks that block height is 0.
///
///
/// Also check out `iroha_executor::permission::derive_conversion` module
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
#[manyhow]
#[proc_macro_derive(
    ValidateGrantRevoke,
    attributes(validate, validate_grant, validate_revoke)
)]
pub fn derive_validate_grant_revoke(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;
    validate::impl_derive_validate_grant_revoke(&input)
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::asset_definition::Owner` type.
///
/// Requires `asset_definition_id` field in the token.
///
/// Implements [`From`] for `permission::asset_definition::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[manyhow]
#[proc_macro_derive(RefIntoAssetDefinitionOwner)]
pub fn derive_ref_into_asset_definition_owner(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(conversion::impl_derive_ref_into_asset_definition_owner(
        &input,
    ))
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::asset::Owner` type.
///
/// Requires `asset_id` field in the token.
///
/// Implements [`From`] for `permission::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[manyhow]
#[proc_macro_derive(RefIntoAssetOwner)]
pub fn derive_ref_into_asset_owner(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(conversion::impl_derive_ref_into_asset_owner(&input))
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::account::Owner` type.
///
/// Requires `account_id` field in the token.
///
/// Implements [`From`] for `permission::asset::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[manyhow]
#[proc_macro_derive(RefIntoAccountOwner)]
pub fn derive_ref_into_account_owner(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(conversion::impl_derive_ref_into_account_owner(&input))
}

/// Should be used together with [`ValidateGrantRevoke`] derive macro to derive a conversion
/// from your token to a `permission::domain::Owner` type.
///
/// Requires `domain_id` field in the token.
///
/// Implements [`From`] for `permission::domain::Owner`
/// and not [`Into`] for your type. [`Into`] will be implemented automatically.
#[manyhow]
#[proc_macro_derive(RefIntoDomainOwner)]
pub fn derive_ref_into_domain_owner(input: TokenStream) -> Result<TokenStream> {
    let input = syn::parse2(input)?;

    Ok(conversion::impl_derive_ref_into_domain_owner(&input))
}

/// Implements the `iroha_executor::Validate` trait for the given `Executor` struct. As
/// this trait has a `iroha_executor::prelude::Visit` at least this one should be implemented as well.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding
/// types, i.e. `verdict`: `iroha_executor::prelude::Result` and `block_height`: `u64`.
/// The types can be unqualified, but not aliased.
#[manyhow]
#[proc_macro_derive(Validate)]
pub fn derive_validate(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_validate(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}

/// Implements the `iroha_executor::prelude::Visit` trait on a given `Executor` struct.
/// Users can supply custom overrides for any of the visit functions as freestanding functions
/// in the same module via the `#[visit(custom(...))]` attribute by
/// supplying corresponding visit function names inside of it, otherwise a default
/// implementation from `iroha_executor::default` module is used.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding
/// types, i.e. `verdict`: `iroha_executor::prelude::Result` and `block_height`: `u64`,
/// though technically only `verdict` is needed. The types can be unqualified, but not aliased.
///
/// # Example
///
/// ```ignore
/// use iroha_executor::prelude::*;
///
/// #[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
/// #[visit(custom(visit_query)]
/// pub struct Executor {
///    verdict: Result,
///    block_height: u64,
/// }
///
/// // Custom visit function should supply a `&mut Executor` as first argument
/// fn visit_query(executor: &mut Executor, _authority: &AccountId, _query: &QueryBox) {
///     executor.deny(ValidationFail::NotPermitted(
///         "All queries are forbidden".to_owned(),
///     ));
/// }
/// ```
#[manyhow]
#[proc_macro_derive(Visit, attributes(visit))]
pub fn derive_visit(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_visit(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}

/// Implements three default entrypoints on a given `Executor` struct: `validate_transaction`,
/// `validate_query` and `validate_instruction`. The `migrate` entrypoint is implied to be
/// implemented manually by the user at all times.
///
/// Users can supply custom overrides for any of the entrypoint functions as freestanding functions
/// in the same module via the `#[entrypoints(custom(...))]` attribute by
/// supplying corresponding entrypoint function names inside of it.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding
/// types, i.e. `verdict`: `iroha_executor::prelude::Result` and `block_height`: `u64`,
/// though technically only `verdict` is needed. The types can be unqualified, but not aliased.
///
/// # Example
///
/// ```ignore
/// use iroha_executor::prelude::*;
///
/// #[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
/// #[entrypoints(custom(validate_query))]
/// pub struct Executor {
///    verdict: Result,
///    block_height: u64,
/// }
/// ```
#[manyhow]
#[proc_macro_derive(ValidateEntrypoints, attributes(entrypoints))]
pub fn derive_entrypoints(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_entrypoints(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}

/// Implements a constructor for the given `Executor` struct. If the `Executor` has any custom fields
/// (i.e. different from the expected fields listed below), they will be included into the constructor
/// automatically and will need to be passed into `new()` function explicitly. In the default case,
/// only the `block_height` needs to be supplied manually.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding
/// types, i.e. `verdict`: `iroha_executor::prelude::Result` and `block_height`: `u64`.
/// The types can be unqualified, but not aliased.
#[manyhow]
#[proc_macro_derive(Constructor)]
pub fn derive_constructor(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_constructor(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}
