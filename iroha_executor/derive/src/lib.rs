//! Crate with macros that facilitate writing a custom executor

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow};
use proc_macro2::TokenStream;

mod default;
mod entrypoint;

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
/// pub fn migrate(block_height: u64) {
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
/// fn visit_query(executor: &mut Executor, _authority: &AccountId, _query: &AnyQueryBox) {
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
