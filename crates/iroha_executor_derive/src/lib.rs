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
/// #[migrate]
/// fn migrate(host: Iroha, context: Context) {
///     todo!()
/// }
/// ```
#[manyhow]
#[proc_macro_attribute]
pub fn migrate(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    if !attr.is_empty() {
        emit!(
            emitter,
            "`#[migrate]` macro for Executor accepts no attributes"
        );
    }

    let Some(item) = emitter.handle(syn::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let result = entrypoint::impl_migrate_entrypoint(item);

    emitter.finish_token_stream_with(result)
}

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
/// fn execute_transaction(transaction: SignedTransaction, host: Iroha, context: Context) -> Result {
///     todo!()
/// }
///
/// #[entrypoint]
/// fn execute_instruction(instruction: InstructionBox, host: Iroha, context: Context) -> Result {
///     todo!()
/// }
///
/// #[entrypoint]
/// fn validate_query(query: QueryBox, host: Iroha, context: Context) -> Result {
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

    let result = entrypoint::impl_validate_entrypoint(&mut emitter, item);

    emitter.finish_token_stream_with(result)
}

/// Implements the `iroha_executor::Validate` trait for the given `Executor` struct. As
/// this trait has a `iroha_executor::prelude::Visit` at least this one should be implemented as well.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding types.
#[manyhow]
#[proc_macro_derive(Execute)]
pub fn derive_execute(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_execute(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}

/// Implements the `iroha_executor::prelude::Visit` trait on a given `Executor` struct.
/// Users can supply custom overrides for any of the visit functions as freestanding functions
/// in the same module via the `#[visit(custom(...))]` attribute by
/// supplying corresponding visit function names inside of it, otherwise a default
/// implementation from `iroha_executor::default` module is used.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding types.
///
/// # Example
///
/// ```ignore
/// use iroha_executor::prelude::*;
///
/// #[derive(Visit, Execute, Entrypoints)]
/// #[visit(custom(visit_query)]
/// struct Executor {
///    host: Iroha,
///    context: Context,
///    verdict: Result,
/// }
///
/// // Custom visit function should supply a `&mut Executor` as first argument
/// fn visit_query(executor: &mut Executor, _query: &AnyQueryBox) {
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

/// Implements three default entrypoints on a given `Executor` struct: `execute_transaction`,
/// `validate_query` and `execute_instruction`. The `migrate` entrypoint is implied to be
/// implemented manually by the user at all times.
///
/// Users can supply custom overrides for any of the entrypoint functions as freestanding functions
/// in the same module via the `#[entrypoints(custom(...))]` attribute by
/// supplying corresponding entrypoint function names inside of it.
///
/// Emits a compile error if the struct didn't have all the expected fields with corresponding types.
///
/// # Example
///
/// ```ignore
/// use iroha_executor::prelude::*;
///
/// #[derive(Visit, Validate, Entrypoints)]
/// #[entrypoints(custom(validate_query))]
/// struct Executor {
///    host: Iroha,
///    context: Context,
///    verdict: Result,
/// }
/// ```
#[manyhow]
#[proc_macro_derive(Entrypoints, attributes(entrypoints))]
pub fn derive_entrypoints(input: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(input) = emitter.handle(syn::parse2(input)) else {
        return emitter.finish_token_stream();
    };

    let result = default::impl_derive_entrypoints(&mut emitter, &input);

    emitter.finish_token_stream_with(result)
}
