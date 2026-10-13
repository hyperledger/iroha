//! State-free native privacy engines, compiled profiles, verified effects and execution proofs.
//!
//! Core owns ledger storage and mounts these modules internally. Module names,
//! explicit `iroha_core::` schema identities and logging targets remain stable.
//! `iroha_core` EnvFilter directives also prefix-match this owner crate's targets.
// Nested `if` blocks remain intentional for readability/instrumentation; Clippy's
// `collapsible_if` lint would force let-chains that obscure the control flow.
#![allow(clippy::collapsible_if)]
#![allow(clippy::all)]
#![allow(clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(
    clippy::cast_lossless,
    clippy::cloned_instead_of_copied,
    clippy::clone_on_copy,
    clippy::collapsible_else_if,
    clippy::doc_markdown,
    clippy::explicit_iter_loop,
    clippy::identity_op,
    clippy::if_not_else,
    clippy::if_same_then_else,
    clippy::ignored_unit_patterns,
    clippy::iter_overeager_cloned,
    clippy::iter_with_drain,
    clippy::large_enum_variant,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_const_for_thread_local,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_continue,
    clippy::needless_pass_by_value,
    clippy::needless_return,
    clippy::option_if_let_else,
    clippy::ptr_arg,
    clippy::question_mark,
    clippy::redundant_closure_for_method_calls,
    clippy::redundant_pub_crate,
    clippy::result_large_err,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::useless_conversion,
    clippy::useless_let_if_seq
)]
#![cfg_attr(test, allow(clippy::large_stack_arrays))]
/// Native transparent execution proofs and bounded deterministic race relations.
pub mod execution_proofs;
#[cfg(test)]
mod ivm_test_support;
/// Typed Exact12 dispatch registry: verification, effect class and delivery per role.
pub mod privacy_dispatch;
/// Native transparent privacy protocol engines.
pub mod privacy_engines;
/// Deterministic compiled manifests for executable privacy engines.
pub mod privacy_profiles;
/// Durable records produced by verified first-release privacy actions.
pub mod privacy_state;
/// Exhaustive native proof verification and verified-effect derivation.
#[doc(hidden)]
pub mod privacy_verifier;
#[cfg(test)]
pub(crate) mod json_macros {
    pub use norito::derive::JsonDeserialize;
}
