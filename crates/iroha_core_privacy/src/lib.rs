//! State-free native privacy engines, compiled profiles, verified effects and execution proofs.
//!
//! Core owns ledger storage and mounts these modules internally. Module names,
//! explicit `iroha_core::` schema identities and logging targets remain stable.
//! `iroha_core` `EnvFilter` directives also prefix-match this owner crate's targets.
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

#[cfg(test)]
mod test_support;
