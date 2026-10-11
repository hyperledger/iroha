//! Shared test fixtures for SDKs and guardrails.
//!
//! These helpers expose canonical wire fixtures used across guard scripts,
//! generators, and SDK regression tests.
/// Atomic cross-transaction fixtures.
pub mod axt;
/// Canonical V1 appeal-finance cancellation fixtures.
pub mod cancel_asset_lock;

/// Genuine native certificate/checkpoint fixtures; execution outputs remain synthetic test inputs.
#[cfg(feature = "transparent_api")]
pub mod native_finality;
/// Deterministic validator-generation and epoch-authorization builders.
pub mod sumeragi_epoch;
