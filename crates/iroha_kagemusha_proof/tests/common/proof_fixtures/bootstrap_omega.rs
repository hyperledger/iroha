//! Shared genuine proof builder; no registered test cases.
//! Actual authenticated Bootstrap sigma/Q/A1/W/A2 wrapped by the complete Omega
//! predicate. Layout diagnostics do not establish the production transport cap.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

/// Shared authenticated Bootstrap proof-chain fixture.
#[path = "a_recursive.rs"]
pub mod bootstrap_chain;

/// Compact one-terminal rooted construction with explicit qualification scope.
#[path = "compact_bootstrap.rs"]
pub mod compact_bootstrap;

include!("bootstrap_omega_body.rs");
