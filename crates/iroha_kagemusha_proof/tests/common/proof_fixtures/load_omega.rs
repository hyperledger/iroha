//! Shared genuine proof builder; no registered test cases.
//! Genuine single-terminal native Load wrapped by the complete Omega predicate.
//! Bootstrap-only or two-terminal catalogs remain explicit component scopes;
//! neither establishes the complete operation catalog or production byte gate.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

/// Shared genuine Bootstrap predecessor and single-terminal Load continuation fixtures.
#[path = "a_load_recursive.rs"]
pub mod load_chain;

#[path = "../mod.rs"]
mod common;

include!("load_omega_body.rs");
