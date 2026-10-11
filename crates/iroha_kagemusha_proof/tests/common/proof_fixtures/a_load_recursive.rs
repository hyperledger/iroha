//! Shared genuine proof builder; no registered test cases.
//! Native four-stage Load fixture intake. Callers must supply the installed
//! originals and genuine finalized receipt evidence for the exact predecessor.
//! No synthetic funding source or alternate test-only Load circuit exists here.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]
#![allow(clippy::duplicate_mod)] // Reuses independently executable Bootstrap fixtures.

/// Genuine Bootstrap predecessor fixtures, independently tested in their own suite.
#[path = "bootstrap_omega.rs"]
pub mod bootstrap_outer;
#[path = "../mod.rs"]
mod common;

include!("a_load_recursive_body.rs");
