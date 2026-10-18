//! Shared genuine proof builder; no registered test cases.
//! Recursive obligation ownership, with genuine Bootstrap state and signed-object
//! composition through the signature Q and the unsplit terminal A. Send tests still
//! isolate its frame.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../bootstrap_objects.rs"]
#[allow(dead_code)] // Shared payer/receiver helpers are consumed by distinct test binaries.
mod bootstrap_objects;
/// Shared test caches owned by this genuine Bootstrap fixture module.
#[path = "../mod.rs"]
pub mod common;
include!("a_recursive_body.rs");
