//! Shared genuine proof builder; no registered test cases.
//! Recursive obligation ownership, with genuine Bootstrap state and signed-object
//! composition through sigma, Q, A1, W and A2. Send tests still isolate its frame.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../bootstrap_objects.rs"]
#[allow(dead_code)] // Shared payer/receiver helpers are consumed by distinct test binaries.
mod bootstrap_objects;
#[path = "../mod.rs"]
mod common;
#[path = "../native_source_factory_checks.rs"]
mod native_source_factory_checks;
include!("a_recursive_body.rs");
