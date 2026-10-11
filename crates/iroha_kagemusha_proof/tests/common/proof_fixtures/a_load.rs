//! Shared genuine proof builder; no registered test cases.
//! Genuine Load sigma, ordinary receipt, own signature Q and production-depth recovery.
//! Component checks here do not accept a lineage without the recursive A chain.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../bootstrap_objects.rs"]
#[allow(dead_code)] // Bootstrap and Load share signing helpers; each consumes distinct objects.
pub(crate) mod bootstrap_objects;
#[path = "../mod.rs"]
mod common;
#[path = "../load_objects.rs"]
mod load_objects;

include!("a_load_body.rs");
