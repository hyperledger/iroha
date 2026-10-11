//! Kotodama V1 source-surface registry shared by the compiler and contract
//! admission.
//!
//! This crate owns the canonical builtin registry, the generated V1 source
//! policy tables and the reserved-name predicates. It depends only on `ivm_abi`
//! and `strum`, so admission and the VM can share source policy without depending
//! on the compiler implementation. Tooling uses the same registry of reserved
//! source names.

pub mod builtin_docs;
pub mod builtins;
pub mod source_policy;
