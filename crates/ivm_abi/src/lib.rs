//! Shared ABI definitions for the Iroha Virtual Machine.
//!
//! This crate hosts the canonical opcode tables, metadata layout, pointer-ABI helpers, syscall
//! numbering, and related error types used by both the VM and the Kotodama compiler.
pub mod access_hints;
pub mod arguments;
pub mod axt;
pub mod call;
pub mod codec;
pub mod contract_call;
pub mod core_query;
pub mod dev_env;
pub mod encoding;
pub mod entrypoint;
pub mod error;
pub mod error_types;
pub mod host_payload;
pub mod instruction;
pub mod json;
pub mod list;
pub mod metadata;
pub mod numeric;
pub mod numeric_tlv;
pub mod pointer_abi;
pub mod private_input;
pub mod state_cursor;
pub mod state_value;
pub mod sum;
pub mod syscalls;
pub mod upgrade;
pub use error::{HostOutputResource, Perm, VMError};
/// Syscall policy determined by `ProgramMetadata.abi_version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallPolicy {
    /// ABI surface for version 1 programs.
    AbiV1,
}

#[cfg(test)]
mod captured_identity_tests;

#[cfg(test)]
mod enum_tests;
