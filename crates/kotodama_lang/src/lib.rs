//! KOTODAMA high-level language support.
//!
//! Bytecode Target
//! ---------------
//! Kotodama compiles to Iroha Virtual Machine (IVM) bytecode (`.to`). It does not target RISC‑V as
//! a standalone architecture. The compiler now emits IVM's native wide (8-bit opcode) encodings
//! exclusively. Earlier RISC‑V–like encodings (e.g., classic `0x33/0x13` ALU forms) are rejected by
//! the VM loader and interpreter; they now exist only in regression tests that verify the trap
//! behaviour. Observable behavior and outputs are defined by IVM.
//!
//! This module provides the building blocks for a compiler that translates
//! Kotodama source programs into IVM bytecode.
//!
//! Multi-file projects use [`linker::SourceLinkRequest`]: a deployable root, explicit companion
//! sources, and optional locked packages. [`session::CompilerSession::build_source_bundle`]
//! compiles that closed inventory without filesystem access. [`compiler::Compiler::compile_file`]
//! loads the declared include/import closure within the entry file's parent directory; the build
//! driver and CLI also accept an explicit source root. Declaration includes share their owner's
//! scope, while imported modules expose only declarations marked `export`.
mod abi_schema;
pub mod ast;
mod call_abi;
mod checked_arithmetic;
pub mod compiler;
pub mod diagnostic;
mod doc_consistency;
pub mod driver;
pub mod editor;
pub mod formatter;
pub mod glossary;
pub mod i18n;
pub mod ir;
pub mod lexer;
pub mod linker;
pub mod lint;
pub mod parser;
pub mod policy;
pub mod regalloc;
pub mod resolved;
mod result_use;
mod secret;
pub mod semantic;
mod semantic_diagnostics;
pub mod session;
pub mod signature_render;
pub mod source;
pub mod spanned_ast;
mod ssa;
pub mod syntax;
pub mod testing;
pub use ivm_abi::{
    Perm, SyscallPolicy, VMError, axt, dev_env, encoding, instruction, metadata, pointer_abi,
    syscalls,
};
