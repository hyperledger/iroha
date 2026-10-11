//! VM-backed Kotodama developer toolchain.
//!
//! Hosts the `koto` CLI/LSP, the `dump_program` inspection tool and the
//! in-process Kotodama test runner. This crate owns VM-backed developer tools;
//! `kotodama_lang` owns compilation, and `ivm` owns the compiler-independent
//! runtime. Tools depend on those owners directly.

/// VM-backed Kotodama test runner shared by developer tools.
pub mod koto_test_driver;

/// Build-time warnings for unsupported production-host requirements.
pub mod deployment_diagnostics;
/// Shared diagnostic presentation and lint policy.
pub mod diagnostics;
/// Shared language-server engine for standalone and Musubi workspaces.
pub mod lsp;
