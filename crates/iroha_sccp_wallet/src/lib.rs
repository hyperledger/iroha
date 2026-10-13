//! Local SCCP v1 wallet library (spec `specs/sccp.md` §7, §8).
//!
//! Wallets run this library against any Taira peer's Torii and the public RPC
//! endpoints in the user's `[sccp]` client configuration; no hosted service
//! is involved. It holds:
//!
//! - `pure`: network-free verification of proof bundles, rotation chains and
//!   Parliament/fast-pause controls against independently observed native destination state, and destination
//!   transaction encodings (EVM calldata and EIP-1559 signing; TON),
//!   exportable to SDK bridges;
//! - `config`: the canonical nested `[sccp]` client table (endpoint lists, timeouts,
//!   pinned deployments per Taira `NetworkId`), retained from the original client parse;
//! - `journal`: the resumable journal keyed by `NetworkId`, built on
//!   `iroha_operation_journal`.
//!
//! This crate is never linked into `irohad`; the `sccp_wallet` layer in
//! `ci/dependency_budget.json` enforces that boundary.
//!
//! - `flow`: typed transfers, deployment and maintenance transitions, exact-byte dispatch and
//!   original observation before an explicit identical-byte rebroadcast. Signing keys remain runtime-only.

pub mod config;
pub mod flow;
pub mod journal;
pub mod pure;
