//! Local SCCP v1 wallet library (spec `specs/sccp.md` §7, §8).
//!
//! Wallets run this library against any Taira peer's Torii and the public RPC
//! endpoints in the user's `[sccp]` client configuration; no hosted service
//! is involved. It holds:
//!
//! - `pure`: network-free verification of proof bundles, rotation chains and
//!   Parliament controls against the destination's own state, and destination
//!   transaction encodings (EVM calldata and EIP-1559 signing; TON),
//!   exportable to SDK bridges;
//! - `config`: the file-only `[sccp]` table (endpoint lists, timeouts, pinned
//!   deployments per Taira `NetworkId`), kept in its own file beside the
//!   client config until the `iroha` client config root nests it;
//! - `journal`: the resumable journal keyed by `NetworkId`, built on
//!   `iroha_operation_journal`.
//!
//! This crate is never linked into `irohad`; the `sccp_wallet` layer in
//! `ci/dependency_budget.json` enforces that boundary.
//!
//! TODO(ws51): add the resumable outbound (§7.1), inbound (§7.2) and refund
//! (§7.3) flows, which verify every piece of evidence before paying and
//! journal it before submitting anything, with a shared flow driver and
//! resume logic.

pub mod config;
pub mod journal;
pub mod pure;
