//! Network I/O for SCCP v1 (spec `specs/sccp.md` §8).
//!
//! This crate talks to the outside world on behalf of the irohad light-client
//! keeper (§4.13.4), the `iroha sccp` CLI and the SCCP wallet (§7):
//!
//! - public-RPC endpoint lists with failover, seeded start indices, rotation
//!   away from endpoints that answer badly, poll budgets and owner-only
//!   secret headers;
//! - blocking HTTP over rustls with one wall-clock deadline per attempt, and
//!   `norito::json` parsing under per-route byte caps and decode limits
//!   ([`limits`]); receipt proofs instead decode JSON incrementally into a bounded
//!   canonical RLP spool, retaining unrelated leaf hashes rather than receipt graphs.
//!   The configured whole-response ceiling and attempt deadline still apply;
//! - EVM JSON-RPC, the beacon light-client API and a TON ADNL-TCP liteclient;
//! - builders for light-client advances, backfills, bootstraps, inbound
//!   proofs and void proofs.
//!
//! Nothing this crate returns is trusted. Every response and every evidence
//! bundle it builds is verified by `iroha_sccp`, the same network-free
//! verifier Taira runs, so a lying endpoint can only cause rejected
//! submissions.

pub mod beacon;
pub mod builders;
pub mod endpoints;
pub mod evm;
pub mod http;
pub mod limits;
pub mod ton;

pub use beacon::BeaconClient;
pub use endpoints::{Backoff, EndpointSet, FailoverPolicy, HttpEndpointKind, PollBudget};
pub use evm::EvmClient;
pub use http::{HttpConfig, HttpTransport, RpcError};

mod receipt_stream;
mod receipt_trie;

mod transaction_proof;
