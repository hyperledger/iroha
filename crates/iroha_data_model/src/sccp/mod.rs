//! SCCP v1 Taira-side data model.
//!
//! SCCP (SORA Cross-Chain Protocol) moves Taira XOR between the Taira Iroha network and the
//! Ethereum, BSC and TON mainnets. The normative design is `specs/sccp.md`.
//! These modules hold the Taira-internal Norito types: consensus parameters, native committee
//! generations, block commitments and the history accumulator, outbound and inbound records,
//! block leaves and destination controls, the route registry and escrow identity, inbound
//! light-client state, events and the Parliament governance payload. The v1 instructions live
//! in [`crate::isi::sccp`].
//!
//! Destinations verify Taira's Sumeragi `CommitQC`, so SCCP has no bridge key, attestation or
//! roster type. The finality header and the certified result it binds live in
//! [`crate::sumeragi_finality::certified_result`].
//!
//! Network profiles reuse [`crate::bridge::SccpNetworkV1`]; contract-visible byte layouts (§3)
//! live with the code that hashes them (`iroha_sccp::v1`), never in Norito derives. Per-chain
//! proofs, advances, bootstraps and consensus sets are opaque headered Norito frames decoded by
//! `iroha_sccp::light_client`, so this crate stays independent of chain structures.

pub mod bounded_bytes;
pub mod commitment;
pub mod control;
pub mod deployment;
pub mod escrow;
pub mod events;
pub mod fast_pause;
pub mod generation;
pub mod governance;
pub mod inbound;
pub mod light_client;
pub mod outbound;
pub mod params;
pub mod registry;

#[cfg(test)]
pub(crate) mod test_support;
