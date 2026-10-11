#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Nexus-specific integration test modules.
#[cfg(feature = "atomic-private-settlement-release")]
mod atomic_private_settlement_localnet;
mod cbdc_rollout_bundle;
mod cbdc_whitelist;
mod cross_dataspace_zk_stark_localnet;
mod cross_lane;
mod lane_registry;
mod localnet_npos;
mod multilane_pipeline;
mod privacy_proof_enforcement;
mod tx_query_cross_dataspace_routing_localnet;
