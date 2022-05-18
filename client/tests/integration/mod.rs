pub use iroha::config::Configuration;

mod add_account;
mod add_asset;
mod add_domain;
mod asset_propagation;
mod burn_public_keys;
mod config;
mod connected_peers;
mod events;
mod multiple_blocks_created;
mod multisignature_account;
mod multisignature_transaction;
mod non_mintable;
mod offline_peers;
mod pagination;
mod permissions;
mod queries;
mod query_errors;
mod restart_peer;
mod roles;
mod transfer_asset;
mod triggers;
mod tx_history;
mod tx_rollback;
mod unregister_peer;
#[cfg(not(coverage))]
mod unstable_network;
