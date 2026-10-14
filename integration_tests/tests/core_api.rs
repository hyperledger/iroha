//! Grouped integration harness for core API, ledger, and application-surface tests.
#[path = "address_canonicalisation.rs"]
mod address_canonicalisation;
#[path = "app_api_canonical_auth.rs"]
mod app_api_canonical_auth;
#[path = "asset.rs"]
mod asset;
#[path = "asset_propagation.rs"]
mod asset_propagation;
#[path = "config.rs"]
mod config;
#[path = "contracts.rs"]
mod contracts;
#[path = "debug_genesis.rs"]
mod debug_genesis;
#[path = "domain_links.rs"]
mod domain_links;
#[path = "fraud_monitoring.rs"]
mod fraud_monitoring;
#[path = "genesis_json.rs"]
mod genesis_json;
#[path = "iroha_cli.rs"]
mod iroha_cli;
#[path = "misc.rs"]
mod misc;
#[path = "multisig.rs"]
mod multisig;
#[path = "musubi_registry.rs"]
mod musubi_registry;
#[path = "native_amx_network.rs"]
mod native_amx_network;
#[path = "native_escrow.rs"]
mod native_escrow;
#[path = "native_game_sessions.rs"]
mod native_game_sessions;
#[path = "native_payment_network.rs"]
mod native_payment_network;
#[path = "native_payment_receipt.rs"]
mod native_payment_receipt;
#[path = "nft.rs"]
mod nft;
#[path = "non_mintable.rs"]
mod non_mintable;
#[path = "pagination.rs"]
mod pagination;
#[path = "permissions.rs"]
mod permissions;
#[path = "pipeline_block_rejected.rs"]
mod pipeline_block_rejected;
#[path = "repo.rs"]
mod repo;
#[path = "roles.rs"]
mod roles;
#[path = "scheduler_teu.rs"]
mod scheduler_teu;
#[path = "set_parameter.rs"]
mod set_parameter;
#[path = "sns.rs"]
mod sns;
#[path = "sorafs_moderation_anchor.rs"]
mod sorafs_moderation_anchor;
#[path = "sorafs_network.rs"]
mod sorafs_network;
#[path = "sorafs_orderbook_ledger.rs"]
mod sorafs_orderbook_ledger;
#[cfg(unix)]
#[path = "sorafs_publication.rs"]
mod sorafs_publication;
#[cfg(unix)]
#[path = "sorafs_publication_authority.rs"]
mod sorafs_publication_authority;
#[cfg(unix)]
#[path = "sorafs_publication_compliance.rs"]
mod sorafs_publication_compliance;
#[cfg(unix)]
#[path = "sorafs_publication_config.rs"]
mod sorafs_publication_config;
#[cfg(unix)]
#[path = "sorafs_publication_http.rs"]
mod sorafs_publication_http;
#[path = "sorafs_repair_ledger.rs"]
mod sorafs_repair_ledger;
#[path = "sorafs_reserve_ledger.rs"]
mod sorafs_reserve_ledger;
#[path = "sorting.rs"]
mod sorting;
#[path = "telemetry.rs"]
mod telemetry;
#[path = "threshold_escrow.rs"]
mod threshold_escrow;
#[path = "torii_failure.rs"]
mod torii_failure;
#[path = "torii_load_profile.rs"]
mod torii_load_profile;
#[path = "transactions_filter.rs"]
mod transactions_filter;
#[path = "transfer_asset.rs"]
mod transfer_asset;
#[path = "transfer_domain.rs"]
mod transfer_domain;
#[path = "tx_chain_id.rs"]
mod tx_chain_id;
#[path = "tx_history.rs"]
mod tx_history;
#[path = "tx_rollback.rs"]
mod tx_rollback;
#[path = "upgrade.rs"]
mod upgrade;
