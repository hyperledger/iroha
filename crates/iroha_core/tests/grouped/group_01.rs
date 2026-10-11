//! Grouped Iroha Core integration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "../asset_total_amount.rs"]
mod asset_total_amount;
#[path = "../bench_repro.rs"]
mod bench_repro;
#[path = "../bridge_proofs.rs"]
mod bridge_proofs;
#[path = "../cache_policy.rs"]
mod cache_policy;
#[path = "../check_genesis_sig.rs"]
mod check_genesis_sig;
#[path = "../confidential_params_registry.rs"]
mod confidential_params_registry;
#[path = "../confidential_policy_gates.rs"]
mod confidential_policy_gates;
#[path = "../confidential_tree_defaults.rs"]
mod confidential_tree_defaults;
#[path = "../contract_code_bytes.rs"]
mod contract_code_bytes;
#[path = "../contract_execution_header_binding.rs"]
mod contract_execution_header_binding;
#[path = "../contract_manifest_triggers.rs"]
mod contract_manifest_triggers;
#[path = "../default_domain_independence.rs"]
mod default_domain_independence;
#[path = "../deterministic_tie_break.rs"]
mod deterministic_tie_break;
#[path = "../executor_migration_introspect.rs"]
mod executor_migration_introspect;
#[path = "../fastpq_transfer_batch.rs"]
mod fastpq_transfer_batch;
#[path = "../find_accounts_with_asset.rs"]
mod find_accounts_with_asset;
#[path = "../fraud_monitoring.rs"]
mod fraud_monitoring;
#[path = "../gov_auto_close_zk_requires_tally.rs"]
mod gov_auto_close_zk_requires_tally;
#[path = "../gov_bond_escrow.rs"]
mod gov_bond_escrow;
#[path = "../gov_citizenship.rs"]
mod gov_citizenship;
#[path = "../gov_finalize_real_vk.rs"]
mod gov_finalize_real_vk;
#[path = "../../src/manifest_signing_test_support.rs"]
mod manifest_signing_test_support;
#[path = "../native_finality_proof.rs"]
mod native_finality_proof;
