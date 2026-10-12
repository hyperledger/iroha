//! Consolidated integration-test harness for `iroha_config`.
#[path = "autoscale_config.rs"]
mod autoscale_config;
#[path = "checked_in_profiles_parse.rs"]
mod checked_in_profiles_parse;
#[path = "compute_economics.rs"]
mod compute_economics;
#[path = "connect_relay_strategy_hard_cut.rs"]
mod connect_relay_strategy_hard_cut;
#[path = "da_ingest_compute_limit.rs"]
mod da_ingest_compute_limit;
#[path = "fastpq_queue_overrides.rs"]
mod fastpq_queue_overrides;
#[path = "fixtures.rs"]
mod fixtures;
#[path = "governance_alternates_parse.rs"]
mod governance_alternates_parse;
#[path = "governance_citizen_service_parse.rs"]
mod governance_citizen_service_parse;
#[path = "kaigi_authorization_config_v1.rs"]
mod kaigi_authorization_config_v1;
#[path = "kura_retention_hard_cut.rs"]
mod kura_retention_hard_cut;
#[path = "minamoto_profile.rs"]
mod minamoto_profile;
#[path = "native_context_archive_limit.rs"]
mod native_context_archive_limit;
#[path = "network_scion_hard_cut.rs"]
mod network_scion_hard_cut;
#[path = "nexus_staking_bounds.rs"]
mod nexus_staking_bounds;
#[path = "nexus_staking_withdraw_grace_hard_cut.rs"]
mod nexus_staking_withdraw_grace_hard_cut;
#[path = "operator_auth_bootstrap_hard_cut.rs"]
mod operator_auth_bootstrap_hard_cut;
#[path = "p2p_hard_cut.rs"]
mod p2p_hard_cut;
#[path = "pipeline_cycle_ceiling.rs"]
mod pipeline_cycle_ceiling;
#[path = "pipeline_signature_batch_alias_hard_cut.rs"]
mod pipeline_signature_batch_alias_hard_cut;
#[path = "push_provider_credentials.rs"]
mod push_provider_credentials;
#[path = "queue_plan_retirement.rs"]
mod queue_plan_retirement;
#[path = "sorafs_gateway_runtime_providers.rs"]
mod sorafs_gateway_runtime_providers;
#[path = "sorafs_governance_dag_runtime_signer.rs"]
mod sorafs_governance_dag_runtime_signer;
#[path = "sorafs_native_transaction_signers.rs"]
mod sorafs_native_transaction_signers;
#[path = "sorafs_por_replay_archive.rs"]
mod sorafs_por_replay_archive;
#[path = "sorafs_provider_ingest_finalized_archive.rs"]
mod sorafs_provider_ingest_finalized_archive;
#[path = "sorafs_reputation_finalized_archive.rs"]
mod sorafs_reputation_finalized_archive;
#[path = "sorafs_storage_pin_aliases.rs"]
mod sorafs_storage_pin_aliases;
#[path = "sorafs_stream_token_runtime_signer.rs"]
mod sorafs_stream_token_runtime_signer;
#[path = "soranet_privacy_ingest_hard_cut.rs"]
mod soranet_privacy_ingest_hard_cut;
#[path = "sumeragi_core_config.rs"]
mod sumeragi_core_config;
#[path = "transaction_gossip_config.rs"]
mod transaction_gossip_config;
#[path = "transaction_ingress_limits.rs"]
mod transaction_ingress_limits;
#[path = "trusted_peers_pop_validation.rs"]
mod trusted_peers_pop_validation;
#[path = "zk_validity_env_independence.rs"]
mod zk_validity_env_independence;
