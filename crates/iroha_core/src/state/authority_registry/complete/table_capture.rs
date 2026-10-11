//! Exact catalog linking declared canonical tables to actual State readers.
//!
//! The catalog contains 217 table outputs in 216 capture groups. Complete table
//! coverage admits declared schema metadata and cannot authorize finality.
//! Even complete coverage will need one State publication cut, derived-index
//! checks, durable Kura node custody, predecessor binding and recovery before
//! any captured nodes may become an execution anchor.
//! TODO: capture prospective tables and cells from original frozen journals, then
//! consume their retained nodes through the State/Kura publication capsule.
//! Musubi availability/resolver/directory readers share one validated borrowed
//! source. State transaction membership retains one writer-owned pair and frontier;
//! its specialized node store still needs durable publication integration. Neither gate may be
//! skipped by supplying empty rows.

use super::{
    Canonical, CanonicalTableLeafSet, CanonicalTablePairedSnapshot, CompleteInventoryError, Field,
    LeafError, LeafLimits, Role, STATE_FIELDS, capture_account_alias_table_once,
    capture_accounts_table_once, capture_domains_table_once, require_complete_inventory, visit,
};
use super::{
    capture_account_rekey_records_once, capture_asset_definitions_once, capture_assets_once,
    capture_contract_alias_bindings_once, capture_contract_subject_bindings_once,
    capture_escrows_once, capture_governance_proposals_once, capture_nfts_once,
    capture_proofs_once, capture_repo_agreements_once, capture_rwas_once,
    capture_verifying_keys_once,
};
use crate::state::deserialize::musubi_source_work::{
    self, SourceValidationError, SourceWorkLimits, observation::MusubiSemanticTable,
};
use crate::state::{State, StateBlock, is_stable_state_view_generation};
use mv::storage::StorageReadOnly;

#[path = "table_capture/catalog.rs"]
mod catalog;
#[path = "table_capture/frozen.rs"]
pub(in crate::state) mod frozen;
use super::transaction_membership::{
    CapturedMembershipCompanion, MembershipCaptureError, MembershipWorkLimits,
    capture_membership_group_once,
};
use catalog::{TableMaterializer, require_exact_table_materializers};

const ALIAS_MATERIALIZER: TableMaterializer = TableMaterializer::Single {
    id: "world.account_aliases",
    capture: capture_account_alias_table_once,
};

include!("table_capture/capture_macros.rs");

#[cfg(test)]
#[path = "table_capture/checked_group_tests.rs"]
mod checked_group_tests;
#[cfg(test)]
#[path = "table_capture/confidential_policy_tests.rs"]
mod confidential_policy_tests;
#[cfg(test)]
#[path = "table_capture/contract_subject_tests.rs"]
mod contract_subject_tests;
#[cfg(test)]
#[path = "table_capture/native_test_support.rs"]
mod native_test_support;
#[path = "table_capture/native_world.rs"]
mod native_world;
#[cfg(test)]
#[path = "table_capture/proof_status_tests.rs"]
mod proof_status_tests;
#[cfg(test)]
#[path = "table_capture/validation_fee_proposal_tests.rs"]
mod validation_fee_proposal_tests;
#[cfg(test)]
#[path = "table_capture/verifying_key_tests.rs"]
mod verifying_key_tests;

#[path = "table_capture/musubi_native.rs"]
mod musubi_native;
use musubi_native::{
    capture_musubi_alias_history_once, capture_musubi_aliases_once,
    capture_musubi_governance_decisions_once, capture_musubi_resolver_index_checkpoints_once,
};

capture_world_table_once!(
    capture_public_lane_reward_accruals_once,
    public_lane_reward_accruals,
    "world.public_lane_reward_accruals"
);
capture_world_table_once!(
    capture_public_lane_stake_custody_once,
    public_lane_stake_custody,
    "world.public_lane_stake_custody"
);
capture_world_table_once!(
    capture_validator_candidate_keys_once,
    validator_candidate_keys,
    "world.validator_candidate_keys"
);
capture_world_table_once!(
    capture_validator_committee_transitions_once,
    validator_committee_transitions,
    "world.validator_committee_transitions"
);

capture_world_table_once!(
    capture_ram_lfe_program_policies_once,
    ram_lfe_program_policies,
    "world.ram_lfe_program_policies"
);
capture_world_table_once!(
    capture_identifier_policies_once,
    identifier_policies,
    "world.identifier_policies"
);
capture_world_table_once!(
    capture_fee_sponsor_programs_once,
    fee_sponsor_programs,
    "world.fee_sponsor_programs"
);
capture_world_table_once!(
    capture_fee_sponsor_program_revisions_once,
    fee_sponsor_program_revisions,
    "world.fee_sponsor_program_revisions"
);
capture_world_table_once!(
    capture_fee_sponsor_enrollments_once,
    fee_sponsor_enrollments,
    "world.fee_sponsor_enrollments"
);
capture_world_table_once!(
    capture_fee_sponsor_vaults_once,
    fee_sponsor_vaults,
    "world.fee_sponsor_vaults"
);
capture_world_table_once!(
    capture_fee_sponsor_budget_counters_once,
    fee_sponsor_budget_counters,
    "world.fee_sponsor_budget_counters"
);
capture_world_table_once!(
    capture_identifier_claims_once,
    identifier_claims,
    "world.identifier_claims"
);
capture_world_table_once!(
    capture_account_recovery_policies_once,
    account_recovery_policies,
    "world.account_recovery_policies"
);
capture_world_table_once!(
    capture_account_recovery_requests_once,
    account_recovery_requests,
    "world.account_recovery_requests"
);
capture_world_table_once!(
    capture_asset_definition_alias_bindings_once,
    asset_definition_alias_bindings,
    "world.asset_definition_alias_bindings"
);
capture_world_table_once!(
    capture_asset_metadata_once,
    asset_metadata,
    "world.asset_metadata"
);
capture_world_table_once!(capture_roles_once, roles, "world.roles");
capture_world_table_once!(
    capture_account_permissions_once,
    account_permissions,
    "world.account_permissions"
);
capture_world_table_once!(
    capture_account_roles_once,
    account_roles,
    "world.account_roles"
);
capture_world_table_once!(
    capture_oracle_feeds_once,
    oracle_feeds,
    "world.oracle_feeds"
);
capture_world_table_once!(
    capture_oracle_observations_once,
    oracle_observations,
    "world.oracle_observations"
);
capture_world_table_once!(
    capture_oracle_history_once,
    oracle_history,
    "world.oracle_history"
);
capture_world_table_once!(
    capture_oracle_provider_stats_once,
    oracle_provider_stats,
    "world.oracle_provider_stats"
);
capture_world_table_once!(
    capture_oracle_disputes_once,
    oracle_disputes,
    "world.oracle_disputes"
);
capture_world_table_once!(
    capture_oracle_changes_once,
    oracle_changes,
    "world.oracle_changes"
);
capture_world_table_once!(
    capture_defi_oracle_attestations_once,
    defi_oracle_attestations,
    "world.defi_oracle_attestations"
);
capture_world_table_once!(
    capture_twitter_bindings_once,
    twitter_bindings,
    "world.twitter_bindings"
);
capture_world_table_once!(
    capture_twitter_bindings_by_uaid_once,
    twitter_bindings_by_uaid,
    "world.twitter_bindings_by_uaid"
);
capture_world_table_once!(
    capture_viral_daily_counters_once,
    viral_daily_counters,
    "world.viral_daily_counters"
);
capture_world_table_once!(
    capture_viral_binding_claims_once,
    viral_binding_claims,
    "world.viral_binding_claims"
);
capture_world_table_once!(
    capture_viral_escrows_once,
    viral_escrows,
    "world.viral_escrows"
);
capture_world_table_once!(
    capture_viral_bonus_paid_once,
    viral_bonus_paid,
    "world.viral_bonus_paid"
);
capture_world_table_once!(
    capture_execution_proof_profiles_once,
    execution_proof_profiles,
    "world.execution_proof_profiles"
);
capture_world_table_once!(
    capture_execution_proof_verifications_once,
    execution_proof_verifications,
    "world.execution_proof_verifications"
);
capture_world_table_once!(
    capture_game_sessions_once,
    game_sessions,
    "world.game_sessions"
);
capture_world_table_once!(
    capture_nft_sale_offers_once,
    nft_sale_offers,
    "world.nft_sale_offers"
);
capture_world_table_once!(
    capture_nft_custody_records_once,
    nft_custody_records,
    "world.nft_custody_records"
);
capture_world_table_once!(capture_vpn_leases_once, vpn_leases, "world.vpn_leases");
capture_world_table_once!(
    capture_space_directory_manifests_once,
    space_directory_manifests,
    "world.space_directory_manifests"
);
capture_world_table_once!(
    capture_axt_handle_counters_once,
    axt_handle_counters,
    "world.axt_handle_counters"
);
capture_world_table_once!(
    capture_axt_asset_incarnations_once,
    axt_asset_incarnations,
    "world.axt_asset_incarnations"
);
capture_world_table_once!(
    capture_axt_replay_ledger_once,
    axt_replay_ledger,
    "world.axt_replay_ledger"
);
capture_world_table_once!(
    capture_axt_spend_nonce_ledger_once,
    axt_spend_nonce_ledger,
    "world.axt_spend_nonce_ledger"
);
capture_world_table_once!(
    capture_axt_source_transfer_replay_ledger_once,
    axt_source_transfer_replay_ledger,
    "world.axt_source_transfer_replay_ledger"
);
capture_world_table_once!(
    capture_axt_handle_budget_ledger_once,
    axt_handle_budget_ledger,
    "world.axt_handle_budget_ledger"
);
capture_world_table_once!(
    capture_tx_sequences_once,
    tx_sequences,
    "world.tx_sequences"
);

fn capture_trigger_action_once(
    state: &State,
    table: crate::smartcontracts::triggers::set::ActionTable,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    use crate::smartcontracts::triggers::set::{
        CheckedActions, TriggerContractError, action_source_work,
    };
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked =
        CheckedActions::capture(&state.world.triggers, action_source_work(limits), &budget);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let mut checked = match checked {
        Ok(checked) => checked,
        Err(TriggerContractError::Publication(mv::PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let outcome = checked.encode(table, limits);
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(outcome?))
}
fn capture_trigger_data_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    capture_trigger_action_once(
        state,
        crate::smartcontracts::triggers::set::ActionTable::Data,
        limits,
    )
}
fn capture_trigger_pipeline_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    capture_trigger_action_once(
        state,
        crate::smartcontracts::triggers::set::ActionTable::Pipeline,
        limits,
    )
}
fn capture_trigger_time_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    capture_trigger_action_once(
        state,
        crate::smartcontracts::triggers::set::ActionTable::Time,
        limits,
    )
}
fn capture_trigger_by_call_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    capture_trigger_action_once(
        state,
        crate::smartcontracts::triggers::set::ActionTable::ByCall,
        limits,
    )
}
fn capture_trigger_contracts_once(
    state: &State,
    limits: LeafLimits,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    use crate::smartcontracts::triggers::set::{
        CheckedContracts, TriggerContractError, contract_source_work,
    };
    let generation = state.state_view_generation();
    if generation & 1 != 0 {
        return Ok(None);
    }
    let budget = state.ivm_execution_budget();
    let checked =
        CheckedContracts::capture(&state.world.triggers, contract_source_work(limits), &budget);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    let mut checked = match checked {
        Ok(checked) => checked,
        Err(TriggerContractError::Publication(mv::PublicationPreparationError::Changed)) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let outcome = checked.encode(limits);
    let current = checked.matches_current();
    drop(checked);
    if !is_stable_state_view_generation(generation, state.state_view_generation()) {
        return Ok(None);
    }
    if !current? {
        return Ok(None);
    }
    Ok(Some(outcome?))
}

capture_world_table_once!(
    capture_consensus_keys_once,
    consensus_keys,
    "world.consensus_keys"
);
capture_world_table_once!(
    capture_consensus_keys_by_pk_once,
    consensus_keys_by_pk,
    "world.consensus_keys_by_pk"
);
capture_world_table_once!(
    capture_domain_committees_once,
    domain_committees,
    "world.domain_committees"
);
capture_world_table_once!(
    capture_domain_endorsement_policies_once,
    domain_endorsement_policies,
    "world.domain_endorsement_policies"
);
capture_world_table_once!(
    capture_domain_endorsements_once,
    domain_endorsements,
    "world.domain_endorsements"
);
capture_world_table_once!(
    capture_domain_endorsements_by_domain_once,
    domain_endorsements_by_domain,
    "world.domain_endorsements_by_domain"
);
capture_world_table_once!(
    capture_pedersen_params_once,
    pedersen_params,
    "world.pedersen_params"
);
capture_world_table_once!(
    capture_poseidon_params_once,
    poseidon_params,
    "world.poseidon_params"
);
capture_world_table_once!(
    capture_runtime_upgrades_once,
    runtime_upgrades,
    "world.runtime_upgrades"
);
capture_world_table_once!(
    capture_privacy_activations_once,
    privacy_activations,
    "world.privacy_activations"
);
capture_world_table_once!(
    capture_private_settlement_governance_once,
    private_settlement_governance,
    "world.private_settlement_governance"
);
capture_world_table_once!(
    capture_private_settlement_pools_once,
    private_settlement_pools,
    "world.private_settlement_pools"
);
capture_world_table_once!(
    capture_private_settlement_roots_once,
    private_settlement_roots,
    "world.private_settlement_roots"
);
capture_world_table_once!(
    capture_private_settlement_nullifiers_once,
    private_settlement_nullifiers,
    "world.private_settlement_nullifiers"
);
capture_world_table_once!(
    capture_private_settlement_outputs_once,
    private_settlement_outputs,
    "world.private_settlement_outputs"
);
capture_world_table_once!(
    capture_private_settlement_staged_locks_once,
    private_settlement_staged_locks,
    "world.private_settlement_staged_locks"
);
capture_world_table_once!(
    capture_private_settlement_receipts_once,
    private_settlement_receipts,
    "world.private_settlement_receipts"
);
capture_world_table_once!(
    capture_private_settlement_aborts_once,
    private_settlement_aborts,
    "world.private_settlement_aborts"
);
capture_world_table_once!(
    capture_privacy_pgc_accounts_once,
    privacy_pgc_accounts,
    "world.privacy_pgc_accounts"
);
capture_world_table_once!(
    capture_privacy_pgc_pool_invariants_once,
    privacy_pgc_pool_invariants,
    "world.privacy_pgc_pool_invariants"
);
capture_world_table_once!(
    capture_privacy_nullifiers_once,
    privacy_nullifiers,
    "world.privacy_nullifiers"
);
capture_world_table_once!(
    capture_privacy_commitments_once,
    privacy_commitments,
    "world.privacy_commitments"
);
capture_world_table_once!(
    capture_privacy_roots_once,
    privacy_roots,
    "world.privacy_roots"
);
capture_world_table_once!(
    capture_privacy_root_heads_once,
    privacy_root_heads,
    "world.privacy_root_heads"
);
capture_world_table_once!(capture_proof_tags_once, proof_tags, "world.proof_tags");
capture_world_table_once!(
    capture_consensus_evidence_once,
    consensus_evidence,
    "world.consensus_evidence"
);
capture_world_table_once!(
    capture_contract_manifests_once,
    contract_manifests,
    "world.contract_manifests"
);
capture_world_table_once!(
    capture_contract_code_once,
    contract_code,
    "world.contract_code"
);
capture_world_table_once!(
    capture_contract_code_uploads_once,
    contract_code_uploads,
    "world.contract_code_uploads"
);
capture_world_table_once!(
    capture_contract_code_upload_chunks_once,
    contract_code_upload_chunks,
    "world.contract_code_upload_chunks"
);
capture_world_table_once!(
    capture_contract_instances_once,
    contract_instances,
    "world.contract_instances"
);
capture_world_table_once!(
    capture_smart_contract_state_once,
    smart_contract_state,
    "world.smart_contract_state"
);

capture_world_table_once!(
    capture_musubi_namespace_bindings_once,
    musubi_namespace_bindings,
    "world.musubi_namespace_bindings"
);
capture_world_table_once!(
    capture_musubi_domain_ownership_generations_once,
    musubi_domain_ownership_generations,
    "world.musubi_domain_ownership_generations"
);
capture_world_table_once!(
    capture_musubi_packages_once,
    musubi_packages,
    "world.musubi_packages"
);
capture_world_table_once!(
    capture_musubi_package_metadata_once,
    musubi_package_metadata,
    "world.musubi_package_metadata"
);
capture_world_table_once!(
    capture_musubi_package_members_once,
    musubi_package_members,
    "world.musubi_package_members"
);
capture_world_table_once!(
    capture_musubi_package_invitations_once,
    musubi_package_invitations,
    "world.musubi_package_invitations"
);
capture_world_table_once!(
    capture_musubi_releases_once,
    musubi_releases,
    "world.musubi_releases"
);
capture_world_table_once!(
    capture_musubi_archives_once,
    musubi_archives,
    "world.musubi_archives"
);
capture_world_table_once!(
    capture_musubi_pin_outbox_high_waters_once,
    musubi_pin_outbox_high_waters,
    "world.musubi_pin_outbox_high_waters"
);
capture_world_table_once!(
    capture_musubi_provider_bundle_attestations_once,
    musubi_provider_bundle_attestations,
    "world.musubi_provider_bundle_attestations"
);
capture_world_table_once!(
    capture_musubi_archive_locations_once,
    musubi_archive_locations,
    "world.musubi_archive_locations"
);

capture_world_table_once!(
    capture_sccp_bridge_keys_once,
    sccp_bridge_keys,
    "world.sccp_bridge_keys"
);
capture_world_table_once!(
    capture_sccp_bridge_key_owners_once,
    sccp_bridge_key_owners,
    "world.sccp_bridge_key_owners"
);
capture_world_table_once!(
    capture_sccp_rosters_once,
    sccp_rosters,
    "world.sccp_rosters"
);
capture_world_table_once!(
    capture_sccp_block_leaves_once,
    sccp_block_leaves,
    "world.sccp_block_leaves"
);
capture_world_table_once!(
    capture_sccp_block_commitments_once,
    sccp_block_commitments,
    "world.sccp_block_commitments"
);
capture_world_table_once!(
    capture_sccp_history_leaves_once,
    sccp_history_leaves,
    "world.sccp_history_leaves"
);
capture_world_table_once!(
    capture_sccp_attestation_subjects_once,
    sccp_attestation_subjects,
    "world.sccp_attestation_subjects"
);
capture_world_table_once!(
    capture_sccp_attestation_status_once,
    sccp_attestation_status,
    "world.sccp_attestation_status"
);
capture_world_table_once!(
    capture_sccp_attestation_signatures_once,
    sccp_attestation_signatures,
    "world.sccp_attestation_signatures"
);
capture_world_table_once!(
    capture_sccp_attestation_faults_once,
    sccp_attestation_faults,
    "world.sccp_attestation_faults"
);
capture_world_table_once!(
    capture_sccp_member_last_signed_once,
    sccp_member_last_signed,
    "world.sccp_member_last_signed"
);
capture_world_table_once!(
    capture_sccp_handoff_stalled_once,
    sccp_handoff_stalled,
    "world.sccp_handoff_stalled"
);
capture_world_table_once!(
    capture_sccp_outbound_messages_once,
    sccp_outbound_messages,
    "world.sccp_outbound_messages"
);
capture_world_table_once!(
    capture_sccp_outbound_by_nonce_once,
    sccp_outbound_by_nonce,
    "world.sccp_outbound_by_nonce"
);
capture_world_table_once!(
    capture_sccp_control_messages_once,
    sccp_control_messages,
    "world.sccp_control_messages"
);
capture_world_table_once!(capture_sccp_routes_once, sccp_routes, "world.sccp_routes");
capture_world_table_once!(
    capture_sccp_destination_words_once,
    sccp_destination_words,
    "world.sccp_destination_words"
);
capture_world_table_once!(
    capture_sccp_governance_revisions_once,
    sccp_governance_revisions,
    "world.sccp_governance_revisions"
);
capture_world_table_once!(
    capture_sccp_inbound_messages_once,
    sccp_inbound_messages,
    "world.sccp_inbound_messages"
);
capture_world_table_once!(
    capture_sccp_pending_counts_once,
    sccp_pending_counts,
    "world.sccp_pending_counts"
);
capture_world_table_once!(
    capture_sccp_light_clients_once,
    sccp_light_clients,
    "world.sccp_light_clients"
);
capture_world_table_once!(
    capture_sccp_light_client_sets_once,
    sccp_light_client_sets,
    "world.sccp_light_client_sets"
);
capture_world_table_once!(
    capture_sccp_light_client_checkpoints_once,
    sccp_light_client_checkpoints,
    "world.sccp_light_client_checkpoints"
);
capture_world_table_once!(
    capture_sccp_light_client_stride_index_once,
    sccp_light_client_stride_index,
    "world.sccp_light_client_stride_index"
);

const TABLE_MATERIALIZERS: &[TableMaterializer] = &[
    TableMaterializer::Single {
        id: "world.domains",
        capture: capture_domains_table_once,
    },
    TableMaterializer::Single {
        id: "world.accounts",
        capture: capture_accounts_table_once,
    },
    ALIAS_MATERIALIZER,
    capture_ram_lfe_program_policies_once::MATERIALIZER,
    capture_identifier_policies_once::MATERIALIZER,
    capture_fee_sponsor_programs_once::MATERIALIZER,
    capture_fee_sponsor_program_revisions_once::MATERIALIZER,
    capture_fee_sponsor_enrollments_once::MATERIALIZER,
    capture_fee_sponsor_vaults_once::MATERIALIZER,
    capture_fee_sponsor_budget_counters_once::MATERIALIZER,
    capture_identifier_claims_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.account_rekey_records",
        capture: capture_account_rekey_records_once,
    },
    capture_account_recovery_policies_once::MATERIALIZER,
    capture_account_recovery_requests_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.asset_definitions",
        capture: capture_asset_definitions_once,
    },
    capture_asset_definition_alias_bindings_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.contract_alias_bindings",
        capture: capture_contract_alias_bindings_once,
    },
    TableMaterializer::Single {
        id: "world.assets",
        capture: capture_assets_once,
    },
    capture_asset_metadata_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.nfts",
        capture: capture_nfts_once,
    },
    TableMaterializer::Single {
        id: "world.rwas",
        capture: capture_rwas_once,
    },
    capture_roles_once::MATERIALIZER,
    capture_account_permissions_once::MATERIALIZER,
    capture_account_roles_once::MATERIALIZER,
    capture_oracle_feeds_once::MATERIALIZER,
    capture_oracle_observations_once::MATERIALIZER,
    capture_oracle_history_once::MATERIALIZER,
    capture_oracle_provider_stats_once::MATERIALIZER,
    capture_oracle_disputes_once::MATERIALIZER,
    capture_oracle_changes_once::MATERIALIZER,
    capture_defi_oracle_attestations_once::MATERIALIZER,
    capture_twitter_bindings_once::MATERIALIZER,
    capture_twitter_bindings_by_uaid_once::MATERIALIZER,
    capture_viral_daily_counters_once::MATERIALIZER,
    capture_viral_binding_claims_once::MATERIALIZER,
    capture_viral_escrows_once::MATERIALIZER,
    capture_viral_bonus_paid_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.asset_escrows",
        capture: capture_escrows_once,
    },
    capture_execution_proof_profiles_once::MATERIALIZER,
    capture_execution_proof_verifications_once::MATERIALIZER,
    capture_game_sessions_once::MATERIALIZER,
    capture_nft_sale_offers_once::MATERIALIZER,
    capture_nft_custody_records_once::MATERIALIZER,
    capture_vpn_leases_once::MATERIALIZER,
    capture_space_directory_manifests_once::MATERIALIZER,
    capture_axt_handle_counters_once::MATERIALIZER,
    capture_axt_asset_incarnations_once::MATERIALIZER,
    capture_axt_replay_ledger_once::MATERIALIZER,
    capture_axt_spend_nonce_ledger_once::MATERIALIZER,
    capture_axt_source_transfer_replay_ledger_once::MATERIALIZER,
    capture_axt_handle_budget_ledger_once::MATERIALIZER,
    capture_tx_sequences_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "triggers.data",
        capture: capture_trigger_data_once,
    },
    TableMaterializer::Single {
        id: "triggers.pipeline",
        capture: capture_trigger_pipeline_once,
    },
    TableMaterializer::Single {
        id: "triggers.time",
        capture: capture_trigger_time_once,
    },
    TableMaterializer::Single {
        id: "triggers.by_call",
        capture: capture_trigger_by_call_once,
    },
    TableMaterializer::Single {
        id: "triggers.contracts",
        capture: capture_trigger_contracts_once,
    },
    TableMaterializer::Single {
        id: "world.verifying_keys",
        capture: capture_verifying_keys_once,
    },
    capture_consensus_keys_once::MATERIALIZER,
    capture_consensus_keys_by_pk_once::MATERIALIZER,
    capture_domain_committees_once::MATERIALIZER,
    capture_domain_endorsement_policies_once::MATERIALIZER,
    capture_domain_endorsements_once::MATERIALIZER,
    capture_domain_endorsements_by_domain_once::MATERIALIZER,
    capture_pedersen_params_once::MATERIALIZER,
    capture_poseidon_params_once::MATERIALIZER,
    capture_runtime_upgrades_once::MATERIALIZER,
    capture_privacy_activations_once::MATERIALIZER,
    capture_private_settlement_governance_once::MATERIALIZER,
    capture_private_settlement_pools_once::MATERIALIZER,
    capture_private_settlement_roots_once::MATERIALIZER,
    capture_private_settlement_nullifiers_once::MATERIALIZER,
    capture_private_settlement_outputs_once::MATERIALIZER,
    capture_private_settlement_staged_locks_once::MATERIALIZER,
    capture_private_settlement_receipts_once::MATERIALIZER,
    capture_private_settlement_aborts_once::MATERIALIZER,
    capture_privacy_pgc_accounts_once::MATERIALIZER,
    capture_privacy_pgc_pool_invariants_once::MATERIALIZER,
    capture_privacy_nullifiers_once::MATERIALIZER,
    capture_privacy_commitments_once::MATERIALIZER,
    capture_privacy_roots_once::MATERIALIZER,
    capture_privacy_root_heads_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.proofs",
        capture: capture_proofs_once,
    },
    capture_proof_tags_once::MATERIALIZER,
    capture_consensus_evidence_once::MATERIALIZER,
    capture_contract_manifests_once::MATERIALIZER,
    capture_contract_code_once::MATERIALIZER,
    capture_contract_code_uploads_once::MATERIALIZER,
    capture_contract_code_upload_chunks_once::MATERIALIZER,
    capture_contract_instances_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.contract_subject_bindings",
        capture: capture_contract_subject_bindings_once,
    },
    capture_smart_contract_state_once::MATERIALIZER,
    capture_musubi_namespace_bindings_once::MATERIALIZER,
    capture_musubi_domain_ownership_generations_once::MATERIALIZER,
    capture_musubi_packages_once::MATERIALIZER,
    capture_musubi_package_metadata_once::MATERIALIZER,
    capture_musubi_package_members_once::MATERIALIZER,
    capture_musubi_package_invitations_once::MATERIALIZER,
    capture_musubi_releases_once::MATERIALIZER,
    capture_musubi_archives_once::MATERIALIZER,
    capture_musubi_pin_outbox_high_waters_once::MATERIALIZER,
    capture_musubi_provider_bundle_attestations_once::MATERIALIZER,
    capture_musubi_archive_locations_once::MATERIALIZER,
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Availability),
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Resolver),
    capture_musubi_resolver_index_checkpoints_once::MATERIALIZER,
    TableMaterializer::MusubiSemantic(&MusubiSemanticTable::Directory),
    capture_musubi_aliases_once::MATERIALIZER,
    capture_musubi_alias_history_once::MATERIALIZER,
    capture_musubi_governance_decisions_once::MATERIALIZER,
    native_world::capture_soracloud_service_revisions_once::MATERIALIZER,
    native_world::capture_soracloud_service_deployments_once::MATERIALIZER,
    native_world::capture_soracloud_app_infra_states_once::MATERIALIZER,
    native_world::capture_soracloud_service_runtime_once::MATERIALIZER,
    native_world::capture_soracloud_inrou_replica_runtime_once::MATERIALIZER,
    native_world::capture_soracloud_service_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_app_infra_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_service_state_entries_once::MATERIALIZER,
    native_world::capture_soracloud_decryption_request_records_once::MATERIALIZER,
    native_world::capture_soracloud_agent_apartments_once::MATERIALIZER,
    native_world::capture_soracloud_agent_apartment_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_training_jobs_once::MATERIALIZER,
    native_world::capture_soracloud_training_job_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_model_registries_once::MATERIALIZER,
    native_world::capture_soracloud_model_weight_versions_once::MATERIALIZER,
    native_world::capture_soracloud_model_weight_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_model_artifacts_once::MATERIALIZER,
    native_world::capture_soracloud_model_artifact_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_uploaded_model_bundles_once::MATERIALIZER,
    native_world::capture_soracloud_inrou_host_capabilities_once::MATERIALIZER,
    native_world::capture_soracloud_hf_sources_once::MATERIALIZER,
    native_world::capture_soracloud_hf_shared_lease_pools_once::MATERIALIZER,
    native_world::capture_soracloud_hf_shared_lease_members_once::MATERIALIZER,
    native_world::capture_soracloud_hf_shared_lease_audit_events_once::MATERIALIZER,
    native_world::capture_soracloud_inrou_service_placements_once::MATERIALIZER,
    native_world::capture_soracloud_mailbox_messages_once::MATERIALIZER,
    native_world::capture_soracloud_runtime_receipts_once::MATERIALIZER,
    native_world::capture_capacity_declarations_once::MATERIALIZER,
    native_world::capture_capacity_fee_ledger_once::MATERIALIZER,
    native_world::capture_capacity_disputes_once::MATERIALIZER,
    native_world::capture_provider_credit_ledger_once::MATERIALIZER,
    native_world::capture_provider_owners_once::MATERIALIZER,
    native_world::capture_provider_ingest_completion_authorities_once::MATERIALIZER,
    native_world::capture_da_pin_intents_by_ticket_once::MATERIALIZER,
    native_world::capture_da_pin_intents_by_alias_once::MATERIALIZER,
    native_world::capture_pin_manifests_once::MATERIALIZER,
    native_world::capture_manifest_aliases_once::MATERIALIZER,
    native_world::capture_replication_orders_once::MATERIALIZER,
    native_world::capture_content_bundles_once::MATERIALIZER,
    native_world::capture_content_chunks_once::MATERIALIZER,
    native_world::capture_soradns_directory_records_once::MATERIALIZER,
    native_world::capture_soradns_directory_pending_once::MATERIALIZER,
    native_world::capture_soradns_directory_history_once::MATERIALIZER,
    native_world::capture_soradns_directory_prev_of_once::MATERIALIZER,
    native_world::capture_soradns_directory_revocations_once::MATERIALIZER,
    native_world::capture_soradns_release_signers_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.repo_agreements",
        capture: capture_repo_agreements_once,
    },
    native_world::capture_settlement_receipts_once::MATERIALIZER,
    native_world::capture_kagemusha_mint_credit_operations_once::MATERIALIZER,
    native_world::capture_kagemusha_issuance_operations_once::MATERIALIZER,
    native_world::capture_kagemusha_redemption_id_operations_once::MATERIALIZER,
    native_world::capture_kagemusha_terminal_nullifier_operations_once::MATERIALIZER,
    native_world::capture_public_lane_validators_once::MATERIALIZER,
    native_world::capture_public_lane_stake_shares_once::MATERIALIZER,
    native_world::capture_public_lane_rewards_once::MATERIALIZER,
    native_world::capture_public_lane_reward_claims_once::MATERIALIZER,
    capture_public_lane_reward_accruals_once::MATERIALIZER,
    capture_public_lane_stake_custody_once::MATERIALIZER,
    native_world::capture_zk_assets_once::MATERIALIZER,
    native_world::capture_elections_once::MATERIALIZER,
    native_world::capture_citizens_once::MATERIALIZER,
    native_world::capture_ministry_agenda_proposals_once::MATERIALIZER,
    TableMaterializer::Single {
        id: "world.governance_proposals",
        capture: capture_governance_proposals_once,
    },
    native_world::capture_governance_referenda_once::MATERIALIZER,
    native_world::capture_governance_locks_once::MATERIALIZER,
    native_world::capture_governance_slashes_once::MATERIALIZER,
    native_world::capture_parliament_attempts_once::MATERIALIZER,
    native_world::capture_tle_key_sessions_once::MATERIALIZER,
    native_world::capture_tle_key_session_rosters_once::MATERIALIZER,
    native_world::capture_tle_key_session_lifecycles_once::MATERIALIZER,
    native_world::capture_tle_active_key_session_once::MATERIALIZER,
    native_world::capture_timed_ovn_evidence_once::MATERIALIZER,
    capture_validator_candidate_keys_once::MATERIALIZER,
    capture_validator_committee_transitions_once::MATERIALIZER,
    native_world::capture_global_beacon_dkg_once::MATERIALIZER,
    native_world::capture_global_beacon_key_sessions_once::MATERIALIZER,
    native_world::capture_global_beacon_active_session_once::MATERIALIZER,
    native_world::capture_global_beacon_latest_pulse_once::MATERIALIZER,
    native_world::capture_global_beacon_pulses_once::MATERIALIZER,
    capture_sccp_bridge_keys_once::MATERIALIZER,
    capture_sccp_bridge_key_owners_once::MATERIALIZER,
    capture_sccp_rosters_once::MATERIALIZER,
    capture_sccp_block_leaves_once::MATERIALIZER,
    capture_sccp_block_commitments_once::MATERIALIZER,
    capture_sccp_history_leaves_once::MATERIALIZER,
    capture_sccp_attestation_subjects_once::MATERIALIZER,
    capture_sccp_attestation_status_once::MATERIALIZER,
    capture_sccp_attestation_signatures_once::MATERIALIZER,
    capture_sccp_attestation_faults_once::MATERIALIZER,
    capture_sccp_member_last_signed_once::MATERIALIZER,
    capture_sccp_handoff_stalled_once::MATERIALIZER,
    capture_sccp_outbound_messages_once::MATERIALIZER,
    capture_sccp_outbound_by_nonce_once::MATERIALIZER,
    capture_sccp_control_messages_once::MATERIALIZER,
    capture_sccp_routes_once::MATERIALIZER,
    capture_sccp_destination_words_once::MATERIALIZER,
    capture_sccp_governance_revisions_once::MATERIALIZER,
    capture_sccp_inbound_messages_once::MATERIALIZER,
    capture_sccp_pending_counts_once::MATERIALIZER,
    capture_sccp_light_clients_once::MATERIALIZER,
    capture_sccp_light_client_sets_once::MATERIALIZER,
    capture_sccp_light_client_checkpoints_once::MATERIALIZER,
    capture_sccp_light_client_stride_index_once::MATERIALIZER,
    TableMaterializer::TransactionMembership,
];

/// This is an operational cap, not a claim that the current catalog is complete.
const MAX_TABLE_MATERIALIZERS: usize = 512;

#[path = "table_capture/aggregate.rs"]
mod aggregate;
use aggregate::{
    CapturedCanonicalTables, TableCaptureError, TableCaptureLimits, capture_tables_once,
};

/// Bounded table acquisition after actual inventory metadata admission.
///
/// Returned nodes cover tables only, not canonical cells or authenticated history.
/// They cannot return a finalized root, disclose rows or authorize IVM/AXT use.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: bind original frozen tables, cells and history before State/Kura publication consumes this owner"
    )
)]
fn capture_actual_state_tables_once(
    state: &State,
    limits: TableCaptureLimits,
) -> Result<Option<CapturedCanonicalTables>, TableCaptureError> {
    capture_tables_once(state, STATE_FIELDS, TABLE_MATERIALIZERS, limits)
}

/// Identities of every canonical table that the exact catalog reads, in catalog order.
///
/// The State table inventory (`specs/state_table_inventory.json`) records, for each
/// canonical table of the registry, that this catalog has a reader for it.
#[cfg(test)]
pub(in crate::state) fn catalog_table_ids() -> Vec<&'static str> {
    require_exact_table_materializers(STATE_FIELDS, TABLE_MATERIALIZERS)
        .expect("the table catalog matches the registry exactly");
    TABLE_MATERIALIZERS
        .iter()
        .flat_map(|owner| owner.table_ids())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(tables: LeafLimits) -> TableCaptureLimits {
        TableCaptureLimits {
            musubi: crate::state::authority_registry::complete::table_capture::musubi_test_limits(),
            tables,
            membership: MembershipWorkLimits {
                max_row_visits: 64,
                max_streamed_bytes: 131072,
                max_ordered_bytes: 131072,
            },
        }
    }

    use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::{AccountDetails, AccountId, rekey::AccountAlias},
        identifier::{IdentifierNormalization, IdentifierPolicy, IdentifierPolicyId},
        ram_lfe::RamLfeProgramId,
        role::{Role as LedgerRole, RoleId},
    };
    use iroha_model_base::topology::DataSpaceId;

    const ALIAS_ONLY: &[TableMaterializer] = &[ALIAS_MATERIALIZER];

    const ONE_TABLE: &[Field] = &[Field::new(
        "world.account_aliases",
        Role::Canonical(Canonical::Table {
            key: crate::state::authority_registry::schema::<AccountAlias>(),
            value: crate::state::authority_registry::schema::<AccountId>(),
        }),
    )];
    const TWO_TABLES: &[Field] = &[
        ONE_TABLE[0],
        Field::new(
            "world.accounts",
            Role::Canonical(Canonical::Table {
                key: crate::state::authority_registry::schema::<AccountId>(),
                value: crate::state::authority_registry::schema::<crate::state::AccountValue>(),
            }),
        ),
    ];
    const ACCOUNTS_ONLY: &[Field] = &[TWO_TABLES[1]];
    const DUPLICATE_TABLE: &[Field] = &[ONE_TABLE[0], ONE_TABLE[0]];
    const FIRST_THREE_TABLES: &[Field] = &[
        Field::new(
            "world.domains",
            Role::Canonical(Canonical::Table {
                key: crate::state::authority_registry::schema::<crate::state::DomainId>(),
                value: crate::state::authority_registry::schema::<crate::state::Domain>(),
            }),
        ),
        TWO_TABLES[1],
        ONE_TABLE[0],
    ];

    fn limits() -> LeafLimits {
        LeafLimits {
            max_tables: 3,
            max_rows: 8,
            max_payload_bytes: 4 * 1024,
            max_ordered_table_bytes: 32 * 1024,
            max_streamed_value_bytes: 8 * 1024 * 1024,
        }
    }

    fn state() -> State {
        State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    #[test]
    fn exact_table_catalog_rejects_missing_duplicate_and_noncanonical_readers() {
        assert_eq!(
            require_exact_table_materializers(TWO_TABLES, ALIAS_ONLY),
            Err(TableCaptureError::MissingMaterializer("world.accounts"))
        );
        assert_eq!(
            require_exact_table_materializers(ONE_TABLE, &[ALIAS_MATERIALIZER, ALIAS_MATERIALIZER],),
            Err(TableCaptureError::DuplicateMaterializer(
                "world.account_aliases"
            ))
        );
        assert_eq!(
            require_exact_table_materializers(&[], ALIAS_ONLY),
            Err(TableCaptureError::UnexpectedMaterializer(
                "world.account_aliases"
            ))
        );
        let reversed = [
            TableMaterializer::Single {
                id: "world.accounts",
                capture: capture_account_alias_table_once,
            },
            ALIAS_MATERIALIZER,
        ];
        assert_eq!(
            require_exact_table_materializers(TWO_TABLES, &reversed),
            Err(TableCaptureError::DisplacedMaterializer(
                "world.account_aliases"
            ))
        );
        assert_eq!(
            require_exact_table_materializers(DUPLICATE_TABLE, ALIAS_ONLY),
            Err(TableCaptureError::DisplacedMaterializer(
                "world.account_aliases"
            ))
        );
        assert_eq!(
            capture_actual_state_tables_once(&state(), policy(limits()))
                .err()
                .expect("three slots cannot retain the complete table catalog"),
            TableCaptureError::MaterializerLimit
        );
    }

    #[test]
    fn actual_table_catalog_admits_metadata_then_enforces_original_node_capacity() {
        let count = require_exact_table_materializers(STATE_FIELDS, TABLE_MATERIALIZERS).unwrap();
        assert_eq!(count, 217);
        assert_eq!(require_complete_inventory(STATE_FIELDS), Ok(()));
        let state = state();
        let budget = state.ivm_execution_budget();
        let original_limit = budget.limit_bytes();
        let before = budget.reserved_bytes();
        let mut cap = limits();
        cap.max_tables = count;
        budget.set_limit_bytes(0);
        assert!(matches!(
            capture_actual_state_tables_once(&state, policy(cap)),
            Err(TableCaptureError::Admission(iroha_allocation::AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 }))
                if requested_bytes == std::alloc::Layout::array::<CanonicalTablePairedSnapshot>(count).unwrap().size()
        ));
        assert_eq!(budget.reserved_bytes(), before);
        budget.set_limit_bytes(original_limit);
        // Inventory admission and local memory refusal confer no State-root handle.
    }

    #[test]
    fn all_native_world_readers_match_default_state_and_retry_during_publication() {
        let state = state();
        let expected = [
            "world.domains",
            "world.accounts",
            "world.account_aliases",
            "world.ram_lfe_program_policies",
            "world.identifier_policies",
            "world.fee_sponsor_programs",
            "world.fee_sponsor_program_revisions",
            "world.fee_sponsor_enrollments",
            "world.fee_sponsor_vaults",
            "world.fee_sponsor_budget_counters",
            "world.identifier_claims",
            "world.account_rekey_records",
            "world.account_recovery_policies",
            "world.account_recovery_requests",
            "world.asset_definitions",
            "world.asset_definition_alias_bindings",
            "world.contract_alias_bindings",
            "world.assets",
            "world.asset_metadata",
            "world.nfts",
            "world.rwas",
            "world.roles",
            "world.account_permissions",
            "world.account_roles",
            "world.oracle_feeds",
            "world.oracle_observations",
            "world.oracle_history",
            "world.oracle_provider_stats",
            "world.oracle_disputes",
            "world.oracle_changes",
            "world.defi_oracle_attestations",
            "world.twitter_bindings",
            "world.twitter_bindings_by_uaid",
            "world.viral_daily_counters",
            "world.viral_binding_claims",
            "world.viral_escrows",
            "world.viral_bonus_paid",
            "world.asset_escrows",
            "world.execution_proof_profiles",
            "world.execution_proof_verifications",
            "world.game_sessions",
            "world.nft_sale_offers",
            "world.nft_custody_records",
            "world.vpn_leases",
            "world.space_directory_manifests",
            "world.axt_handle_counters",
            "world.axt_asset_incarnations",
            "world.axt_replay_ledger",
            "world.axt_spend_nonce_ledger",
            "world.axt_source_transfer_replay_ledger",
            "world.axt_handle_budget_ledger",
            "world.tx_sequences",
            "triggers.data",
            "triggers.pipeline",
            "triggers.time",
            "triggers.by_call",
            "triggers.contracts",
            "world.verifying_keys",
            "world.consensus_keys",
            "world.consensus_keys_by_pk",
            "world.domain_committees",
            "world.domain_endorsement_policies",
            "world.domain_endorsements",
            "world.domain_endorsements_by_domain",
            "world.pedersen_params",
            "world.poseidon_params",
            "world.runtime_upgrades",
            "world.privacy_activations",
            "world.private_settlement_governance",
            "world.private_settlement_pools",
            "world.private_settlement_roots",
            "world.private_settlement_nullifiers",
            "world.private_settlement_outputs",
            "world.private_settlement_staged_locks",
            "world.private_settlement_receipts",
            "world.private_settlement_aborts",
            "world.privacy_pgc_accounts",
            "world.privacy_pgc_pool_invariants",
            "world.privacy_nullifiers",
            "world.privacy_commitments",
            "world.privacy_roots",
            "world.privacy_root_heads",
            "world.proofs",
            "world.proof_tags",
            "world.consensus_evidence",
            "world.contract_manifests",
            "world.contract_code",
            "world.contract_code_uploads",
            "world.contract_code_upload_chunks",
            "world.contract_instances",
            "world.contract_subject_bindings",
            "world.smart_contract_state",
            "world.musubi_namespace_bindings",
            "world.musubi_domain_ownership_generations",
            "world.musubi_packages",
            "world.musubi_package_metadata",
            "world.musubi_package_members",
            "world.musubi_package_invitations",
            "world.musubi_releases",
            "world.musubi_archives",
            "world.musubi_pin_outbox_high_waters",
            "world.musubi_provider_bundle_attestations",
            "world.musubi_archive_locations",
            "world.musubi_archive_availability",
            "world.musubi_resolver_index",
            "world.musubi_resolver_index_checkpoints",
            "world.musubi_public_directory",
            "world.musubi_aliases",
            "world.musubi_alias_history",
            "world.musubi_governance_decisions",
            "world.soracloud_service_revisions",
            "world.soracloud_service_deployments",
            "world.soracloud_app_infra_states",
            "world.soracloud_service_runtime",
            "world.soracloud_inrou_replica_runtime",
            "world.soracloud_service_audit_events",
            "world.soracloud_app_infra_audit_events",
            "world.soracloud_service_state_entries",
            "world.soracloud_decryption_request_records",
            "world.soracloud_agent_apartments",
            "world.soracloud_agent_apartment_audit_events",
            "world.soracloud_training_jobs",
            "world.soracloud_training_job_audit_events",
            "world.soracloud_model_registries",
            "world.soracloud_model_weight_versions",
            "world.soracloud_model_weight_audit_events",
            "world.soracloud_model_artifacts",
            "world.soracloud_model_artifact_audit_events",
            "world.soracloud_uploaded_model_bundles",
            "world.soracloud_inrou_host_capabilities",
            "world.soracloud_hf_sources",
            "world.soracloud_hf_shared_lease_pools",
            "world.soracloud_hf_shared_lease_members",
            "world.soracloud_hf_shared_lease_audit_events",
            "world.soracloud_inrou_service_placements",
            "world.soracloud_mailbox_messages",
            "world.soracloud_runtime_receipts",
            "world.capacity_declarations",
            "world.capacity_fee_ledger",
            "world.capacity_disputes",
            "world.provider_credit_ledger",
            "world.provider_owners",
            "world.provider_ingest_completion_authorities",
            "world.da_pin_intents_by_ticket",
            "world.da_pin_intents_by_alias",
            "world.pin_manifests",
            "world.manifest_aliases",
            "world.replication_orders",
            "world.content_bundles",
            "world.content_chunks",
            "world.soradns_directory_records",
            "world.soradns_directory_pending",
            "world.soradns_directory_history",
            "world.soradns_directory_prev_of",
            "world.soradns_directory_revocations",
            "world.soradns_release_signers",
            "world.repo_agreements",
            "world.settlement_receipts",
            "world.kagemusha_mint_credit_operations",
            "world.kagemusha_issuance_operations",
            "world.kagemusha_redemption_id_operations",
            "world.kagemusha_terminal_nullifier_operations",
            "world.public_lane_validators",
            "world.public_lane_stake_shares",
            "world.public_lane_rewards",
            "world.public_lane_reward_claims",
            "world.public_lane_reward_accruals",
            "world.public_lane_stake_custody",
            "world.zk_assets",
            "world.elections",
            "world.citizens",
            "world.ministry_agenda_proposals",
            "world.governance_proposals",
            "world.governance_referenda",
            "world.governance_locks",
            "world.governance_slashes",
            "world.parliament_attempts",
            "world.tle_key_sessions",
            "world.tle_key_session_rosters",
            "world.tle_key_session_lifecycles",
            "world.tle_active_key_session",
            "world.timed_ovn_evidence",
            "world.validator_candidate_keys",
            "world.validator_committee_transitions",
            "world.global_beacon_dkg",
            "world.global_beacon_key_sessions",
            "world.global_beacon_active_session",
            "world.global_beacon_latest_pulse",
            "world.global_beacon_pulses",
            "world.sccp_bridge_keys",
            "world.sccp_bridge_key_owners",
            "world.sccp_rosters",
            "world.sccp_block_leaves",
            "world.sccp_block_commitments",
            "world.sccp_history_leaves",
            "world.sccp_attestation_subjects",
            "world.sccp_attestation_status",
            "world.sccp_attestation_signatures",
            "world.sccp_attestation_faults",
            "world.sccp_member_last_signed",
            "world.sccp_handoff_stalled",
            "world.sccp_outbound_messages",
            "world.sccp_outbound_by_nonce",
            "world.sccp_control_messages",
            "world.sccp_routes",
            "world.sccp_destination_words",
            "world.sccp_governance_revisions",
            "world.sccp_inbound_messages",
            "world.sccp_pending_counts",
            "world.sccp_light_clients",
            "world.sccp_light_client_sets",
            "world.sccp_light_client_checkpoints",
            "world.sccp_light_client_stride_index",
            "state.transactions.current",
            "state.transactions.rollback",
        ];
        assert_eq!(
            TABLE_MATERIALIZERS
                .iter()
                .flat_map(|owner| owner.table_ids())
                .collect::<Vec<_>>(),
            expected
        );
        // Every listed Single has one table; the one indivisible transaction
        // membership owner retains both current and rollback tables together.
        assert_eq!(expected.len(), 217);
        assert_eq!(
            TABLE_MATERIALIZERS
                .iter()
                .filter(|owner| matches!(owner, TableMaterializer::TransactionMembership))
                .count(),
            1
        );
        assert_eq!(TABLE_MATERIALIZERS.len(), expected.len() - 1);
        let mut missing = Vec::new();
        visit(STATE_FIELDS, &mut |field| {
            if matches!(field.role, Role::Canonical(Canonical::Table { .. }))
                && !TABLE_MATERIALIZERS
                    .iter()
                    .any(|owner| owner.table_ids().any(|id| id == field.id))
            {
                missing.push(field.id);
            }
            if matches!(field.role, Role::Derived { .. }) {
                assert!(
                    !TABLE_MATERIALIZERS
                        .iter()
                        .any(|owner| owner.table_ids().any(|id| id == field.id)),
                    "derived index {} cannot claim a canonical table reader",
                    field.id,
                );
            }
        });
        assert!(
            missing.is_empty(),
            "actual table readers must be exhaustive: {missing:?}"
        );
        assert_eq!(
            require_exact_table_materializers(STATE_FIELDS, TABLE_MATERIALIZERS),
            Ok(217)
        );
        assert_eq!(TABLE_MATERIALIZERS.len(), 216);
        assert_eq!(
            TABLE_MATERIALIZERS
                .iter()
                .filter(|owner| matches!(owner, TableMaterializer::MusubiSemantic(_)))
                .count(),
            3
        );
        for owner in TABLE_MATERIALIZERS {
            let (TableMaterializer::Single { id, capture }
            | TableMaterializer::Native { id, capture, .. }) = owner
            else {
                continue;
            };
            let node = capture(&state, limits())
                .expect("bounded declared table")
                .expect("stable generation");
            assert_eq!(node.table_id(), *id);
            // Fresh State owns the three canonical SNS namespace-policy rows.
            // Capture them rather than treating initialized State as an empty World.
            let expected_rows = if *id == "world.smart_contract_state" {
                let rows = state.world.smart_contract_state.view();
                assert_eq!(rows.iter().count(), 3);
                3
            } else {
                0
            };
            assert_eq!(node.row_count(), expected_rows, "{}", id);
        }
        let mut publication = state.state_view_publication();
        let guard = publication.begin();
        for owner in TABLE_MATERIALIZERS {
            let (TableMaterializer::Single { capture, .. }
            | TableMaterializer::Native { capture, .. }) = owner
            else {
                continue;
            };
            assert!(
                capture(&state, limits())
                    .expect("busy generation is a retry")
                    .is_none()
            );
        }
        drop(guard);
    }

    #[test]
    fn identifier_policy_reader_binds_actual_rows_and_rejects_changed_value_proof() {
        let mut state = state();
        let owner = AccountId::new(
            KeyPair::from_seed(b"table-identifier-owner".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        state.world.accounts.insert(
            owner.clone(),
            crate::state::AccountValue::new(AccountDetails::default()),
        );
        let id: IdentifierPolicyId = "phone#business".parse().expect("policy id");
        let program_id: RamLfeProgramId = "program".parse().expect("program id");
        let policy = IdentifierPolicy::new(
            id.clone(),
            owner,
            IdentifierNormalization::Exact,
            program_id,
        );
        state
            .world
            .identifier_policies
            .insert(id.clone(), policy.clone());
        let before = capture_identifier_policies_once(&state, limits())
            .expect("bounded policy table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 1);
        state
            .world
            .identifier_policies
            .insert(id.clone(), policy.with_note("changed"));
        let changed = capture_identifier_policies_once(&state, limits())
            .expect("bounded changed table")
            .expect("stable generation");
        assert_ne!(before.root(), changed.root());
        let proof = changed
            .prove_lookup("world.identifier_policies", &id)
            .expect("changed-value lookup");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.identifier_policies",
                limits(),
                &before.root(),
                &changed.ordered_root(),
                &id,
                &proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn role_reader_authenticates_complete_raw_key_range_and_rejects_omission() {
        let mut state = state();
        let first: RoleId = "first".parse().expect("role id");
        let second: RoleId = "second".parse().expect("role id");
        for id in [&first, &second] {
            state.world.roles.insert(
                (*id).clone(),
                LedgerRole {
                    id: (*id).clone(),
                    permissions: Default::default(),
                    permission_epochs: Default::default(),
                },
            );
        }
        let before = capture_roles_once(&state, limits())
            .expect("bounded role table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 2);
        let mut keys = [
            (norito::codec::encode_adaptive(&first), first),
            (norito::codec::encode_adaptive(&second), second),
        ];
        keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let (start, end) = (&keys[0].0, &keys[1].0);
        let proof = before
            .prove_raw_range(start, end, 1, 8 * 1024)
            .expect("bounded exact interval");
        let verified = CanonicalTableLeafSet::verify_paired_raw_range(
            "world.roles",
            limits(),
            &before.root(),
            &before.lookup_root(),
            &before.ordered_root(),
            start,
            end,
            1,
            8 * 1024,
            &proof,
        )
        .expect("complete scoped interval");
        assert_eq!(verified.rows().count(), 1);
        assert_eq!(
            verified.rows().next().expect("first row").0,
            start.as_slice()
        );

        let mut roles = state.world.roles.block();
        roles.remove(keys[0].1.clone());
        roles.commit();
        let omitted = capture_roles_once(&state, limits())
            .expect("bounded omitted table")
            .expect("stable generation");
        assert_ne!(before.root(), omitted.root());
        let omitted_proof = omitted
            .prove_raw_range(start, end, 1, 8 * 1024)
            .expect("bounded omission interval");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_raw_range(
                "world.roles",
                limits(),
                &before.root(),
                &omitted.lookup_root(),
                &omitted.ordered_root(),
                start,
                end,
                1,
                8 * 1024,
                &omitted_proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn viral_claim_reader_authenticates_raw_key_range_and_rejects_changed_value() {
        let mut state = state();
        let first = Hash::new(b"first-viral-claim");
        let second = Hash::new(b"second-viral-claim");
        state.world.viral_binding_claims.insert(first, 1);
        state.world.viral_binding_claims.insert(second, 2);
        let before = capture_viral_binding_claims_once(&state, limits())
            .expect("bounded viral claim table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 2);
        let mut keys = [
            (norito::codec::encode_adaptive(&first), first),
            (norito::codec::encode_adaptive(&second), second),
        ];
        keys.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let (start, end) = (&keys[0].0, &keys[1].0);
        let proof = before
            .prove_raw_range(start, end, 1, 8 * 1024)
            .expect("bounded exact interval");
        let verified = CanonicalTableLeafSet::verify_paired_raw_range(
            "world.viral_binding_claims",
            limits(),
            &before.root(),
            &before.lookup_root(),
            &before.ordered_root(),
            start,
            end,
            1,
            8 * 1024,
            &proof,
        )
        .expect("complete scoped interval");
        assert_eq!(verified.rows().count(), 1);
        assert_eq!(
            verified.rows().next().expect("first row").0,
            start.as_slice()
        );

        state.world.viral_binding_claims.insert(keys[0].1, 3);
        let changed = capture_viral_binding_claims_once(&state, limits())
            .expect("bounded changed table")
            .expect("stable generation");
        assert_ne!(before.root(), changed.root());
        let changed_proof = changed
            .prove_raw_range(start, end, 1, 8 * 1024)
            .expect("bounded changed interval");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_raw_range(
                "world.viral_binding_claims",
                limits(),
                &before.root(),
                &changed.lookup_root(),
                &changed.ordered_root(),
                start,
                end,
                1,
                8 * 1024,
                &changed_proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn transaction_sequence_reader_rejects_changed_account_value() {
        let mut state = state();
        let owner = AccountId::new(
            KeyPair::from_seed(b"table-sequence-owner".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        state.world.accounts.insert(
            owner.clone(),
            crate::state::AccountValue::new(AccountDetails::default()),
        );
        state.world.tx_sequences.insert(owner.clone(), 1);
        let before = capture_tx_sequences_once(&state, limits())
            .expect("bounded sequence table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 1);
        let proof = before
            .prove_lookup("world.tx_sequences", &owner)
            .expect("sequence inclusion proof");
        assert!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.tx_sequences",
                limits(),
                &before.root(),
                &before.ordered_root(),
                &owner,
                &proof,
            )
            .expect("valid scoped sequence inclusion")
            .is_some()
        );

        state.world.tx_sequences.insert(owner.clone(), 2);
        let changed = capture_tx_sequences_once(&state, limits())
            .expect("bounded changed sequence table")
            .expect("stable generation");
        assert_ne!(before.root(), changed.root());
        let changed_proof = changed
            .prove_lookup("world.tx_sequences", &owner)
            .expect("changed sequence inclusion proof");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.tx_sequences",
                limits(),
                &before.root(),
                &changed.ordered_root(),
                &owner,
                &changed_proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn contract_code_reader_rejects_mutated_and_omitted_bytes() {
        let mut state = state();
        let id = iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::new(u64::MAX),
            Hash::new(b"captured-contract-code"),
        );
        state.world.contract_code.insert(id, vec![1, 2, 3]);
        let before = capture_contract_code_once(&state, limits())
            .expect("bounded code table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 1);
        let original_proof = before
            .prove_lookup("world.contract_code", &id)
            .expect("code inclusion proof");
        assert!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.contract_code",
                limits(),
                &before.root(),
                &before.ordered_root(),
                &id,
                &original_proof,
            )
            .expect("valid scoped inclusion")
            .is_some()
        );

        state.world.contract_code.insert(id, vec![1, 2, 4]);
        let changed = capture_contract_code_once(&state, limits())
            .expect("bounded changed code table")
            .expect("stable generation");
        assert_ne!(before.root(), changed.root());
        let changed_proof = changed
            .prove_lookup("world.contract_code", &id)
            .expect("changed code proof");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.contract_code",
                limits(),
                &before.root(),
                &changed.ordered_root(),
                &id,
                &changed_proof,
            ),
            Err(LeafError::RootMismatch)
        ));

        let mut code = state.world.contract_code.block();
        code.remove(id);
        code.commit();
        let omitted = capture_contract_code_once(&state, limits())
            .expect("bounded omitted code table")
            .expect("stable generation");
        assert_eq!(omitted.row_count(), 0);
        let omitted_proof = omitted
            .prove_lookup("world.contract_code", &id)
            .expect("code absence proof");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.contract_code",
                limits(),
                &before.root(),
                &omitted.ordered_root(),
                &id,
                &omitted_proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn contract_code_reader_streams_max_image_cntr_artifact_and_checks_full_preimage() {
        use iroha_data_model::smart_contract::{
            entrypoint::{EntrypointValueTypeNodeV1, EntrypointValueTypeV1},
            manifest::EntryPointKind,
        };

        const MAX_IMAGE_BYTES: usize = 0x0010_0000; // IVM V1's image ceiling after the fixed header.
        let interface = ivm::EmbeddedContractInterfaceV1 {
            callables: vec![crate::ivm_test_support::unit_callable(0)],
            seiyaku_name: "TestContract".to_owned(),
            compiler_fingerprint: "iroha-core-state-root-test".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "main".to_owned(),
                kind: EntryPointKind::Kotoage,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(EntrypointValueTypeV1 {
                    nodes: vec![EntrypointValueTypeNodeV1::Unit],
                }),
                permission: Some("CanInvoke".to_owned()),
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: None,
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        let mut artifact = ivm::ProgramMetadata::default().encode();
        artifact.extend_from_slice(&interface.encode_section());
        // CNTR's canonical Norito frame need not end on an instruction boundary.
        // A canonical empty LTLB section owns the padding; raw bytes between
        // sections would not be a valid production artifact.
        let literal_prefix_len = artifact.len() - ivm::HEADER_SIZE + 16;
        let post_pad = (4 - literal_prefix_len % 4) % 4;
        artifact.extend_from_slice(b"LTLB");
        artifact.extend_from_slice(&0_u32.to_le_bytes()); // Literal count.
        artifact.extend_from_slice(&u32::try_from(post_pad).unwrap().to_le_bytes());
        artifact.extend_from_slice(&0_u32.to_le_bytes()); // Literal data length.
        artifact.resize(artifact.len() + post_pad, 0);
        let executable_offset = artifact.len();
        let code_bytes = MAX_IMAGE_BYTES - (executable_offset - ivm::HEADER_SIZE);
        assert!(code_bytes >= 16 && code_bytes % 4 == 0);
        artifact.extend_from_slice(&crate::ivm_test_support::unit_return());
        let filler =
            ivm::encoding::wide::encode_rr(ivm::instruction::wide::arithmetic::ADD, 3, 1, 2)
                .to_le_bytes();
        for _ in 0..((code_bytes - 16) / filler.len()) {
            artifact.extend_from_slice(&filler);
        }
        assert_eq!(artifact.len() - ivm::HEADER_SIZE, MAX_IMAGE_BYTES);
        assert!(norito::codec::encode_adaptive(&artifact).len() > MAX_IMAGE_BYTES);
        let admitted = ivm::verify_contract_artifact(&artifact)
            .expect("ceiling-sized CNTR artifact is production-admitted");
        assert_eq!(admitted.code_offset, executable_offset);
        assert_eq!((admitted.code_offset - ivm::HEADER_SIZE) % 4, 0);
        let id = iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::new(u64::MAX),
            ivm::contract_code_hash(&artifact),
        );
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 1,
            max_payload_bytes: 2 * 1024 * 1024,
            max_ordered_table_bytes: 1024,
            max_streamed_value_bytes: 8 * 1024 * 1024,
        };
        let mut state = state();
        state.world.contract_code.insert(id, artifact.clone());
        assert!(matches!(
            capture_contract_code_once(
                &state,
                LeafLimits {
                    max_payload_bytes: 1024 * 1024,
                    ..limits
                }
            ),
            Err(LeafError::PayloadLimit)
        ));
        let captured = capture_contract_code_once(&state, limits)
            .expect("large bounded code capture")
            .expect("stable generation");
        let start = norito::codec::encode_adaptive(&id);
        let mut end = start.clone();
        end.push(0xff);
        let proof = captured
            .prove_raw_range(&start, &end, 1, 4096)
            .expect("digest-only range has bounded size");
        let verified = CanonicalTableLeafSet::verify_paired_raw_range(
            "world.contract_code",
            limits,
            &captured.root(),
            &captured.lookup_root(),
            &captured.ordered_root(),
            &start,
            &end,
            1,
            4096,
            &proof,
        )
        .expect("complete digest-only key range");
        assert_eq!(verified.len(), 1);
        CanonicalTableLeafSet::verify_paired_value_preimage(
            "world.contract_code",
            limits,
            &verified,
            &start,
            &artifact,
        )
        .expect("entire canonical artifact matches authenticated digest");
        let last = artifact.len() - 1;
        artifact[last] ^= 1;
        assert_eq!(
            CanonicalTableLeafSet::verify_paired_value_preimage(
                "world.contract_code",
                limits,
                &verified,
                &start,
                &artifact,
            ),
            Err(LeafError::ValuePreimageMismatch)
        );
    }

    #[test]
    fn oracle_history_reader_streams_large_canonical_vector_fixture() {
        use iroha_data_model::{
            events::data::oracle::FeedEventRecord,
            oracle::{FeedEvent, FeedEventOutcome},
        };

        let kit = iroha_data_model::oracle::kits::price_xor_usd();
        let id = kit.feed_config.feed_id.clone();
        let request_hash = kit.connector_request.request_hash();
        let evidence = vec![Hash::new(b"oracle evidence"); 16];
        // A canonical typed capacity fixture. Direct insertion does not claim
        // these exact Missing outcomes are emitted by AggregateOracleFeed.
        let records: Vec<_> = (0..2048)
            .map(|slot| FeedEventRecord {
                event: FeedEvent {
                    feed_id: id.clone(),
                    feed_config_version: kit.feed_config.feed_config_version,
                    slot,
                    request_hash,
                    outcome: FeedEventOutcome::Missing,
                },
                recorded_at_ms: slot,
                evidence_hashes: evidence.clone(),
            })
            .collect();
        assert!(
            norito::codec::encode_adaptive_into(&records, &mut std::io::sink())
                .expect("canonical history length")
                > 1024 * 1024
        );
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 1,
            max_payload_bytes: 2 * 1024 * 1024,
            max_ordered_table_bytes: 1024,
            max_streamed_value_bytes: 8 * 1024 * 1024,
        };
        let mut state = state();
        state
            .world
            .oracle_history
            .insert(id.clone(), records.clone());
        let captured = capture_oracle_history_once(&state, limits)
            .expect("bounded history capture")
            .expect("stable generation");
        let start = norito::codec::encode_adaptive(&id);
        let mut end = start.clone();
        end.push(0xff);
        let proof = captured
            .prove_raw_range(&start, &end, 1, 4096)
            .expect("bounded digest-only history range");
        let verified = CanonicalTableLeafSet::verify_paired_raw_range(
            "world.oracle_history",
            limits,
            &captured.root(),
            &captured.lookup_root(),
            &captured.ordered_root(),
            &start,
            &end,
            1,
            4096,
            &proof,
        )
        .expect("complete history key interval");
        CanonicalTableLeafSet::verify_paired_value_preimage(
            "world.oracle_history",
            limits,
            &verified,
            &start,
            &records,
        )
        .expect("complete oracle history value");
        let mut changed = records;
        changed[2047].evidence_hashes[15] = Hash::new(b"different evidence");
        assert_eq!(
            CanonicalTableLeafSet::verify_paired_value_preimage(
                "world.oracle_history",
                limits,
                &verified,
                &start,
                &changed,
            ),
            Err(LeafError::ValuePreimageMismatch)
        );
    }

    #[test]
    fn musubi_domain_generation_reader_rejects_changed_value() {
        let mut state = state();
        let id = crate::state::DomainId::try_new("musubi", "universal").expect("domain id");
        state
            .world
            .musubi_domain_ownership_generations
            .insert(id.clone(), 7);
        let before = capture_musubi_domain_ownership_generations_once(&state, limits())
            .expect("bounded Musubi generation table")
            .expect("stable generation");
        assert_eq!(before.row_count(), 1);
        let proof = before
            .prove_lookup("world.musubi_domain_ownership_generations", &id)
            .expect("generation inclusion proof");
        assert!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.musubi_domain_ownership_generations",
                limits(),
                &before.root(),
                &before.ordered_root(),
                &id,
                &proof,
            )
            .expect("valid scoped inclusion")
            .is_some()
        );

        state
            .world
            .musubi_domain_ownership_generations
            .insert(id.clone(), 8);
        let changed = capture_musubi_domain_ownership_generations_once(&state, limits())
            .expect("bounded changed generation table")
            .expect("stable generation");
        assert_ne!(before.root(), changed.root());
        let changed_proof = changed
            .prove_lookup("world.musubi_domain_ownership_generations", &id)
            .expect("changed generation proof");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.musubi_domain_ownership_generations",
                limits(),
                &before.root(),
                &changed.ordered_root(),
                &id,
                &changed_proof,
            ),
            Err(LeafError::RootMismatch)
        ));
    }

    #[test]
    fn actual_reader_nodes_bind_identity_rows_and_generation_without_authority() {
        let mut state = state();
        let owner = AccountId::new(
            KeyPair::from_seed(b"table-owner-alias".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let alias = AccountAlias::domainless(
            "captured".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        state.world.accounts.insert(
            owner.clone(),
            crate::state::AccountValue::new(AccountDetails::default()),
        );
        state
            .world
            .account_aliases
            .insert(alias.clone(), owner.clone());
        state.world.rebuild_account_alias_index().unwrap();
        let before = capture_tables_once(&state, ONE_TABLE, ALIAS_ONLY, policy(limits()))
            .expect("bounded actual table")
            .expect("stable generation");
        assert_eq!(before.nodes().len(), 1);
        assert_eq!(before.generation, state.state_view_generation());
        assert_eq!(before.nodes()[0].table_id(), "world.account_aliases");
        assert_eq!(before.nodes()[0].row_count(), 1);
        let first_three = capture_tables_once(
            &state,
            FIRST_THREE_TABLES,
            &TABLE_MATERIALIZERS[..3],
            policy(limits()),
        )
        .expect("three bounded actual tables")
        .expect("stable generation");
        assert_eq!(
            first_three
                .nodes()
                .iter()
                .map(CanonicalTablePairedSnapshot::table_id)
                .collect::<Vec<_>>(),
            ["world.domains", "world.accounts", "world.account_aliases"]
        );
        assert_eq!(
            first_three
                .nodes()
                .iter()
                .map(CanonicalTablePairedSnapshot::row_count)
                .collect::<Vec<_>>(),
            [0, 1, 1]
        );
        assert_eq!(
            capture_tables_once(
                &state,
                FIRST_THREE_TABLES,
                &TABLE_MATERIALIZERS[..3],
                policy(LeafLimits {
                    max_rows: 1,
                    ..limits()
                }),
            )
            .err()
            .expect("aggregate row bound"),
            TableCaptureError::AggregateRowLimit
        );

        let empty = self::state();
        let omitted = capture_tables_once(&empty, ONE_TABLE, ALIAS_ONLY, policy(limits()))
            .unwrap()
            .unwrap();
        assert_ne!(before.nodes()[0].root(), omitted.nodes()[0].root());
        let omitted_proof = omitted.nodes()[0]
            .prove_lookup("world.account_aliases", &alias)
            .expect("bounded absence path");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.account_aliases",
                limits(),
                &before.nodes()[0].root(),
                &omitted.nodes()[0].ordered_root(),
                &alias,
                &omitted_proof,
            ),
            Err(LeafError::RootMismatch)
        ));

        let alternate = AccountId::new(
            KeyPair::from_seed(b"table-owner-replacement".to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        state.world.accounts.insert(
            alternate.clone(),
            crate::state::AccountValue::new(AccountDetails::default()),
        );
        state.world.account_aliases.insert(alias.clone(), alternate);
        state.world.rebuild_account_alias_index().unwrap();
        let tampered = capture_tables_once(&state, ONE_TABLE, ALIAS_ONLY, policy(limits()))
            .unwrap()
            .unwrap();
        assert_ne!(before.nodes()[0].root(), tampered.nodes()[0].root());
        let tampered_proof = tampered.nodes()[0]
            .prove_lookup("world.account_aliases", &alias)
            .expect("bounded changed-value path");
        assert!(matches!(
            CanonicalTableLeafSet::verify_paired_lookup(
                "world.account_aliases",
                limits(),
                &before.nodes()[0].root(),
                &tampered.nodes()[0].ordered_root(),
                &alias,
                &tampered_proof,
            ),
            Err(LeafError::RootMismatch)
        ));

        let mut publication = state.state_view_publication();
        let guard = publication.begin();
        assert!(
            capture_tables_once(&state, ONE_TABLE, ALIAS_ONLY, policy(limits()))
                .unwrap()
                .is_none()
        );
        drop(guard);
    }

    #[test]
    fn substituted_reader_and_table_count_bound_refuse_capture() {
        const WRONG_READER: &[TableMaterializer] = &[TableMaterializer::Single {
            id: "world.accounts",
            capture: capture_account_alias_table_once,
        }];
        let state = state();
        assert_eq!(
            capture_tables_once(&state, ACCOUNTS_ONLY, WRONG_READER, policy(limits()))
                .err()
                .expect("wrong table node"),
            TableCaptureError::IdentityMismatch {
                expected: "world.accounts",
                actual: "world.account_aliases",
            }
        );
        assert_eq!(
            capture_tables_once(
                &state,
                ONE_TABLE,
                ALIAS_ONLY,
                policy(LeafLimits {
                    max_tables: 0,
                    ..limits()
                }),
            )
            .err()
            .expect("table count bound"),
            TableCaptureError::MaterializerLimit
        );
    }
}

#[cfg(test)]
fn musubi_test_limits() -> SourceWorkLimits {
    SourceWorkLimits {
        geometry: iroha_data_model::musubi::source_work::SourceGeometryLimits {
            elements: 1_000_000,
            variable_bytes: 1_000_000,
        },
        table_pass_rows: 1_000_000,
        lookup_index_entries: 1_000_000,
        model_operations: 1_000_000,
        signature_checks: 1_000_000,
    }
}

#[cfg(test)]
#[path = "table_capture/musubi_semantic_tests.rs"]
mod musubi_semantic_tests;

use crate::state::deserialize::musubi_source_read::{
    MusubiSourceAcquisitionError, StateMusubiSourceCut,
};
