//! Remaining native-Norito World table readers.
//!
//! Every reader binds the complete persisted record using its existing declared
//! schema. Native encoding is not proof that a record was admitted or that its
//! cross-table constraints hold. In particular, content refcounts, confidential
//! tree metadata, mirrored governance status and Parliament's internal indexes
//! retain their existing recovery consistency requirements. No derived field is
//! projected into independent authority by this diagnostic capture.
//! TODO: enforce the owner-specific consistency checks under the same admitted
//! State publication cut before these scoped snapshots enter a finalized root.

use super::*;

capture_world_table_once!(
    pub(super) capture_soracloud_service_revisions_once,
    soracloud_service_revisions,
    "world.soracloud_service_revisions"
);
capture_world_table_once!(
    pub(super) capture_soracloud_service_deployments_once,
    soracloud_service_deployments,
    "world.soracloud_service_deployments"
);
capture_world_table_once!(
    pub(super) capture_soracloud_app_infra_states_once,
    soracloud_app_infra_states,
    "world.soracloud_app_infra_states"
);
capture_world_table_once!(
    pub(super) capture_soracloud_service_runtime_once,
    soracloud_service_runtime,
    "world.soracloud_service_runtime"
);
capture_world_table_once!(
    pub(super) capture_soracloud_inrou_replica_runtime_once,
    soracloud_inrou_replica_runtime,
    "world.soracloud_inrou_replica_runtime"
);
capture_world_table_once!(
    pub(super) capture_soracloud_service_audit_events_once,
    soracloud_service_audit_events,
    "world.soracloud_service_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_app_infra_audit_events_once,
    soracloud_app_infra_audit_events,
    "world.soracloud_app_infra_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_service_state_entries_once,
    soracloud_service_state_entries,
    "world.soracloud_service_state_entries"
);
capture_world_table_once!(
    pub(super) capture_soracloud_decryption_request_records_once,
    soracloud_decryption_request_records,
    "world.soracloud_decryption_request_records"
);
capture_world_table_once!(
    pub(super) capture_soracloud_agent_apartments_once,
    soracloud_agent_apartments,
    "world.soracloud_agent_apartments"
);
capture_world_table_once!(
    pub(super) capture_soracloud_agent_apartment_audit_events_once,
    soracloud_agent_apartment_audit_events,
    "world.soracloud_agent_apartment_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_training_jobs_once,
    soracloud_training_jobs,
    "world.soracloud_training_jobs"
);
capture_world_table_once!(
    pub(super) capture_soracloud_training_job_audit_events_once,
    soracloud_training_job_audit_events,
    "world.soracloud_training_job_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_model_registries_once,
    soracloud_model_registries,
    "world.soracloud_model_registries"
);
capture_world_table_once!(
    pub(super) capture_soracloud_model_weight_versions_once,
    soracloud_model_weight_versions,
    "world.soracloud_model_weight_versions"
);
capture_world_table_once!(
    pub(super) capture_soracloud_model_weight_audit_events_once,
    soracloud_model_weight_audit_events,
    "world.soracloud_model_weight_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_model_artifacts_once,
    soracloud_model_artifacts,
    "world.soracloud_model_artifacts"
);
capture_world_table_once!(
    pub(super) capture_soracloud_model_artifact_audit_events_once,
    soracloud_model_artifact_audit_events,
    "world.soracloud_model_artifact_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_uploaded_model_bundles_once,
    soracloud_uploaded_model_bundles,
    "world.soracloud_uploaded_model_bundles"
);
capture_world_table_once!(
    pub(super) capture_soracloud_inrou_host_capabilities_once,
    soracloud_inrou_host_capabilities,
    "world.soracloud_inrou_host_capabilities"
);
capture_world_table_once!(
    pub(super) capture_soracloud_hf_sources_once,
    soracloud_hf_sources,
    "world.soracloud_hf_sources"
);
capture_world_table_once!(
    pub(super) capture_soracloud_hf_shared_lease_pools_once,
    soracloud_hf_shared_lease_pools,
    "world.soracloud_hf_shared_lease_pools"
);
capture_world_table_once!(
    pub(super) capture_soracloud_hf_shared_lease_members_once,
    soracloud_hf_shared_lease_members,
    "world.soracloud_hf_shared_lease_members"
);
capture_world_table_once!(
    pub(super) capture_soracloud_hf_shared_lease_audit_events_once,
    soracloud_hf_shared_lease_audit_events,
    "world.soracloud_hf_shared_lease_audit_events"
);
capture_world_table_once!(
    pub(super) capture_soracloud_inrou_service_placements_once,
    soracloud_inrou_service_placements,
    "world.soracloud_inrou_service_placements"
);
capture_world_table_once!(
    pub(super) capture_soracloud_mailbox_messages_once,
    soracloud_mailbox_messages,
    "world.soracloud_mailbox_messages"
);
capture_world_table_once!(
    pub(super) capture_soracloud_runtime_receipts_once,
    soracloud_runtime_receipts,
    "world.soracloud_runtime_receipts"
);
capture_world_table_once!(
    pub(super) capture_capacity_declarations_once,
    capacity_declarations,
    "world.capacity_declarations"
);
capture_world_table_once!(
    pub(super) capture_capacity_fee_ledger_once,
    capacity_fee_ledger,
    "world.capacity_fee_ledger"
);
capture_world_table_once!(
    pub(super) capture_capacity_disputes_once,
    capacity_disputes,
    "world.capacity_disputes"
);
capture_world_table_once!(
    pub(super) capture_provider_credit_ledger_once,
    provider_credit_ledger,
    "world.provider_credit_ledger"
);
capture_world_table_once!(
    pub(super) capture_provider_owners_once,
    provider_owners,
    "world.provider_owners"
);
capture_world_table_once!(
    pub(super) capture_provider_ingest_completion_authorities_once,
    provider_ingest_completion_authorities,
    "world.provider_ingest_completion_authorities"
);
capture_world_table_once!(
    pub(super) capture_da_pin_intents_by_ticket_once,
    da_pin_intents_by_ticket,
    "world.da_pin_intents_by_ticket"
);
capture_world_table_once!(
    pub(super) capture_da_pin_intents_by_alias_once,
    da_pin_intents_by_alias,
    "world.da_pin_intents_by_alias"
);
capture_world_table_once!(
    pub(super) capture_pin_manifests_once,
    pin_manifests,
    "world.pin_manifests"
);
capture_world_table_once!(
    pub(super) capture_manifest_aliases_once,
    manifest_aliases,
    "world.manifest_aliases"
);
capture_world_table_once!(
    pub(super) capture_replication_orders_once,
    replication_orders,
    "world.replication_orders"
);
capture_world_table_once!(
    pub(super) capture_content_bundles_once,
    content_bundles,
    "world.content_bundles"
);
capture_world_table_once!(
    pub(super) capture_content_chunks_once,
    content_chunks,
    "world.content_chunks"
);
capture_world_table_once!(
    pub(super) capture_soradns_directory_records_once,
    soradns_directory_records,
    "world.soradns_directory_records"
);
capture_world_table_once!(
    pub(super) capture_soradns_directory_pending_once,
    soradns_directory_pending,
    "world.soradns_directory_pending"
);
capture_world_table_once!(
    pub(super) capture_soradns_directory_history_once,
    soradns_directory_history,
    "world.soradns_directory_history"
);
capture_world_table_once!(
    pub(super) capture_soradns_directory_prev_of_once,
    soradns_directory_prev_of,
    "world.soradns_directory_prev_of"
);
capture_world_table_once!(
    pub(super) capture_soradns_directory_revocations_once,
    soradns_directory_revocations,
    "world.soradns_directory_revocations"
);
capture_world_table_once!(
    pub(super) capture_soradns_release_signers_once,
    soradns_release_signers,
    "world.soradns_release_signers"
);
capture_world_table_once!(
    pub(super) capture_settlement_receipts_once,
    settlement_receipts,
    "world.settlement_receipts"
);
capture_world_table_once!(
    pub(super) capture_public_lane_validators_once,
    public_lane_validators,
    "world.public_lane_validators"
);
capture_world_table_once!(
    pub(super) capture_public_lane_stake_shares_once,
    public_lane_stake_shares,
    "world.public_lane_stake_shares"
);
capture_world_table_once!(
    pub(super) capture_zk_assets_once,
    zk_assets,
    "world.zk_assets"
);
capture_world_table_once!(
    pub(super) capture_elections_once,
    elections,
    "world.elections"
);
capture_world_table_once!(
    pub(super) capture_citizens_once,
    citizens,
    "world.citizens"
);
capture_world_table_once!(
    pub(super) capture_ministry_agenda_proposals_once,
    ministry_agenda_proposals,
    "world.ministry_agenda_proposals"
);
capture_world_table_once!(
    pub(super) capture_governance_referenda_once,
    governance_referenda,
    "world.governance_referenda"
);
capture_world_table_once!(
    pub(super) capture_governance_locks_once,
    governance_locks,
    "world.governance_locks"
);
capture_world_table_once!(
    pub(super) capture_governance_slashes_once,
    governance_slashes,
    "world.governance_slashes"
);
capture_world_table_once!(
    pub(super) capture_parliament_attempts_once,
    parliament_attempts,
    "world.parliament_attempts"
);
capture_world_table_once!(
    pub(super) capture_tle_key_sessions_once,
    tle_key_sessions,
    "world.tle_key_sessions"
);
capture_world_table_once!(
    pub(super) capture_tle_key_session_rosters_once,
    tle_key_session_rosters,
    "world.tle_key_session_rosters"
);
capture_world_table_once!(
    pub(super) capture_tle_key_session_lifecycles_once,
    tle_key_session_lifecycles,
    "world.tle_key_session_lifecycles"
);
capture_world_table_once!(
    pub(super) capture_tle_active_key_session_once,
    tle_active_key_session,
    "world.tle_active_key_session"
);
capture_world_table_once!(
    pub(super) capture_timed_ovn_evidence_once,
    timed_ovn_evidence,
    "world.timed_ovn_evidence"
);
capture_world_table_once!(
    pub(super) capture_global_beacon_dkg_once,
    global_beacon_dkg,
    "world.global_beacon_dkg"
);
capture_world_table_once!(
    pub(super) capture_global_beacon_key_sessions_once,
    global_beacon_key_sessions,
    "world.global_beacon_key_sessions"
);
capture_world_table_once!(
    pub(super) capture_global_beacon_active_session_once,
    global_beacon_active_session,
    "world.global_beacon_active_session"
);
capture_world_table_once!(
    pub(super) capture_global_beacon_latest_pulse_once,
    global_beacon_latest_pulse,
    "world.global_beacon_latest_pulse"
);
capture_world_table_once!(
    pub(super) capture_global_beacon_pulses_once,
    global_beacon_pulses,
    "world.global_beacon_pulses"
);

#[cfg(test)]
mod tests {
    use super::super::native_test_support::{
        capture_controls, cloned, fixture_insert, fixture_remove, limits,
    };
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{ElectionState, World, ZkAssetState},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        asset::AssetDefinitionId,
        content::ContentChunk,
        soracloud::{
            SORA_SERVICE_STATE_ENTRY_VERSION_V1, SoraServiceLifecycleActionV1,
            SoraServiceStateEntryV1, SoraStateEncryptionV1,
        },
        sorafs::capacity::ProviderId,
    };
    use std::num::NonZeroU64;

    fn account(seed: &[u8]) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }

    capture_controls!(
        service_state_reader_rejects_changed_payload_and_omitted_row,
        soracloud_service_state_entries,
        capture_soracloud_service_state_entries_once,
        {
            let payload = vec![0xc1; 512];
            let row = SoraServiceStateEntryV1 {
                schema_version: SORA_SERVICE_STATE_ENTRY_VERSION_V1,
                service_name: "capture".parse().unwrap(),
                service_version: "1.0.0".to_owned(),
                binding_name: "encrypted".parse().unwrap(),
                state_key: "/state/entry".to_owned(),
                encryption: SoraStateEncryptionV1::ClientCiphertext,
                payload_bytes: NonZeroU64::new(512).unwrap(),
                payload_commitment: Hash::new(&payload),
                payload,
                fhe_public_key_digest: None,
                fhe_residual_multiple_bound: None,
                fhe_bound_mode: None,
                last_update_sequence: 7,
                governance_tx_hash: Hash::new(b"capture-governance"),
                source_action: SoraServiceLifecycleActionV1::StateMutation,
            };
            row.validate().unwrap();
            (
                (
                    row.service_name.to_string(),
                    row.binding_name.to_string(),
                    row.state_key.clone(),
                ),
                row,
            )
        },
        |row: &mut SoraServiceStateEntryV1| {
            row.payload[0] ^= 1;
            row.payload_commitment = Hash::new(&row.payload);
        }
    );

    capture_controls!(
        provider_owner_reader_rejects_changed_authority_and_omitted_row,
        provider_owners,
        capture_provider_owners_once,
        (
            ProviderId::new([0x21; 32]),
            account(b"capture-provider-owner")
        ),
        |row: &mut AccountId| *row = account(b"capture-provider-replacement")
    );

    capture_controls!(
        content_chunk_reader_binds_persisted_reference_count_and_omitted_row,
        content_chunks,
        capture_content_chunks_once,
        ([0x22; 32], ContentChunk::new(vec![1, 2, 3, 4])),
        |row: &mut ContentChunk| row.refcount += 1
    );

    capture_controls!(
        directory_history_reader_rejects_changed_link_and_omitted_row,
        soradns_directory_history,
        capture_soradns_directory_history_once,
        (7_u64, [0x23_u8; 32]),
        |row: &mut [u8; 32]| row[0] ^= 1
    );

    capture_controls!(
        confidential_reader_binds_persisted_tree_metadata_and_omitted_row,
        zk_assets,
        capture_zk_assets_once,
        (
            AssetDefinitionId::from_uuid_bytes([
                0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x41, 0x31, 0x81, 0x31, 0x31, 0x31, 0x31, 0x31,
                0x31, 0x31,
            ])
            .unwrap(),
            ZkAssetState::default()
        ),
        |row: &mut ZkAssetState| row.persisted_root[0] ^= 1
    );

    capture_controls!(
        election_reader_rejects_changed_nullifiers_and_omitted_row,
        elections,
        capture_elections_once,
        (
            "capture-election".to_owned(),
            ElectionState {
                options: 2,
                tally: vec![0, 0],
                ..ElectionState::default()
            }
        ),
        |row: &mut ElectionState| {
            row.accepted_ballots
                .push(crate::state::StandaloneBallotCorpusEntryV1 {
                    nullifier: [0x26; 32],
                    commitment: [0x27; 32],
                });
        }
    );

    capture_controls!(
        beacon_session_reader_rejects_changed_binding_and_omitted_row,
        global_beacon_active_session,
        capture_global_beacon_active_session_once,
        (7_u64, [0x27_u8; 32]),
        |row: &mut [u8; 32]| row[0] ^= 1
    );
}
