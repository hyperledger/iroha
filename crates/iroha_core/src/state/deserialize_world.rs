#[path = "deserialize_world_musubi_rejection.rs"]
pub(in crate::state) mod musubi_rejection;
use musubi_rejection::{ProjectionCut, ProjectionRejection, ProjectionTable};

#[path = "deserialize_world_musubi_source_read.rs"]
pub(crate) mod musubi_source_read;

#[path = "deserialize_world_musubi_live.rs"]
mod musubi_live;
#[path = "deserialize_world_musubi_source_work.rs"]
pub(in crate::state) mod musubi_source_work;
pub(in crate::state) use musubi_live::validate_musubi_live_projection_cut;
use musubi_live::validate_musubi_live_projections;

#[path = "deserialize_world_musubi_derived.rs"]
mod musubi_derived;
#[path = "deserialize_world_musubi_universal.rs"]
pub(in crate::state) mod musubi_universal;
#[path = "deserialize_world_proof_tag_index.rs"]
mod proof_tag_index;
#[path = "deserialize_world_verifying_key_index.rs"]
mod verifying_key_index;

struct MusubiPersistedState<'a> {
    namespace_bindings: &'a Storage<MusubiNamespaceV1, MusubiNamespaceBindingV1>,
    packages: &'a Storage<MusubiPackageIdV1, MusubiPackageRecordV1>,
    package_metadata: &'a Storage<MusubiPackageIdV1, MusubiPackageMetadataRecordV1>,
    package_members: &'a Storage<MusubiPackageMemberKeyV1, MusubiPackageMemberV1>,
    package_invitations: &'a Storage<MusubiInviteIdV1, MusubiMaintainerInvitationV1>,
    maintainer_directory:
        &'a Storage<MusubiMaintainerDirectoryKeyV1, MusubiMaintainerDirectoryEntryV1>,
    releases: &'a Storage<MusubiReleaseIdV1, MusubiReleaseRecordV1>,
    archives: &'a Storage<ArchiveId, MusubiArchiveRecordV1>,
    provider_bundle_attestations:
        &'a Storage<MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1>,
    archive_locations: &'a Storage<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1>,
    archive_availability: &'a Storage<ArchiveId, MusubiArchiveAvailabilityV1>,
    archive_reverse_references: &'a Storage<ArchiveId, MusubiArchiveReverseReferencesV1>,
    resolver_index: &'a Storage<MusubiReleaseIdV1, MusubiResolverReleaseRowV1>,
    resolver_index_checkpoints:
        &'a Storage<MusubiResolverIndexRevisionV1, MusubiRegistrySnapshotV1>,
    public_directory: &'a Storage<MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1>,
    aliases: &'a Storage<MusubiAliasNameV1, MusubiAliasRecordV1>,
    alias_history: &'a Storage<MusubiAliasHistoryKeyV1, MusubiAliasHistoryEntryV1>,
    governance_decisions: &'a Storage<[u8; 32], MusubiGovernanceDecisionConsumptionV1>,
    resolver_index_revision: u64,
    replication_shortfall_releases: u64,
}

fn validate_asset_transfer_control_persistence_v1(world: &World) -> Result<(), json::Error> {
    let accounts = world.accounts.view();
    let asset_definitions = world.asset_definitions.view();
    for (account_id, account) in accounts.iter() {
        let Some(raw) = account
            .metadata()
            .get(iroha_data_model::asset::ASSET_TRANSFER_CONTROL_METADATA_KEY)
        else {
            continue;
        };
        let store = raw
            .clone()
            .try_into_any_norito::<iroha_data_model::asset::AssetTransferControlStoreV1>()
            .map_err(|error| json::Error::InvalidField {
                field: "accounts.*.metadata.asset_transfer_controls".to_owned(),
                message: format!(
                    "first-release snapshot is incompatible: account {account_id} has undecodable native asset transfer-control state: {error}"
                ),
            })?;
        if store.controls.is_empty() {
            return Err(json::Error::InvalidField {
                field: "accounts.*.metadata.asset_transfer_controls".to_owned(),
                message: format!(
                    "first-release snapshot is incompatible: account {account_id} persists an empty native asset transfer-control store"
                ),
            });
        }
        store
            .validate_canonical()
            .map_err(|error| json::Error::InvalidField {
                field: "accounts.*.metadata.asset_transfer_controls".to_owned(),
                message: format!(
                    "first-release snapshot is incompatible: account {account_id} has non-canonical native asset transfer-control state: {error}"
                ),
            })?;
        if let Some(record) = store
            .controls
            .iter()
            .find(|record| asset_definitions.get(&record.asset_definition_id).is_none())
        {
            return Err(json::Error::InvalidField {
                field: "accounts.*.metadata.asset_transfer_controls".to_owned(),
                message: format!(
                    "first-release snapshot is incompatible: account {account_id} has native transfer-control state for missing asset definition {}",
                    record.asset_definition_id
                ),
            });
        }
    }
    Ok(())
}

fn proposal_status_matches_latest_attempt_v1(
    proposal_status: GovernanceProposalStatus,
    attempt_status: Option<iroha_data_model::governance::types::GovernanceAttemptStatusV1>,
) -> bool {
    attempt_status.map_or(
        proposal_status == GovernanceProposalStatus::Proposed,
        |status| proposal_status == GovernanceProposalStatus::from_attempt_status(status),
    )
}

fn validate_no_standalone_governance_state_for_typed_proposals_v1(
    world: &World,
) -> Result<(), json::Error> {
    let proposals = world.governance_proposals.view();
    let aliases_typed_proposal = |selector: &str| {
        iroha_data_model::governance::decode_governance_proposal_selector_alias_v1(selector)
            .is_some_and(|proposal_id| proposals.get(&proposal_id).is_some())
    };
    macro_rules! reject_typed_alias {
        ($field:literal, $storage:expr) => {{
            let view = $storage.view();
            if let Some((selector, _)) = view
                .iter()
                .find(|(selector, _)| aliases_typed_proposal(selector))
            {
                return Err(json::Error::InvalidField {
                    field: $field.to_owned(),
                    message: format!(
                        "standalone governance selector {selector:?} aliases an exact typed proposal"
                    ),
                });
            }
        }};
    }
    reject_typed_alias!("governance_referenda", world.governance_referenda);
    reject_typed_alias!("governance_locks", world.governance_locks);
    reject_typed_alias!("governance_slashes", world.governance_slashes);
    reject_typed_alias!("elections", world.elections);
    Ok(())
}

struct SoracloudInrouPersistedStateV1<'a> {
    sequence_watermark: u64,
    service_revisions: &'a Storage<(String, String), SoraDeploymentBundleV1>,
    service_deployments: &'a Storage<Name, SoraServiceDeploymentStateV1>,
    app_infra_states: &'a Storage<Name, SoraAppInfraStateV1>,
    service_runtime: &'a Storage<Name, SoraServiceRuntimeStateV1>,
    inrou_replica_runtime: &'a Storage<(String, String, String), SoraInrouReplicaRuntimeStateV1>,
    service_audit_events: &'a Storage<u64, SoraServiceAuditEventV1>,
    app_infra_audit_events: &'a Storage<u64, SoraAppInfraAuditEventV1>,
    training_job_audit_events: &'a Storage<u64, SoraTrainingJobAuditEventV1>,
    model_weight_audit_events: &'a Storage<u64, SoraModelWeightAuditEventV1>,
    model_artifact_audit_events: &'a Storage<u64, SoraModelArtifactAuditEventV1>,
    hf_shared_lease_audit_events: &'a Storage<u64, SoraHfSharedLeaseAuditEventV1>,
    agent_apartment_audit_events: &'a Storage<u64, SoraAgentApartmentAuditEventV1>,
    service_state_entries: &'a Storage<(String, String, String), SoraServiceStateEntryV1>,
    decryption_request_records: &'a Storage<(String, String), SoraDecryptionRequestRecordV1>,
    agent_apartments: &'a Storage<String, SoraAgentApartmentRecordV1>,
    training_jobs: &'a Storage<(String, String), SoraTrainingJobRecordV1>,
    model_registries: &'a Storage<(String, String), SoraModelRegistryV1>,
    model_weight_versions: &'a Storage<(String, String, String), SoraModelWeightVersionRecordV1>,
    model_artifacts: &'a Storage<(String, String), SoraModelArtifactRecordV1>,
    hf_sources: &'a Storage<Hash, SoraHfSourceRecordV1>,
    hf_shared_lease_pools: &'a Storage<Hash, SoraHfSharedLeasePoolV1>,
    hf_shared_lease_members: &'a Storage<(String, String), SoraHfSharedLeaseMemberV1>,
    inrou_host_capabilities: &'a Storage<AccountId, SoraInrouHostCapabilityRecordV1>,
    inrou_service_placements: &'a Storage<(String, String), SoraInrouServicePlacementRecordV1>,
    uploaded_model_bundles: &'a Storage<(String, String, String), SoraUploadedModelBundleV1>,
    mailbox_messages: &'a Storage<Hash, SoraServiceMailboxMessageV1>,
    runtime_receipts: &'a Storage<Hash, SoraRuntimeReceiptV1>,
}

impl SoracloudInrouPersistedStateV1<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "first-release restore validation keeps every authoritative Inrou-reachable store in one fail-closed boundary"
    )]
    fn validate(self) -> Result<(), json::Error> {
        let mut authoritative_sequences = std::collections::BTreeSet::new();
        let service_revisions = self.service_revisions.view();
        for (key, bundle) in service_revisions.iter() {
            bundle.require_production_support().map_err(|error| {
                invalid_soracloud_state("soracloud_service_revisions", error.to_string())
            })?;
            bundle.validate_for_admission().map_err(|error| {
                invalid_soracloud_state("soracloud_service_revisions", error.to_string())
            })?;
            let expected_key = (
                bundle.service.service_name.as_ref().to_owned(),
                bundle.service.service_version.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_service_revisions",
                    "storage key must match the embedded service_name and service_version",
                ));
            }
        }

        let uploaded_model_bundles = self.uploaded_model_bundles.view();
        for (key, bundle) in uploaded_model_bundles.iter() {
            bundle.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_uploaded_model_bundles", error.to_string())
            })?;
            let expected_key = (
                bundle.service_name.as_ref().to_owned(),
                bundle.model_id.clone(),
                bundle.weight_version.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_uploaded_model_bundles",
                    "storage key must match embedded service_name, model_id, and weight_version",
                ));
            }
        }

        let service_deployments = self.service_deployments.view();
        for ((_service_name, service_version), bundle) in service_revisions.iter() {
            if service_deployments
                .get(&bundle.service.service_name)
                .is_none()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_revisions",
                    format!(
                        "service `{}` admitted revision `{service_version}` has no authoritative deployment",
                        bundle.service.service_name
                    ),
                ));
            }
        }
        for (key, deployment) in service_deployments.iter() {
            deployment.require_production_support().map_err(|error| {
                invalid_soracloud_state("soracloud_service_deployments", error.to_string())
            })?;
            deployment.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_service_deployments", error.to_string())
            })?;
            if key != &deployment.service_name {
                return Err(invalid_soracloud_state(
                    "soracloud_service_deployments",
                    "storage key must match the embedded service_name",
                ));
            }
            let exact_revision_count = u32::try_from(
                service_revisions
                    .iter()
                    .filter(|((service_name, _), _)| {
                        service_name.as_str() == deployment.service_name.as_ref()
                    })
                    .count(),
            )
            .map_err(|error| {
                invalid_soracloud_state(
                    "soracloud_service_deployments",
                    format!(
                        "service `{}` admitted revision count does not fit u32: {error}",
                        deployment.service_name
                    ),
                )
            })?;
            if deployment.revision_count != exact_revision_count {
                return Err(invalid_soracloud_state(
                    "soracloud_service_deployments",
                    format!(
                        "service `{}` revision_count {} must equal its exact admitted revision count {exact_revision_count}",
                        deployment.service_name, deployment.revision_count
                    ),
                ));
            }
            let current_revision_key = (
                deployment.service_name.as_ref().to_owned(),
                deployment.current_service_version.clone(),
            );
            let current_bundle = service_revisions.get(&current_revision_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_service_deployments",
                    format!(
                        "service `{}` current revision `{}` is missing from soracloud_service_revisions",
                        deployment.service_name, deployment.current_service_version
                    ),
                )
            })?;
            deployment
                .validate_against_active_bundle(current_bundle)
                .map_err(|error| {
                    invalid_soracloud_state(
                        "soracloud_service_deployments",
                        format!(
                            "service `{}` current revision `{}` is not bound to its active admitted bundle: {error}",
                            deployment.service_name, deployment.current_service_version
                        ),
                    )
                })?;
            for ((_service_name, _service_version), revision) in
                service_revisions.iter().filter(|((service_name, _), _)| {
                    service_name.as_str() == deployment.service_name.as_ref()
                })
            {
                crate::soracloud_runtime::validate_soracloud_service_revision_identity(
                    current_bundle,
                    revision,
                )
                .map_err(|message| {
                    invalid_soracloud_state("soracloud_service_revisions", message)
                })?;
            }
            for (rollout_field, rollout) in [
                ("active_rollout", deployment.active_rollout.as_ref()),
                ("last_rollout", deployment.last_rollout.as_ref()),
            ] {
                let Some(rollout) = rollout else {
                    continue;
                };
                for (version_field, version) in [
                    (
                        "candidate_version",
                        Some(rollout.candidate_version.as_str()),
                    ),
                    ("baseline_version", Some(rollout.baseline_version.as_str())),
                ] {
                    let Some(version) = version else {
                        continue;
                    };
                    let revision_key = (
                        deployment.service_name.as_ref().to_owned(),
                        version.to_owned(),
                    );
                    if service_revisions.get(&revision_key).is_none() {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_deployments",
                            format!(
                                "service `{}` {rollout_field}.{version_field} `{version}` is missing from soracloud_service_revisions",
                                deployment.service_name
                            ),
                        ));
                    }
                }
            }
        }

        let app_infra_audit_events = self.app_infra_audit_events.view();
        for (sequence, event) in app_infra_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_app_infra_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_app_infra_audit_events",
                event.sequence,
            )?;
        }
        let app_infra_states = self.app_infra_states.view();
        for (key, state) in app_infra_states.iter() {
            state.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_app_infra_states", error.to_string())
            })?;
            if key != &state.app_name {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_states",
                    "storage key must match the embedded app_name",
                ));
            }
            let updated_event = app_infra_audit_events
                .get(&state.updated_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_app_infra_audit_events",
                        "app state is missing its exact updated_sequence audit event",
                    )
                })?;
            if updated_event.app_name != state.app_name
                || updated_event.to_version != state.current_app_version
                || updated_event.app_manifest_hash != state.current_manifest_hash
            {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "app state's current revision does not match its updated_sequence audit event",
                ));
            }
            let deployed_event = app_infra_audit_events
                .get(&state.deployed_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_app_infra_audit_events",
                        "app state is missing its exact deployed_sequence audit event",
                    )
                })?;
            if deployed_event.app_name != state.app_name {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "app state's deployed_sequence audit event belongs to another app",
                ));
            }
            let history = app_infra_audit_events
                .iter()
                .filter_map(|(sequence, event)| {
                    (event.app_name == state.app_name).then_some((*sequence, event))
                })
                .collect::<Vec<_>>();
            let history_count = u32::try_from(history.len()).map_err(|error| {
                invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    format!("app audit history length does not fit u32: {error}"),
                )
            })?;
            let first_event = history.first().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "app state has no authoritative audit history",
                )
            })?;
            let last_event = history.last().expect("non-empty app audit history");
            if history_count != state.revision_count
                || first_event.0 != state.deployed_sequence
                || first_event.1.action != iroha_data_model::soracloud::SoraAppInfraActionV1::Deploy
                || first_event.1.from_version.is_some()
                || last_event.0 != state.updated_sequence
                || u32::try_from(state.manifest.services.len()).map_or(true, |service_count| {
                    last_event.1.service_count != service_count
                })
            {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "app audit history must exactly project deployment, revision count, update head, and current service count",
                ));
            }
            for events in history.windows(2) {
                let previous = events[0].1;
                let current = events[1].1;
                if current.action != iroha_data_model::soracloud::SoraAppInfraActionV1::Upgrade
                    || current.from_version.as_deref() != Some(previous.to_version.as_str())
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_app_infra_audit_events",
                        "app upgrades must form one contiguous version history from the deployment event",
                    ));
                }
            }
            for service_ref in &state.manifest.services {
                let deployment = service_deployments
                    .get(&service_ref.service_name)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_app_infra_states",
                            format!(
                                "app `{}` service `{}` has no authoritative deployment",
                                state.app_name, service_ref.service_name
                            ),
                        )
                    })?;
                if deployment.current_service_version != service_ref.service_version
                    || deployment.current_service_manifest_hash != service_ref.service_manifest_hash
                    || deployment.current_container_manifest_hash
                        != service_ref.container_manifest_hash
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_app_infra_states",
                        format!(
                            "app `{}` service `{}` must exactly match its active deployment revision and manifest hashes",
                            state.app_name, service_ref.service_name
                        ),
                    ));
                }
                let revision_key = (
                    service_ref.service_name.as_ref().to_owned(),
                    service_ref.service_version.clone(),
                );
                let admitted_bundle = service_revisions.get(&revision_key).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_app_infra_states",
                        format!(
                            "app `{}` service `{}` revision `{}` has no admitted bundle",
                            state.app_name, service_ref.service_name, service_ref.service_version
                        ),
                    )
                })?;
                if admitted_bundle.service.execution_plane != service_ref.execution_plane
                    || admitted_bundle.container.runtime != service_ref.runtime
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_app_infra_states",
                        format!(
                            "app `{}` service `{}` execution plane and runtime must match its admitted bundle",
                            state.app_name, service_ref.service_name
                        ),
                    ));
                }
            }
        }
        for (_sequence, event) in app_infra_audit_events.iter() {
            if app_infra_states.get(&event.app_name).is_none() {
                return Err(invalid_soracloud_state(
                    "soracloud_app_infra_audit_events",
                    "app audit event has no authoritative app state",
                ));
            }
        }

        for (key, state) in self.service_runtime.view().iter() {
            state.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_service_runtime", error.to_string())
            })?;
            if key != &state.service_name {
                return Err(invalid_soracloud_state(
                    "soracloud_service_runtime",
                    "storage key must match the embedded service_name",
                ));
            }
            let deployment = service_deployments.get(key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_service_runtime",
                    format!("service `{key}` runtime state has no authoritative deployment"),
                )
            })?;
            if state.active_service_version != deployment.current_service_version {
                return Err(invalid_soracloud_state(
                    "soracloud_service_runtime",
                    format!(
                        "service `{key}` runtime revision `{}` must equal its active deployment revision `{}`",
                        state.active_service_version, deployment.current_service_version
                    ),
                ));
            }
            let admitted_bundle = service_revisions
                .get(&(
                    state.service_name.as_ref().to_owned(),
                    state.active_service_version.clone(),
                ))
                .expect("active deployment revision was validated above");
            if state.materialized_bundle_hash != admitted_bundle.container.bundle_hash {
                return Err(invalid_soracloud_state(
                    "soracloud_service_runtime",
                    "materialized bundle hash must equal the exact active admitted bundle",
                ));
            }
        }

        let inrou_service_placements = self.inrou_service_placements.view();
        for (key, state) in self.inrou_replica_runtime.view().iter() {
            state.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_inrou_replica_runtime", error.to_string())
            })?;
            let canonical_slot = state.replica_slot.to_string();
            let parsed_slot = key.2.parse::<u16>().map_err(|error| {
                invalid_soracloud_state(
                    "soracloud_inrou_replica_runtime",
                    format!("replica-slot storage key is not a canonical u16: {error}"),
                )
            })?;
            if key.0.as_str() != state.service_name.as_ref()
                || key.1.as_str() != state.service_version.as_str()
                || parsed_slot != state.replica_slot
                || key.2.as_str() != canonical_slot.as_str()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_replica_runtime",
                    "storage key must exactly match the embedded service revision and canonical replica slot",
                ));
            }
            let placement_record = inrou_service_placements
                .get(&(
                    state.service_name.as_ref().to_owned(),
                    state.service_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_replica_runtime",
                        format!(
                            "service `{}` revision `{}` replica {} has no authoritative placement record",
                            state.service_name, state.service_version, state.replica_slot
                        ),
                    )
                })?;
            let assignment = placement_record
                .placements
                .iter()
                .find(|placement| placement.replica_slot == state.replica_slot)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_replica_runtime",
                        format!(
                            "service `{}` revision `{}` replica {} has no authoritative placement assignment",
                            state.service_name, state.service_version, state.replica_slot
                        ),
                    )
                })?;
            if !assignment.host_availability.is_available()
                || state.placement_incarnation != assignment.placement_incarnation
                || state.validator_account_id != assignment.validator_account_id
                || state.peer_id != assignment.peer_id
                || state.selected_guest_isa != assignment.selected_guest_isa
            {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_replica_runtime",
                    "replica runtime identity must exactly match its authoritative placement assignment, which must be available",
                ));
            }
            let admitted_bundle = service_revisions
                .get(&(
                    state.service_name.as_ref().to_owned(),
                    state.service_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_replica_runtime",
                        "replica runtime references no retained admitted service revision",
                    )
                })?;
            if state.materialized_bundle_hash != admitted_bundle.container.bundle_hash {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_replica_runtime",
                    "materialized bundle hash must equal the exact admitted Inrou bundle",
                ));
            }
        }

        let service_audit_events = self.service_audit_events.view();
        let mut previous_service_event_height = 0_u64;
        let mut previous_service_event_timestamp_ms = 0_u64;
        for (sequence, event) in service_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_service_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            if event.block_height < previous_service_event_height
                || event.block_timestamp_ms < previous_service_event_timestamp_ms
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    "audit block heights and timestamps must be nondecreasing in global sequence order",
                ));
            }
            previous_service_event_height = event.block_height;
            previous_service_event_timestamp_ms = event.block_timestamp_ms;
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_service_audit_events",
                event.sequence,
            )?;
            if service_deployments.get(&event.service_name).is_none() {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    "service audit event has no authoritative deployment",
                ));
            }
            let event_bundle = service_revisions
                .get(&(
                    event.service_name.as_ref().to_owned(),
                    event.to_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        "service audit event has no exact retained target revision",
                    )
                })?;
            if event.service_manifest_hash != event_bundle.service_manifest_hash()
                || event.container_manifest_hash != event_bundle.container_manifest_hash()
                || event.from_version.as_ref().is_some_and(|from_version| {
                    service_revisions
                        .get(&(event.service_name.as_ref().to_owned(), from_version.clone()))
                        .is_none()
                })
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    "service audit event must exactly bind retained source/target revisions and target manifest hashes",
                ));
            }
        }

        validate_soracloud_service_deployment_history(
            &service_revisions,
            &service_deployments,
            &service_audit_events,
        )?;

        let training_job_audit_events = self.training_job_audit_events.view();
        for (sequence, event) in training_job_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_training_job_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_training_job_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_training_job_audit_events",
                event.sequence,
            )?;
        }

        let model_weight_audit_events = self.model_weight_audit_events.view();
        for (sequence, event) in model_weight_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_model_weight_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_model_weight_audit_events",
                event.sequence,
            )?;
        }

        let model_artifact_audit_events = self.model_artifact_audit_events.view();
        for (sequence, event) in model_artifact_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_model_artifact_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifact_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_model_artifact_audit_events",
                event.sequence,
            )?;
        }

        let hf_shared_lease_audit_events = self.hf_shared_lease_audit_events.view();
        for (sequence, event) in hf_shared_lease_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_hf_shared_lease_audit_events", error.to_string())
            })?;
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_hf_shared_lease_audit_events",
                event.sequence,
            )?;
        }

        let agent_apartment_audit_events = self.agent_apartment_audit_events.view();
        let mut previous_agent_event_height = 0_u64;
        let mut previous_agent_event_timestamp_ms = 0_u64;
        for (sequence, event) in agent_apartment_audit_events.iter() {
            event.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_agent_apartment_audit_events", error.to_string())
            })?;
            let expected_status = if event.block_height >= event.lease_expires_height {
                iroha_data_model::soracloud::SoraAgentRuntimeStatusV1::LeaseExpired
            } else {
                iroha_data_model::soracloud::SoraAgentRuntimeStatusV1::Running
            };
            if event.status != expected_status {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "audit status must equal the consensus-height lease projection",
                ));
            }
            if sequence != &event.sequence {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "storage key must match the embedded audit sequence",
                ));
            }
            if event.block_height < previous_agent_event_height
                || event.block_timestamp_ms < previous_agent_event_timestamp_ms
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "audit heights and timestamps must be nondecreasing in sequence order",
                ));
            }
            previous_agent_event_height = event.block_height;
            previous_agent_event_timestamp_ms = event.block_timestamp_ms;
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_agent_apartment_audit_events",
                event.sequence,
            )?;
        }

        let mut service_binding_total_bytes =
            std::collections::BTreeMap::<(String, String), u64>::new();
        for (key, entry) in self.service_state_entries.view().iter() {
            entry
                .encryption
                .require_production_support()
                .map_err(|error| {
                    invalid_soracloud_state("soracloud_service_state_entries", error.to_string())
                })?;
            entry.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_service_state_entries", error.to_string())
            })?;
            let expected_key = (
                entry.service_name.as_ref().to_owned(),
                entry.binding_name.as_ref().to_owned(),
                entry.state_key.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_service_state_entries",
                    "storage key must match the embedded service_name, binding_name, and state_key",
                ));
            }
            let revision_key = (
                entry.service_name.as_ref().to_owned(),
                entry.service_version.clone(),
            );
            let bundle = service_revisions.get(&revision_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_service_state_entries",
                    format!(
                        "state row `{}` references missing service revision `{}`",
                        entry.state_key, entry.service_version
                    ),
                )
            })?;
            let binding = bundle
                .service
                .state_bindings
                .iter()
                .find(|binding| binding.binding_name == entry.binding_name)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_state_entries",
                        format!(
                            "state row `{}` references undeclared binding `{}` on revision `{}`",
                            entry.state_key, entry.binding_name, entry.service_version
                        ),
                    )
                })?;
            if entry.encryption != binding.encryption
                || !entry.state_key.starts_with(&binding.key_prefix)
                || entry.payload_bytes > binding.max_item_bytes
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_state_entries",
                    format!(
                        "state row `{}` must satisfy the exact encryption, key prefix, and item limit of binding `{}` revision `{}`",
                        entry.state_key, entry.binding_name, entry.service_version
                    ),
                ));
            }
            let audit_event = service_audit_events
                .get(&entry.last_update_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_state_entries",
                        format!(
                            "state row `{}` references missing service audit sequence {}",
                            entry.state_key, entry.last_update_sequence
                        ),
                    )
                })?;
            if audit_event.action != entry.source_action
                || audit_event.service_name != entry.service_name
                || audit_event.to_version != entry.service_version
                || audit_event.service_manifest_hash != bundle.service_manifest_hash()
                || audit_event.container_manifest_hash != bundle.container_manifest_hash()
                || audit_event.governance_tx_hash != Some(entry.governance_tx_hash)
                || audit_event.binding_name.as_ref() != Some(&entry.binding_name)
                || audit_event.state_key.as_deref() != Some(entry.state_key.as_str())
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_state_entries",
                    format!(
                        "state row `{}` must exactly match its producing service audit event",
                        entry.state_key
                    ),
                ));
            }
            let aggregate_key = (
                entry.service_name.as_ref().to_owned(),
                entry.binding_name.as_ref().to_owned(),
            );
            let aggregate = service_binding_total_bytes
                .entry(aggregate_key)
                .or_default();
            *aggregate = aggregate
                .checked_add(entry.payload_bytes.get())
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_state_entries",
                        format!(
                            "binding `{}` aggregate payload size overflows u64",
                            entry.binding_name
                        ),
                    )
                })?;
            if *aggregate > binding.max_total_bytes.get() {
                return Err(invalid_soracloud_state(
                    "soracloud_service_state_entries",
                    format!(
                        "binding `{}` aggregate payload size exceeds its admitted maximum",
                        entry.binding_name
                    ),
                ));
            }
        }

        let decryption_request_records = self.decryption_request_records.view();
        for (key, record) in decryption_request_records.iter() {
            record.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_decryption_request_records", error.to_string())
            })?;
            let expected_key = (
                record.service_name.as_ref().to_owned(),
                record.request.request_id.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_decryption_request_records",
                    "storage key must match the embedded service_name and request_id",
                ));
            }
            let revision_key = (
                record.service_name.as_ref().to_owned(),
                record.service_version.clone(),
            );
            let bundle = service_revisions.get(&revision_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_decryption_request_records",
                    format!(
                        "decryption request `{}` references missing service revision `{}`",
                        record.request.request_id, record.service_version
                    ),
                )
            })?;
            let binding = bundle
                .service
                .state_bindings
                .iter()
                .find(|binding| binding.binding_name == record.request.binding_name)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_decryption_request_records",
                        "decryption request binding must exist in its retained service revision",
                    )
                })?;
            if binding.encryption == iroha_data_model::soracloud::SoraStateEncryptionV1::Plaintext
                || !record.request.state_key.starts_with(&binding.key_prefix)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_decryption_request_records",
                    "decryption request must target non-plaintext state within its declared binding prefix",
                ));
            }
            let event = service_audit_events.get(&record.sequence).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_decryption_request_records",
                    "decryption request is missing its exact audit sequence",
                )
            })?;
            if event.action
                != iroha_data_model::soracloud::SoraServiceLifecycleActionV1::DecryptionRequest
                || event.service_name != record.service_name
                || event.from_version.is_some()
                || event.to_version != record.service_version
                || event.service_manifest_hash != bundle.service_manifest_hash()
                || event.container_manifest_hash != bundle.container_manifest_hash()
                || event.governance_tx_hash != Some(record.request.governance_tx_hash)
                || event.binding_name.as_ref() != Some(&record.request.binding_name)
                || event.state_key.as_deref() != Some(record.request.state_key.as_str())
                || !event.config_mutations.is_empty()
                || !event.secret_mutations.is_empty()
                || event.rollout_state.is_some()
                || event.policy_name.as_ref() != Some(&record.request.policy_name)
                || event.policy_snapshot_hash != Some(record.policy_snapshot_hash())
                || event.jurisdiction_tag.as_deref()
                    != Some(record.request.jurisdiction_tag.as_str())
                || event.consent_evidence_hash != record.request.consent_evidence_hash
                || event.break_glass != Some(record.request.break_glass)
                || event.break_glass_reason.as_deref()
                    != record.request.break_glass_reason.as_deref()
                || event.lease_reporting_epoch_rollover.is_some()
                || event.signer != record.signer
            {
                return Err(invalid_soracloud_state(
                    "soracloud_decryption_request_records",
                    "decryption request must exactly match its retained service audit event and revision",
                ));
            }
        }
        for event in service_audit_events
            .iter()
            .filter_map(|(_sequence, event)| {
                (event.action
                    == iroha_data_model::soracloud::SoraServiceLifecycleActionV1::DecryptionRequest)
                    .then_some(event)
            })
        {
            if !decryption_request_records.iter().any(|(_key, record)| {
                record.sequence == event.sequence && record.service_name == event.service_name
            }) {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    "decryption-request audit event has no authoritative request record",
                ));
            }
        }

        let training_jobs = self.training_jobs.view();
        for (key, job) in training_jobs.iter() {
            job.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_training_jobs", error.to_string())
            })?;
            let expected_key = (job.service_name.as_ref().to_owned(), job.job_id.clone());
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "storage key must match the embedded service_name and job_id",
                ));
            }
            let job_revision_key = (
                job.service_name.as_ref().to_owned(),
                job.service_version.clone(),
            );
            let job_bundle = service_revisions.get(&job_revision_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "training job references a missing retained service revision",
                )
            })?;
            if !job_bundle.container.capabilities.allow_model_training {
                return Err(invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "training job revision must admit model training",
                ));
            }
            let created_event = training_job_audit_events
                .get(&job.created_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_training_jobs",
                        "training job is missing its exact created_sequence audit event",
                    )
                })?;
            if created_event.action != iroha_data_model::soracloud::SoraTrainingJobActionV1::Start
                || created_event.service_name != job.service_name
                || created_event.model_name != job.model_name
                || created_event.job_id != job.job_id
                || created_event.status
                    != iroha_data_model::soracloud::SoraTrainingJobStatusV1::Running
                || created_event.completed_steps != 0
                || created_event.checkpoint_count != 0
                || created_event.retry_count != 0
                || created_event.compute_consumed_units != 0
                || created_event.storage_consumed_bytes != 0
                || created_event.last_checkpoint_step.is_some()
                || created_event.latest_metrics_hash.is_some()
                || created_event.last_failure_reason.is_some()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "training job created_sequence must be its exact initial Start projection",
                ));
            }
            let updated_event = training_job_audit_events
                .get(&job.updated_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_training_jobs",
                        "training job is missing its exact updated_sequence audit event",
                    )
                })?;
            if updated_event.service_name != job.service_name
                || updated_event.service_version != job.service_version
                || updated_event.model_name != job.model_name
                || updated_event.job_id != job.job_id
                || updated_event.status != job.status
                || updated_event.completed_steps != job.completed_steps
                || updated_event.checkpoint_count != job.checkpoint_count
                || updated_event.retry_count != job.retry_count
                || updated_event.compute_consumed_units != job.compute_consumed_units
                || updated_event.storage_consumed_bytes != job.storage_consumed_bytes
                || updated_event.last_checkpoint_step != job.last_checkpoint_step
                || updated_event.latest_metrics_hash != job.latest_metrics_hash
                || updated_event.last_failure_reason != job.last_failure_reason
            {
                return Err(invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "training job must exactly match its updated_sequence audit projection",
                ));
            }
            let latest_sequence = training_job_audit_events
                .iter()
                .filter_map(|(sequence, event)| {
                    (event.service_name == job.service_name && event.job_id == job.job_id)
                        .then_some(*sequence)
                })
                .max();
            if latest_sequence != Some(job.updated_sequence) {
                return Err(invalid_soracloud_state(
                    "soracloud_training_jobs",
                    "updated_sequence must be the latest audit event for the training job",
                ));
            }
        }
        for event in training_job_audit_events
            .iter()
            .map(|(_sequence, event)| event)
        {
            let job_key = (event.service_name.as_ref().to_owned(), event.job_id.clone());
            let job = training_jobs.get(&job_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_training_job_audit_events",
                    "training-job audit event has no authoritative job record",
                )
            })?;
            let revision_key = (
                event.service_name.as_ref().to_owned(),
                event.service_version.clone(),
            );
            let bundle = service_revisions.get(&revision_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_training_job_audit_events",
                    "training-job audit event references a missing retained service revision",
                )
            })?;
            if event.model_name != job.model_name
                || !bundle.container.capabilities.allow_model_training
                || (event.action == iroha_data_model::soracloud::SoraTrainingJobActionV1::Start
                    && event.sequence != job.created_sequence)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_training_job_audit_events",
                    "training-job audit identity, revision, or Start sequence is inconsistent",
                ));
            }
        }

        for (_key, bundle) in uploaded_model_bundles.iter() {
            if service_deployments.get(&bundle.service_name).is_none() {
                return Err(invalid_soracloud_state(
                    "soracloud_uploaded_model_bundles",
                    "uploaded-model bundle owner must have an authoritative service deployment",
                ));
            }
        }

        let model_registries = self.model_registries.view();
        let model_weight_versions = self.model_weight_versions.view();
        for (key, registry) in model_registries.iter() {
            registry.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_model_registries", error.to_string())
            })?;
            let expected_key = (
                registry.service_name.as_ref().to_owned(),
                registry.model_name.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "storage key must match the embedded service_name and model_name",
                ));
            }
            if service_revisions
                .get(&(
                    registry.service_name.as_ref().to_owned(),
                    registry.service_version.clone(),
                ))
                .is_none()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "model registry references a missing retained service revision",
                ));
            }
            let updated_event = model_weight_audit_events
                .get(&registry.updated_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_model_registries",
                        "model registry is missing its exact updated_sequence audit event",
                    )
                })?;
            if updated_event.service_name != registry.service_name
                || updated_event.service_version != registry.service_version
                || updated_event.model_name != registry.model_name
                || updated_event.current_version != registry.current_version
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "model registry must exactly match its updated_sequence audit projection",
                ));
            }
            let latest_sequence = model_weight_audit_events
                .iter()
                .filter_map(|(sequence, event)| {
                    (event.service_name == registry.service_name
                        && event.model_name == registry.model_name)
                        .then_some(*sequence)
                })
                .max();
            if latest_sequence != Some(registry.updated_sequence) {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "updated_sequence must be the latest audit event for the model registry",
                ));
            }
            let registry_weights = model_weight_versions
                .iter()
                .filter(|((_service, _model, _version), weight)| {
                    weight.service_name == registry.service_name
                        && weight.model_name == registry.model_name
                })
                .map(|(_key, weight)| weight)
                .collect::<Vec<_>>();
            if registry_weights.is_empty()
                || registry_weights
                    .iter()
                    .filter(|weight| weight.parent_version.is_none())
                    .count()
                    != 1
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "each model registry must own weights with exactly one lineage root",
                ));
            }
            if let Some(current_version) = registry.current_version.as_ref()
                && !registry_weights
                    .iter()
                    .any(|weight| weight.weight_version == *current_version)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_registries",
                    "current_version must resolve to an authoritative model weight",
                ));
            }
        }

        for (key, weight) in model_weight_versions.iter() {
            weight.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_model_weight_versions", error.to_string())
            })?;
            let expected_key = (
                weight.service_name.as_ref().to_owned(),
                weight.model_name.clone(),
                weight.weight_version.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "storage key must match embedded service_name, model_name, and weight_version",
                ));
            }
            if service_revisions
                .get(&(
                    weight.service_name.as_ref().to_owned(),
                    weight.service_version.clone(),
                ))
                .is_none()
                || model_registries
                    .get(&(
                        weight.service_name.as_ref().to_owned(),
                        weight.model_name.clone(),
                    ))
                    .is_none()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "model weight must reference a retained service revision and registry",
                ));
            }
            let Some(source) = weight.source_provenance.as_ref() else {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "first-release model weights require explicit source_provenance",
                ));
            };
            if source.kind
                == iroha_data_model::soracloud::SoraModelProvenanceKindV1::HfSourceAdmission
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "first-release state cannot contain unwritten HF source-admission provenance",
                ));
            }
            if (source.kind == iroha_data_model::soracloud::SoraModelProvenanceKindV1::TrainingJob
                && weight.training_job_id != source.id)
                || (source.kind
                    == iroha_data_model::soracloud::SoraModelProvenanceKindV1::UserUpload
                    && !weight.training_job_id.is_empty())
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "model weight training_job_id must exactly match its first-release provenance kind",
                ));
            }
            let registered_event = model_weight_audit_events
                .get(&weight.registered_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_model_weight_versions",
                        "model weight is missing its exact registered_sequence audit event",
                    )
                })?;
            if registered_event.action
                != iroha_data_model::soracloud::SoraModelWeightActionV1::Register
                || registered_event.service_name != weight.service_name
                || registered_event.model_name != weight.model_name
                || registered_event.target_version != weight.weight_version
                || registered_event.parent_version != weight.parent_version
                || registered_event.gate_approved.is_some()
                || registered_event.rollback_reason.is_some()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "model weight must exactly match its registration audit event",
                ));
            }
            if let Some(parent_version) = weight.parent_version.as_ref() {
                let parent = model_weight_versions
                    .get(&(
                        weight.service_name.as_ref().to_owned(),
                        weight.model_name.clone(),
                        parent_version.clone(),
                    ))
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_model_weight_versions",
                            "model weight parent_version is missing from its registry lineage",
                        )
                    })?;
                if parent.registered_sequence >= weight.registered_sequence {
                    return Err(invalid_soracloud_state(
                        "soracloud_model_weight_versions",
                        "model weight parent must have an earlier registration sequence",
                    ));
                }
            }
            if let Some(promoted_sequence) = weight.promoted_sequence {
                let promoted_event = model_weight_audit_events
                    .get(&promoted_sequence)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_model_weight_versions",
                            "promoted model weight is missing its exact promotion audit event",
                        )
                    })?;
                if promoted_event.action
                    != iroha_data_model::soracloud::SoraModelWeightActionV1::Promote
                    || promoted_event.service_name != weight.service_name
                    || promoted_event.service_version != weight.service_version
                    || promoted_event.model_name != weight.model_name
                    || promoted_event.target_version != weight.weight_version
                    || promoted_event.current_version.as_deref()
                        != Some(weight.weight_version.as_str())
                    || promoted_event.parent_version != weight.parent_version
                    || promoted_event.gate_approved != Some(true)
                    || promoted_event.rollback_reason.is_some()
                    || weight.promoted_by.as_ref() != Some(&promoted_event.signer)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_model_weight_versions",
                        "promoted model weight must exactly match its promotion audit event",
                    ));
                }
                let latest_promotion = model_weight_audit_events
                    .iter()
                    .filter_map(|(sequence, event)| {
                        (event.action
                            == iroha_data_model::soracloud::SoraModelWeightActionV1::Promote
                            && event.service_name == weight.service_name
                            && event.model_name == weight.model_name
                            && event.target_version == weight.weight_version)
                            .then_some(*sequence)
                    })
                    .max();
                if latest_promotion != Some(promoted_sequence) {
                    return Err(invalid_soracloud_state(
                        "soracloud_model_weight_versions",
                        "promoted_sequence must be the latest promotion of that model weight",
                    ));
                }
            }
        }
        for event in model_weight_audit_events
            .iter()
            .map(|(_sequence, event)| event)
        {
            let weight = model_weight_versions
                .get(&(
                    event.service_name.as_ref().to_owned(),
                    event.model_name.clone(),
                    event.target_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_model_weight_audit_events",
                        "model-weight audit event has no authoritative target weight",
                    )
                })?;
            if service_revisions
                .get(&(
                    event.service_name.as_ref().to_owned(),
                    event.service_version.clone(),
                ))
                .is_none()
                || event.parent_version != weight.parent_version
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_audit_events",
                    "model-weight audit event references a missing revision or wrong lineage parent",
                ));
            }
            let action_shape_is_valid = match event.action {
                iroha_data_model::soracloud::SoraModelWeightActionV1::Register => {
                    event.gate_approved.is_none() && event.rollback_reason.is_none()
                }
                iroha_data_model::soracloud::SoraModelWeightActionV1::Promote => {
                    event.gate_approved == Some(true)
                        && event.rollback_reason.is_none()
                        && event.current_version.as_deref() == Some(event.target_version.as_str())
                }
                iroha_data_model::soracloud::SoraModelWeightActionV1::Rollback => {
                    event.gate_approved.is_none()
                        && event.rollback_reason.is_some()
                        && event.current_version.as_deref() == Some(event.target_version.as_str())
                }
            };
            if !action_shape_is_valid {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_audit_events",
                    "model-weight audit event fields do not match its lifecycle action",
                ));
            }
        }

        let model_artifacts = self.model_artifacts.view();
        for (key, artifact) in model_artifacts.iter() {
            artifact.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_model_artifacts", error.to_string())
            })?;
            let expected_key = (
                artifact.service_name.as_ref().to_owned(),
                artifact.artifact_id.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifacts",
                    "storage key must match the embedded service_name and artifact_id",
                ));
            }
            if service_revisions
                .get(&(
                    artifact.service_name.as_ref().to_owned(),
                    artifact.service_version.clone(),
                ))
                .is_none()
                || artifact.weight_version != artifact.consumed_by_version
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifacts",
                    "model artifact must reference a retained revision and carry paired weight consumption metadata",
                ));
            }
            let Some(source) = artifact.source_provenance.as_ref() else {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifacts",
                    "first-release model artifacts require explicit source_provenance",
                ));
            };
            let registered_event = model_artifact_audit_events
                .get(&artifact.registered_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_model_artifacts",
                        "model artifact is missing its exact registration audit event",
                    )
                })?;
            if registered_event.action
                != iroha_data_model::soracloud::SoraModelArtifactActionV1::Register
                || registered_event.service_name != artifact.service_name
                || registered_event.model_name != artifact.model_name
                || registered_event.training_job_id != artifact.artifact_id
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifacts",
                    "model artifact identity must exactly match its registration audit event",
                ));
            }
            let linked_weight = artifact.weight_version.as_ref().and_then(|version| {
                model_weight_versions.get(&(
                    artifact.service_name.as_ref().to_owned(),
                    artifact.model_name.clone(),
                    version.clone(),
                ))
            });
            match source.kind {
                iroha_data_model::soracloud::SoraModelProvenanceKindV1::TrainingJob => {
                    if source.id != artifact.training_job_id
                        || artifact.training_job_id != artifact.artifact_id
                        || artifact.chunk_manifest_root.is_some()
                        || registered_event.consumed_by_version.is_some()
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_model_artifacts",
                            "training-job artifact provenance and registration shape are inconsistent",
                        ));
                    }
                    let job = training_jobs
                        .get(&(
                            artifact.service_name.as_ref().to_owned(),
                            artifact.training_job_id.clone(),
                        ))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_model_artifacts",
                                "training-job artifact references a missing authoritative job",
                            )
                        })?;
                    if job.model_name != artifact.model_name
                        || job.status
                            != iroha_data_model::soracloud::SoraTrainingJobStatusV1::Completed
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_model_artifacts",
                            "training-job artifact must reference the completed matching model job",
                        ));
                    }
                }
                iroha_data_model::soracloud::SoraModelProvenanceKindV1::UserUpload => {
                    let Some(weight_version) = artifact.weight_version.as_ref() else {
                        return Err(invalid_soracloud_state(
                            "soracloud_model_artifacts",
                            "user-upload artifact must be consumed by its finalized weight version",
                        ));
                    };
                    let bundle = uploaded_model_bundles
                        .get(&(
                            artifact.service_name.as_ref().to_owned(),
                            source.id.clone(),
                            weight_version.clone(),
                        ))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_model_artifacts",
                                "user-upload artifact references a missing uploaded-model bundle",
                            )
                        })?;
                    if artifact.training_job_id != artifact.artifact_id
                        || artifact.chunk_manifest_root != Some(bundle.chunk_manifest_root)
                        || registered_event.consumed_by_version.as_ref() != Some(weight_version)
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_model_artifacts",
                            "user-upload artifact must exactly bind its bundle and registration projection",
                        ));
                    }
                }
                iroha_data_model::soracloud::SoraModelProvenanceKindV1::HfSourceAdmission => {
                    return Err(invalid_soracloud_state(
                        "soracloud_model_artifacts",
                        "first-release state cannot contain unwritten HF source-admission provenance",
                    ));
                }
            }
            if let Some(weight) = linked_weight {
                if (source.kind
                    == iroha_data_model::soracloud::SoraModelProvenanceKindV1::TrainingJob
                    && weight.training_job_id != artifact.training_job_id)
                    || weight.source_provenance.as_ref() != Some(source)
                    || weight.weight_artifact_hash != artifact.weight_artifact_hash
                    || weight.dataset_ref != artifact.dataset_ref
                    || weight.training_config_hash != artifact.training_config_hash
                    || weight.reproducibility_hash != artifact.reproducibility_hash
                    || weight.provenance_attestation_hash != artifact.provenance_attestation_hash
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_model_artifacts",
                        "consumed model artifact must exactly match its authoritative weight provenance",
                    ));
                }
            } else if artifact.weight_version.is_some() {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifacts",
                    "consumed model artifact references a missing authoritative weight",
                ));
            }
        }
        for (_key, weight) in model_weight_versions.iter() {
            let linked_artifact_count = model_artifacts
                .iter()
                .filter(|((_service, _artifact_id), artifact)| {
                    artifact.service_name == weight.service_name
                        && artifact.model_name == weight.model_name
                        && artifact.weight_version.as_deref()
                            == Some(weight.weight_version.as_str())
                        && artifact.source_provenance == weight.source_provenance
                })
                .count();
            if linked_artifact_count != 1 {
                return Err(invalid_soracloud_state(
                    "soracloud_model_weight_versions",
                    "each model weight must resolve to exactly one consumed provenance artifact",
                ));
            }
        }
        for event in model_artifact_audit_events
            .iter()
            .map(|(_sequence, event)| event)
        {
            let artifact = model_artifacts
                .get(&(
                    event.service_name.as_ref().to_owned(),
                    event.training_job_id.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_model_artifact_audit_events",
                        "model-artifact audit event has no authoritative artifact record",
                    )
                })?;
            if service_revisions
                .get(&(
                    event.service_name.as_ref().to_owned(),
                    event.service_version.clone(),
                ))
                .is_none()
                || event.sequence != artifact.registered_sequence
                || event.service_version != artifact.service_version
                || event.model_name != artifact.model_name
                || event.training_job_id != artifact.artifact_id
                || event.consumed_by_version != artifact.consumed_by_version
            {
                return Err(invalid_soracloud_state(
                    "soracloud_model_artifact_audit_events",
                    "model-artifact audit event must be the artifact's unique exact registration projection",
                ));
            }
        }

        let runtime_receipts = self.runtime_receipts.view();
        let agent_apartments = self.agent_apartments.view();
        validate_soracloud_agent_apartment_records(
            &agent_apartments,
            &agent_apartment_audit_events,
        )?;
        validate_soracloud_agent_apartment_history(
            &agent_apartments,
            &agent_apartment_audit_events,
            &runtime_receipts,
        )?;

        let hf_sources = self.hf_sources.view();
        for (key, source) in hf_sources.iter() {
            source.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_hf_sources", error.to_string())
            })?;
            if key != &source.source_id {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_sources",
                    "storage key must match the embedded source_id",
                ));
            }
        }

        let hf_shared_lease_pools = self.hf_shared_lease_pools.view();
        let hf_shared_lease_members = self.hf_shared_lease_members.view();
        for (key, pool) in hf_shared_lease_pools.iter() {
            pool.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_hf_shared_lease_pools", error.to_string())
            })?;
            let expected_pool_id = iroha_data_model::soracloud::derive_hf_shared_lease_pool_id_v1(
                pool.source_id,
                pool.storage_class,
                pool.lease_term_ms,
            )
            .map_err(|error| {
                invalid_soracloud_state("soracloud_hf_shared_lease_pools", error.to_string())
            })?;
            if key != &pool.pool_id || pool.pool_id != expected_pool_id {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_pools",
                    "storage key and pool_id must equal the canonical source/class/term identity",
                ));
            }
            if hf_sources.get(&pool.source_id).is_none() {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_pools",
                    "HF shared-lease pool references a missing canonical source",
                ));
            }
            let active_member_count = u32::try_from(
                hf_shared_lease_members
                    .iter()
                    .filter(|((_pool, _account), member)| {
                        member.pool_id == pool.pool_id
                            && member.status
                                == iroha_data_model::soracloud::SoraHfSharedLeaseMemberStatusV1::Active
                    })
                    .count(),
            )
            .map_err(|error| {
                invalid_soracloud_state(
                    "soracloud_hf_shared_lease_pools",
                    format!("active member count does not fit u32: {error}"),
                )
            })?;
            if pool.active_member_count != active_member_count
                || (pool.status == iroha_data_model::soracloud::SoraHfSharedLeaseStatusV1::Active)
                    != (active_member_count > 0)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_pools",
                    "pool status and active_member_count must equal the exact membership projection",
                ));
            }
            if let Some(queued) = pool.queued_next_window.as_ref() {
                let sponsor = hf_shared_lease_members
                    .get(&(
                        pool.pool_id.to_string(),
                        queued.sponsor_account_id.to_string(),
                    ))
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_hf_shared_lease_pools",
                            "queued-window sponsor is missing from the pool membership store",
                        )
                    })?;
                if sponsor.status
                    != iroha_data_model::soracloud::SoraHfSharedLeaseMemberStatusV1::Active
                    || sponsor.source_id != pool.source_id
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_hf_shared_lease_pools",
                        "queued-window sponsor must be an active member of the exact source pool",
                    ));
                }
            }
        }
        for (key, member) in hf_shared_lease_members.iter() {
            member.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_hf_shared_lease_members", error.to_string())
            })?;
            let expected_key = (member.pool_id.to_string(), member.account_id.to_string());
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_members",
                    "storage key must match the embedded pool_id and account_id",
                ));
            }
            let pool = hf_shared_lease_pools.get(&member.pool_id).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_hf_shared_lease_members",
                    "HF shared-lease member references a missing pool",
                )
            })?;
            if member.source_id != pool.source_id {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_members",
                    "HF shared-lease member source_id must match its pool",
                ));
            }
            for service_name in &member.service_bindings {
                let parsed_name = service_name.parse::<Name>().map_err(|error| {
                    invalid_soracloud_state(
                        "soracloud_hf_shared_lease_members",
                        format!("service binding is not a canonical Name: {error}"),
                    )
                })?;
                if parsed_name.as_ref() != service_name.as_str() {
                    return Err(invalid_soracloud_state(
                        "soracloud_hf_shared_lease_members",
                        "service binding must use its canonical Name spelling",
                    ));
                }
            }
            for apartment_name in &member.apartment_bindings {
                let parsed_name = apartment_name.parse::<Name>().map_err(|error| {
                    invalid_soracloud_state(
                        "soracloud_hf_shared_lease_members",
                        format!("apartment binding is not a canonical Name: {error}"),
                    )
                })?;
                if parsed_name.as_ref() != apartment_name.as_str() {
                    return Err(invalid_soracloud_state(
                        "soracloud_hf_shared_lease_members",
                        "apartment binding must use its canonical Name spelling",
                    ));
                }
            }
        }
        for event in hf_shared_lease_audit_events
            .iter()
            .map(|(_sequence, event)| event)
        {
            let pool = hf_shared_lease_pools.get(&event.pool_id).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_hf_shared_lease_audit_events",
                    "HF shared-lease audit event references a missing retained pool",
                )
            })?;
            if event.source_id != pool.source_id {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_audit_events",
                    "HF shared-lease audit source_id must match its retained pool",
                ));
            }
            let member = hf_shared_lease_members
                .get(&(event.pool_id.to_string(), event.account_id.to_string()))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_hf_shared_lease_audit_events",
                        "HF shared-lease audit account has no retained member in the exact pool",
                    )
                })?;
            if member.source_id != event.source_id {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_shared_lease_audit_events",
                    "HF shared-lease audit member source_id must match the event and pool",
                ));
            }
            for (field, binding) in [
                ("service_name", event.service_name.as_deref()),
                ("apartment_name", event.apartment_name.as_deref()),
            ] {
                if let Some(binding) = binding {
                    let parsed = binding.parse::<Name>().map_err(|error| {
                        invalid_soracloud_state(
                            "soracloud_hf_shared_lease_audit_events",
                            format!("{field} is not a canonical Name: {error}"),
                        )
                    })?;
                    if parsed.as_ref() != binding {
                        return Err(invalid_soracloud_state(
                            "soracloud_hf_shared_lease_audit_events",
                            format!("{field} must use its canonical Name spelling"),
                        ));
                    }
                }
            }
        }

        for (source_id, _source) in hf_sources.iter() {
            if !hf_shared_lease_pools
                .iter()
                .any(|(_pool_id, pool)| pool.source_id == *source_id)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_hf_sources",
                    "canonical HF source has no retained shared-lease pool",
                ));
            }
        }

        let inrou_host_capabilities = self.inrou_host_capabilities.view();
        for (key, capability) in inrou_host_capabilities.iter() {
            capability.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_inrou_host_capabilities", error.to_string())
            })?;
            if key != &capability.validator_account_id {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_host_capabilities",
                    "storage key must match the embedded validator_account_id",
                ));
            }
        }

        let mut inrou_reservation_usage = BTreeMap::<AccountId, (u32, u64, u64, u64)>::new();
        let mut inrou_available_hosts = BTreeSet::<AccountId>::new();
        for (key, placement) in inrou_service_placements.iter() {
            placement.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_inrou_service_placements", error.to_string())
            })?;
            let expected_key = (
                placement.service_name.as_ref().to_owned(),
                placement.service_version.clone(),
            );
            if key != &expected_key {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "storage key must match the embedded service_name and service_version",
                ));
            }
            let admitted_key = (
                placement.service_name.as_ref().to_owned(),
                placement.service_version.clone(),
            );
            let admitted_bundle = service_revisions.get(&admitted_key).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    format!(
                        "service `{}` revision `{}` placement has no admitted bundle",
                        placement.service_name, placement.service_version
                    ),
                )
            })?;
            let deployment = service_deployments
                .get(&placement.service_name)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        format!(
                            "service `{}` revision `{}` placement has no authoritative deployment",
                            placement.service_name, placement.service_version
                        ),
                    )
                })?;
            if deployment.current_service_version != placement.service_version {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "first-release Inrou placement must reference the exact active deployment revision",
                ));
            }
            let lease = deployment.service_lease.as_ref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "Inrou placement requires an authoritative hosted-service lease",
                )
            })?;
            if admitted_bundle.container.runtime
                != iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou
                || admitted_bundle.service.execution_plane
                    != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
            {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "Inrou placement must reference an admitted Inrou HTTP-service revision",
                ));
            }
            if placement.desired_replica_count != admitted_bundle.service.replicas.get() {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    format!(
                        "service `{}` revision `{}` desired replica count {} must equal admitted manifest count {}",
                        placement.service_name,
                        placement.service_version,
                        placement.desired_replica_count,
                        admitted_bundle.service.replicas.get()
                    ),
                ));
            }
            let inrou = admitted_bundle.container.inrou.as_ref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "admitted Inrou revision is missing its canonical Inrou manifest",
                )
            })?;
            let per_replica_volume_bytes = admitted_bundle
                .service
                .lease_volumes
                .iter()
                .filter(|volume| volume.kind.is_per_replica())
                .try_fold(0_u64, |total, volume| {
                    total.checked_add(volume.max_total_bytes.get())
                })
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "per-replica lease-volume reservation overflows u64",
                    )
                })?;
            let per_replica_storage_bytes = admitted_bundle
                .container
                .resources
                .ephemeral_storage_bytes
                .get()
                .checked_add(per_replica_volume_bytes)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "per-replica storage reservation overflows u64",
                    )
                })?;
            let per_replica_cpu_millis = admitted_bundle
                .container
                .resources
                .checked_inrou_host_cpu_millis()
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "per-replica physical CPU reservation overflows u64",
                    )
                })?;
            let per_replica_memory_bytes = admitted_bundle
                .container
                .resources
                .checked_inrou_host_memory_bytes()
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "per-replica physical memory reservation overflows u64",
                    )
                })?;
            for assignment in &placement.placements {
                if assignment.economic_clock != lease.economic_clock
                    || assignment.lease_started_height != lease.lease_started_height
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        format!(
                            "service `{}` revision `{}` replica {} belongs to another economic lease incarnation",
                            placement.service_name,
                            placement.service_version,
                            assignment.replica_slot
                        ),
                    ));
                }
                if !admitted_bundle
                    .service
                    .placement_targets
                    .iter()
                    .any(|target| {
                        target.validator_account_id == assignment.validator_account_id
                            && target.peer_id == assignment.peer_id
                    })
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "Inrou assignment must match an exact admitted placement target",
                    ));
                }
                let selected_guest_artifact = inrou
                    .guest_images
                    .get(&assignment.selected_guest_isa)
                    .map(|image| &image.published_artifact)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_inrou_service_placements",
                            "Inrou assignment selected guest ISA is absent from its admitted revision",
                        )
                    })?;
                if assignment.host_availability.is_available() {
                    inrou_available_hosts.insert(assignment.validator_account_id.clone());
                    let capability = inrou_host_capabilities
                        .get(&assignment.validator_account_id)
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_inrou_service_placements",
                                "available Inrou assignment is missing its exact authoritative host capability",
                            )
                        })?;
                    if capability.peer_id != assignment.peer_id
                        || !capability
                            .supported_guest_isas
                            .contains(&assignment.selected_guest_isa)
                        || selected_guest_artifact != &capability.trusted_guest_artifact
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_inrou_service_placements",
                            "available Inrou assignment must exactly match its retained capability peer, selected guest ISA, and trusted artifact",
                        ));
                    }
                    if per_replica_cpu_millis > u64::from(capability.max_cpu_millis)
                        || per_replica_memory_bytes > capability.max_memory_bytes
                        || per_replica_storage_bytes > capability.max_storage_bytes
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_inrou_service_placements",
                            "available Inrou assignment's per-replica resources exceed its retained host capability",
                        ));
                    }
                }
                let usage = inrou_reservation_usage
                    .entry(assignment.validator_account_id.clone())
                    .or_insert((0, 0, 0, 0));
                usage.0 = usage.0.checked_add(1).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "aggregate hosted-replica reservation overflows u32",
                    )
                })?;
                usage.1 = usage.1.checked_add(per_replica_cpu_millis).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_inrou_service_placements",
                        "aggregate CPU reservation overflows u64",
                    )
                })?;
                usage.2 = usage
                    .2
                    .checked_add(per_replica_memory_bytes)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_inrou_service_placements",
                            "aggregate memory reservation overflows u64",
                        )
                    })?;
                usage.3 = usage
                    .3
                    .checked_add(per_replica_storage_bytes)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_inrou_service_placements",
                            "aggregate storage reservation overflows u64",
                        )
                    })?;
            }
        }
        for (validator_account_id, (replicas, cpu_millis, memory_bytes, storage_bytes)) in
            inrou_reservation_usage
        {
            if !inrou_available_hosts.contains(&validator_account_id) {
                continue;
            }
            let Some(capability) = inrou_host_capabilities.get(&validator_account_id) else {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "available Inrou reservation aggregate has no retained host capability",
                ));
            };
            if replicas > u32::from(capability.max_hosted_replica_capacity)
                || cpu_millis > u64::from(capability.max_cpu_millis)
                || memory_bytes > capability.max_memory_bytes
                || storage_bytes > capability.max_storage_bytes
            {
                return Err(invalid_soracloud_state(
                    "soracloud_inrou_service_placements",
                    "aggregate Inrou reservations exceed the retained host capability",
                ));
            }
        }

        let mailbox_messages = self.mailbox_messages.view();
        for (key, message) in mailbox_messages.iter() {
            message.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_mailbox_messages", error.to_string())
            })?;
            if key != &message.message_id {
                return Err(invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "storage key must match the embedded message_id",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_mailbox_messages",
                message.enqueue_sequence,
            )?;
            let source_bundle = service_revisions
                .get(&(
                    message.from_service.as_ref().to_owned(),
                    message.from_service_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_mailbox_messages",
                        "source service revision must exist in admitted Soracloud state",
                    )
                })?;
            let source_handler = source_bundle
                .service
                .handlers
                .iter()
                .find(|handler| handler.handler_name == message.from_handler)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_mailbox_messages",
                        "source handler must exist in the bound admitted service revision",
                    )
                })?;
            if source_handler.class
                != iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update
                || source_handler.mailbox.is_none()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "source handler must be an update mailbox handler",
                ));
            }
            let destination_bundle = service_revisions
                .get(&(
                    message.to_service.as_ref().to_owned(),
                    message.to_service_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_mailbox_messages",
                        "destination service revision must exist in admitted Soracloud state",
                    )
                })?;
            let destination_handler = destination_bundle
                .service
                .handlers
                .iter()
                .find(|handler| handler.handler_name == message.to_handler)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_mailbox_messages",
                        "destination handler must exist in the bound admitted service revision",
                    )
                })?;
            let destination_mailbox = destination_handler.mailbox.as_ref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "destination handler must carry an admitted mailbox contract",
                )
            })?;
            if destination_handler.class
                != iroha_data_model::soracloud::SoraServiceHandlerClassV1::Update
            {
                return Err(invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "destination handler must be update",
                ));
            }
            let payload_len = u64::try_from(message.payload_bytes.len()).map_err(|error| {
                invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    format!("payload length does not fit u64: {error}"),
                )
            })?;
            if payload_len > destination_mailbox.max_message_bytes.get() {
                return Err(invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "payload exceeds the bound destination mailbox contract",
                ));
            }
            let retention_blocks = destination_mailbox.retention_blocks.get();
            if message.delivery_delay_blocks >= retention_blocks
                || message.available_after_height
                    != message
                        .enqueue_height
                        .checked_add(u64::from(message.delivery_delay_blocks))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_mailbox_messages",
                                "derived availability height overflows",
                            )
                        })?
                || message.expires_at_height
                    != message
                        .enqueue_height
                        .checked_add(u64::from(retention_blocks))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_mailbox_messages",
                                "derived expiry height overflows",
                            )
                        })?
            {
                return Err(invalid_soracloud_state(
                    "soracloud_mailbox_messages",
                    "ledger schedule must be exactly derived from enqueue, delay, and destination retention",
                ));
            }
        }

        let mut consumed_mailbox_messages = std::collections::BTreeSet::new();
        for (key, receipt) in runtime_receipts.iter() {
            receipt.validate().map_err(|error| {
                invalid_soracloud_state("soracloud_runtime_receipts", error.to_string())
            })?;
            if key != &receipt.receipt_id {
                return Err(invalid_soracloud_state(
                    "soracloud_runtime_receipts",
                    "storage key must match the embedded receipt_id",
                ));
            }
            register_soracloud_sequence(
                &mut authoritative_sequences,
                "soracloud_runtime_receipts",
                receipt.emitted_sequence,
            )?;
            let receipt_bundle = service_revisions
                .get(&(
                    receipt.service_name.as_ref().to_owned(),
                    receipt.service_version.clone(),
                ))
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "receipt service revision must exist in admitted Soracloud state",
                    )
                })?;
            let receipt_handler = receipt_bundle
                .service
                .handlers
                .iter()
                .find(|handler| handler.handler_name == receipt.handler_name)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "receipt handler must exist in the bound admitted service revision",
                    )
                })?;
            if receipt_handler.class != receipt.handler_class
                || receipt_handler.certified_response != receipt.certified_by
            {
                return Err(invalid_soracloud_state(
                    "soracloud_runtime_receipts",
                    "receipt class and certification must match the admitted handler contract",
                ));
            }
            if let Some(message_id) = receipt.mailbox_message_id {
                if receipt.execution_host.is_none() {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "ordered mailbox receipts must carry deterministic-validator attribution",
                    ));
                }
                let message = mailbox_messages.get(&message_id).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "ordered mailbox receipt references no retained source message",
                    )
                })?;
                if message.to_service != receipt.service_name
                    || message.to_service_version != receipt.service_version
                    || message.to_handler != receipt.handler_name
                    || message.payload_commitment != receipt.request_commitment
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "ordered mailbox receipt must exactly bind its source message destination and request commitment",
                    ));
                }
                let expected_receipt_id =
                    crate::soracloud_runtime::ordered_mailbox_runtime_receipt_id(receipt)
                        .expect("mailbox_message_id was proven present");
                if receipt.receipt_id != expected_receipt_id {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "ordered mailbox receipt_id must equal its canonical sequence-independent receipt ID",
                    ));
                }
                if !consumed_mailbox_messages.insert(message_id) {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "one mailbox message must not be consumed by multiple receipts",
                    ));
                }
            } else {
                if receipt.execution_host.is_some() {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "deterministic-validator attribution requires an authoritative mailbox message",
                    ));
                }
                let expected_receipt_id =
                    iroha_data_model::soracloud::derive_soracloud_local_read_receipt_id_v1(receipt);
                if receipt.receipt_id != expected_receipt_id {
                    return Err(invalid_soracloud_state(
                        "soracloud_runtime_receipts",
                        "local-read receipt_id must equal its canonical sequence-independent local-read receipt ID",
                    ));
                }
            }
        }

        if authoritative_sequences.contains(&0) {
            return Err(invalid_soracloud_state(
                "soracloud_authoritative_sequences",
                "retained Soracloud sequences must be greater than zero",
            ));
        }
        if let Some(max_retained_sequence) = authoritative_sequences.last().copied()
            && max_retained_sequence > self.sequence_watermark
        {
            return Err(invalid_soracloud_state(
                "soracloud_sequence_watermark",
                format!(
                    "watermark {} is below retained authoritative sequence {max_retained_sequence}",
                    self.sequence_watermark
                ),
            ));
        }
        Ok(())
    }
}

/// Validate each retained service lifecycle using the caller-held authoritative views.
#[allow(
    clippy::too_many_lines,
    reason = "moved original first-release restore validation remains an ordered fail-closed boundary over the caller-held views"
)]
#[inline(never)]
fn validate_soracloud_service_deployment_history(
    service_revisions: &StorageView<'_, (String, String), SoraDeploymentBundleV1>,
    service_deployments: &StorageView<'_, Name, SoraServiceDeploymentStateV1>,
    service_audit_events: &StorageView<'_, u64, SoraServiceAuditEventV1>,
) -> Result<(), json::Error> {
    use iroha_data_model::soracloud::{
        SoraRolloutStageV1, SoraServiceConfigMutationV1,
        SoraServiceLifecycleActionV1 as ServiceAction, SoraServiceSecretMutationV1,
        SoracloudFhePolicyVersionLifecycleV1,
    };
    for (service_name, deployment) in service_deployments.iter() {
        let history = service_audit_events
            .iter()
            .filter_map(|(_sequence, event)| (&event.service_name == service_name).then_some(event))
            .collect::<Vec<_>>();
        let Some(first_event) = history.first().copied() else {
            return Err(invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!("service `{service_name}` has no authoritative lifecycle history"),
            ));
        };
        if first_event.action != ServiceAction::Deploy {
            return Err(invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!("service `{service_name}` lifecycle history must begin with Deploy"),
            ));
        }

        let mut active_version: Option<String> = None;
        let mut process_generation = 0_u64;
        let mut config_generation = 0_u64;
        let mut secret_generation = 0_u64;
        let mut folded_configs = std::collections::BTreeMap::new();
        let mut folded_secrets = std::collections::BTreeMap::new();
        let mut process_started_sequence = 0_u64;
        let mut admitted_versions = std::collections::BTreeSet::new();
        let mut folded_rollout = None;
        let mut folded_service_lease = None;

        for event in &history {
            let process_changed = matches!(
                event.action,
                ServiceAction::Deploy | ServiceAction::Upgrade | ServiceAction::Rollback
            );
            let expected_process_generation = if process_changed {
                process_generation.checked_add(1).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!("service `{service_name}` process generation overflows u64"),
                    )
                })?
            } else {
                process_generation
            };
            if event.process_generation != expected_process_generation {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` event {} has process_generation {}, expected {expected_process_generation}",
                        event.sequence, event.process_generation
                    ),
                ));
            }

            let config_changed = !event.config_mutations.is_empty();
            let expected_config_generation = if config_changed {
                config_generation.checked_add(1).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!("service `{service_name}` config generation overflows u64"),
                    )
                })?
            } else {
                config_generation
            };
            if event.config_generation != expected_config_generation {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` event {} config generation must advance exactly when a committed config delta is present",
                        event.sequence
                    ),
                ));
            }
            for mutation in &event.config_mutations {
                match mutation {
                    SoraServiceConfigMutationV1::Upsert(entry) => {
                        folded_configs.insert(entry.config_name.clone(), entry.clone());
                    }
                    SoraServiceConfigMutationV1::Delete(config_name) => {
                        if folded_configs.remove(config_name).is_none() {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                format!(
                                    "service `{service_name}` event {} deletes absent config `{config_name}`",
                                    event.sequence
                                ),
                            ));
                        }
                    }
                }
            }
            if iroha_data_model::soracloud::derive_soracloud_service_config_snapshot_hash_v1(
                &folded_configs,
            ) != event.config_snapshot_hash
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` event {} config snapshot hash does not match replayed committed deltas",
                        event.sequence
                    ),
                ));
            }

            let secret_changed = !event.secret_mutations.is_empty();
            let expected_secret_generation = if secret_changed {
                secret_generation.checked_add(1).ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!("service `{service_name}` secret generation overflows u64"),
                    )
                })?
            } else {
                secret_generation
            };
            if event.secret_generation != expected_secret_generation {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` event {} secret generation must advance exactly when a committed secret delta is present",
                        event.sequence
                    ),
                ));
            }
            for mutation in &event.secret_mutations {
                match mutation {
                    SoraServiceSecretMutationV1::Upsert(entry) => {
                        folded_secrets.insert(entry.secret_name.clone(), entry.clone());
                    }
                    SoraServiceSecretMutationV1::Delete(secret_name) => {
                        if folded_secrets.remove(secret_name).is_none() {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                format!(
                                    "service `{service_name}` event {} deletes absent secret `{secret_name}`",
                                    event.sequence
                                ),
                            ));
                        }
                    }
                }
            }
            if iroha_data_model::soracloud::derive_soracloud_service_secret_snapshot_hash_v1(
                &folded_secrets,
            ) != event.secret_snapshot_hash
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` event {} secret snapshot hash does not match replayed committed deltas",
                        event.sequence
                    ),
                ));
            }

            match event.action {
                ServiceAction::Deploy => {
                    if active_version.is_some() || event.sequence != first_event.sequence {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` must contain exactly one initial Deploy event"
                            ),
                        ));
                    }
                }
                ServiceAction::Upgrade | ServiceAction::Rollback => {
                    if event.from_version.as_ref() != active_version.as_ref() {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` event {} does not continue the exact active-version history",
                                event.sequence
                            ),
                        ));
                    }
                }
                _ => {
                    if active_version.as_deref() != Some(event.to_version.as_str()) {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` event {} does not bind the active revision at that sequence",
                                event.sequence
                            ),
                        ));
                    }
                }
            }

            match event.action {
                ServiceAction::Deploy | ServiceAction::Upgrade => {
                    if !admitted_versions.insert(event.to_version.clone()) {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` revision `{}` has more than one admission event",
                                event.to_version
                            ),
                        ));
                    }
                    active_version = Some(event.to_version.clone());
                    folded_rollout = event.rollout_state.clone();
                    if event.action == ServiceAction::Upgrade {
                        let rollout = folded_rollout.as_ref().expect(
                            "Upgrade action field validation requires an exact rollout state",
                        );
                        let candidate_bundle = service_revisions
                            .get(&(
                                service_name.as_ref().to_owned(),
                                rollout.candidate_version.clone(),
                            ))
                            .expect("event target revision was validated above");
                        let policy = &candidate_bundle.service.rollout;
                        let expected_traffic = if policy.canary_percent == 0 {
                            100
                        } else {
                            policy.canary_percent
                        };
                        if rollout.canary_percent != policy.canary_percent
                            || rollout.traffic_percent != expected_traffic
                            || rollout.health_failures != 0
                            || rollout.max_health_failures
                                != policy.automatic_rollback_failures.get()
                            || rollout.health_window_secs != policy.health_window_secs.get()
                        {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "upgrade audit rollout state must exactly match its admitted candidate policy",
                            ));
                        }
                    }
                }
                ServiceAction::Rollout => {
                    let previous = folded_rollout.as_ref().ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "rollout progress has no preceding candidate rollout",
                        )
                    })?;
                    let next = event
                        .rollout_state
                        .as_ref()
                        .expect("Rollout action field validation requires an exact rollout state");
                    if previous.stage != SoraRolloutStageV1::Canary
                        || previous.rollout_handle != next.rollout_handle
                        || previous.baseline_version != next.baseline_version
                        || previous.candidate_version != next.candidate_version
                        || previous.canary_percent != next.canary_percent
                        || previous.max_health_failures != next.max_health_failures
                        || previous.health_window_secs != next.health_window_secs
                        || previous.created_sequence != next.created_sequence
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "rollout progress must continue the exact immutable candidate rollout",
                        ));
                    }
                    let healthy_transition = next.traffic_percent >= previous.traffic_percent
                        && next.health_failures == 0;
                    let unhealthy_transition = next.traffic_percent == previous.traffic_percent
                        && next.health_failures == previous.health_failures.saturating_add(1)
                        && next.stage == SoraRolloutStageV1::Canary
                        && next.health_failures < next.max_health_failures;
                    if !healthy_transition && !unhealthy_transition {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "rollout progress does not describe one canonical healthy or unhealthy step",
                        ));
                    }
                    folded_rollout = Some(next.clone());
                }
                ServiceAction::Rollback => {
                    if let Some(next) = event.rollout_state.as_ref() {
                        let previous = folded_rollout.as_ref().ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "automatic rollback has no preceding candidate rollout",
                            )
                        })?;
                        if previous.stage != SoraRolloutStageV1::Canary
                            || previous.rollout_handle != next.rollout_handle
                            || previous.baseline_version != next.baseline_version
                            || previous.candidate_version != next.candidate_version
                            || previous.canary_percent != next.canary_percent
                            || previous.max_health_failures != next.max_health_failures
                            || previous.health_window_secs != next.health_window_secs
                            || previous.created_sequence != next.created_sequence
                            || next.traffic_percent != 0
                            || next.health_failures != previous.health_failures.saturating_add(1)
                            || next.health_failures < next.max_health_failures
                        {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "automatic rollback must be the exact threshold-crossing rollout transition",
                            ));
                        }
                        folded_rollout = Some(next.clone());
                    } else {
                        folded_rollout = None;
                    }
                    active_version = Some(event.to_version.clone());
                }
                _ => {}
            }

            match event.action {
                ServiceAction::Deploy | ServiceAction::Upgrade => {
                    let event_bundle = service_revisions
                        .get(&(service_name.as_ref().to_owned(), event.to_version.clone()))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "lease admission target has no retained bundle",
                            )
                        })?;
                    let mut prior_deployment = deployment.clone();
                    prior_deployment.service_lease = folded_service_lease.clone();
                    let existing =
                        (event.action == ServiceAction::Upgrade).then_some(&prior_deployment);
                    let expected = crate::smartcontracts::isi::soracloud::build_http_service_lease_state(
                        event_bundle,
                        existing,
                        event.block_height,
                        event.action == ServiceAction::Upgrade,
                    )
                    .map_err(|error| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` lease admission transition is invalid: {error}"
                            ),
                        )
                    })?;
                    let expected_commitment = expected.as_ref().map(
                        iroha_data_model::soracloud::derive_soracloud_service_lease_commitment_v1,
                    );
                    if event.service_lease_commitment != expected_commitment {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` event {} must retain the exact writer-derived post-admission lease economics",
                                event.sequence
                            ),
                        ));
                    }
                    folded_service_lease = expected;
                }
                ServiceAction::Rollback if event.rollout_state.is_none() => {
                    let event_bundle = service_revisions
                        .get(&(service_name.as_ref().to_owned(), event.to_version.clone()))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "explicit rollback target has no retained bundle",
                            )
                        })?;
                    let mut prior_deployment = deployment.clone();
                    prior_deployment.service_lease = folded_service_lease.clone();
                    let expected = crate::smartcontracts::isi::soracloud::build_http_service_lease_state(
                        event_bundle,
                        Some(&prior_deployment),
                        event.block_height,
                        false,
                    )
                    .map_err(|error| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` rollback lease transition is invalid: {error}"
                            ),
                        )
                    })?;
                    let expected_commitment = expected.as_ref().map(
                        iroha_data_model::soracloud::derive_soracloud_service_lease_commitment_v1,
                    );
                    if event.service_lease_commitment != expected_commitment {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` explicit rollback must retain exact writer-derived lease economics"
                            ),
                        ));
                    }
                    folded_service_lease = expected;
                }
                ServiceAction::LeaseUsage | ServiceAction::LeaseReportingEpochRollover => {
                    let prior = folded_service_lease.as_ref().ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` lease usage has no replayed hosted-service lease"
                            ),
                        )
                    })?;
                    let usage = event.lease_usage.as_ref().ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "lease accounting event is missing its validated usage input",
                        )
                    })?;
                    let assignment_bundle = service_revisions
                        .get(&(
                            service_name.as_ref().to_owned(),
                            usage.assignment.service_version.clone(),
                        ))
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                "lease reporter assignment references no retained revision",
                            )
                        })?;
                    if !lease_usage_assignment_version_is_writer_reachable(
                        &usage.assignment.service_version,
                        usage.finalize_reporter,
                        &event.to_version,
                        folded_rollout.as_ref(),
                    ) || assignment_bundle.service.execution_plane
                        != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
                        || assignment_bundle.container.runtime
                            != iroha_data_model::soracloud::SoraContainerRuntimeV1::Inrou
                        || usage.assignment.placement.replica_slot
                            > assignment_bundle.service.replicas.get()
                        || usage.assignment.placement_reconciled_at_ms > event.block_timestamp_ms
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "lease reporter assignment was not writer-reachable for the retained Inrou revision and event transition",
                        ));
                    }
                    let expected = replay_soracloud_service_lease_usage(
                        prior,
                        usage,
                        event.lease_reporting_epoch_rollover.as_ref(),
                        event.block_height,
                        deployment.accounted_storage_bytes().map_err(|error| {
                            invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                format!(
                                    "service `{service_name}` accounted storage is invalid: {error}"
                                ),
                            )
                        })?,
                    )
                    .map_err(|message| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` lease usage event {} is not live-replayable: {message}",
                                event.sequence
                            ),
                        )
                    })?;
                    let expected_commitment =
                        iroha_data_model::soracloud::derive_soracloud_service_lease_commitment_v1(
                            &expected,
                        );
                    if event.service_lease_commitment != Some(expected_commitment) {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` lease usage event {} must commit its exact replayed post-state",
                                event.sequence
                            ),
                        ));
                    }
                    folded_service_lease = Some(expected);
                }
                _ => {
                    if event.service_lease_commitment.is_some() {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            "non-lease transition must not replace hosted-service lease state",
                        ));
                    }
                }
            }

            if matches!(
                event.action,
                ServiceAction::StateMutation | ServiceAction::FheJobRun
            ) {
                let event_bundle = service_revisions
                    .get(&(service_name.as_ref().to_owned(), event.to_version.clone()))
                    .expect("event target revision was validated above");
                let binding_name = event
                    .binding_name
                    .as_ref()
                    .expect("state-producing action field validation requires binding_name");
                let state_key = event
                    .state_key
                    .as_deref()
                    .expect("state-producing action field validation requires state_key");
                let binding = event_bundle
                    .service
                    .state_bindings
                    .iter()
                    .find(|binding| &binding.binding_name == binding_name)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` state-producing event {} references an undeclared binding",
                                event.sequence
                            ),
                        )
                    })?;
                if !state_key.starts_with(&binding.key_prefix)
                    || (event.action == ServiceAction::FheJobRun
                        && binding.encryption
                            != iroha_data_model::soracloud::SoraStateEncryptionV1::FheCiphertext)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!(
                            "service `{service_name}` state-producing event {} does not satisfy its exact retained binding",
                            event.sequence
                        ),
                    ));
                }
                if event.action == ServiceAction::FheJobRun {
                    let policy_name = event
                        .policy_name
                        .as_ref()
                        .expect("FHE job action field validation requires an exact policy name");
                    let policy_digest = event
                        .policy_snapshot_hash
                        .expect("FHE job action field validation requires an exact policy digest");
                    let exact_policy_exists = deployment
                        .fhe_policy_records
                        .get(policy_name)
                        .is_some_and(|record| {
                            record
                                .versions
                                .values()
                                .any(|version| version.material.material_digest == policy_digest)
                        });
                    if !exact_policy_exists {
                        return Err(invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` FHE job event {} references no retained governed policy material",
                                event.sequence
                            ),
                        ));
                    }
                }
            }

            if process_changed {
                process_started_sequence = event.sequence;
            }
            process_generation = event.process_generation;
            config_generation = event.config_generation;
            secret_generation = event.secret_generation;
        }

        let exact_revision_count = usize::try_from(deployment.revision_count).map_err(|error| {
            invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!("service `{service_name}` revision count does not fit usize: {error}"),
            )
        })?;
        if admitted_versions.len() != exact_revision_count
            || service_revisions.iter().any(|((name, version), _bundle)| {
                name.as_str() == service_name.as_ref() && !admitted_versions.contains(version)
            })
            || active_version.as_deref() != Some(deployment.current_service_version.as_str())
            || process_generation != deployment.process_generation
            || process_started_sequence != deployment.process_started_sequence
            || config_generation != deployment.config_generation
            || secret_generation != deployment.secret_generation
            || folded_configs != deployment.service_configs
            || folded_secrets != deployment.service_secrets
            || folded_service_lease != deployment.service_lease
            || folded_rollout.as_ref() != deployment.last_rollout.as_ref()
        {
            return Err(invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!(
                    "service `{service_name}` lifecycle history must exactly reconstruct its revisions, active process, material generations, and rollout head"
                ),
            ));
        }

        let mut expected_fhe_event_sequences = std::collections::BTreeSet::new();
        for (policy_name, policy) in &deployment.fhe_policy_records {
            let versions = policy.versions.iter().collect::<Vec<_>>();
            let mut previous_admission_sequence = 0_u64;
            for (index, (_version, state)) in versions.iter().enumerate() {
                let expected_action = if index == 0 {
                    ServiceAction::FhePolicyRegister
                } else {
                    ServiceAction::FhePolicyRotate
                };
                let matches = history
                    .iter()
                    .filter(|event| {
                        event.action == expected_action
                            && event.policy_name.as_ref() == Some(policy_name)
                            && event.policy_snapshot_hash == Some(state.material.material_digest)
                            && event.governance_tx_hash == Some(state.admitted_by_transaction_hash)
                    })
                    .copied()
                    .collect::<Vec<_>>();
                if matches.len() != 1 || matches[0].sequence <= previous_admission_sequence {
                    return Err(invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!(
                            "service `{service_name}` FHE policy `{policy_name}` version {} must have one ordered exact admission event",
                            state.material.version
                        ),
                    ));
                }
                let admission_event = matches[0];
                expected_fhe_event_sequences.insert(admission_event.sequence);
                previous_admission_sequence = admission_event.sequence;
                match state.lifecycle {
                    SoracloudFhePolicyVersionLifecycleV1::Superseded => {
                        let Some((_next_version, next_state)) = versions.get(index + 1) else {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_deployments",
                                "superseded FHE policy version has no successor",
                            ));
                        };
                        if state.deactivated_by_transaction_hash
                            != Some(next_state.admitted_by_transaction_hash)
                        {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_deployments",
                                "superseded FHE policy version must be deactivated by its exact successor admission",
                            ));
                        }
                    }
                    SoracloudFhePolicyVersionLifecycleV1::Revoked => {
                        let deactivation_hash = state
                            .deactivated_by_transaction_hash
                            .expect("revoked FHE policy validation requires deactivation hash");
                        let revoke_matches = history
                            .iter()
                            .filter(|event| {
                                event.action == ServiceAction::FhePolicyRevoke
                                    && event.sequence > admission_event.sequence
                                    && event.policy_name.as_ref() == Some(policy_name)
                                    && event.policy_snapshot_hash
                                        == Some(state.material.material_digest)
                                    && event.governance_tx_hash == Some(deactivation_hash)
                            })
                            .copied()
                            .collect::<Vec<_>>();
                        if revoke_matches.len() != 1 {
                            return Err(invalid_soracloud_state(
                                "soracloud_service_audit_events",
                                format!(
                                    "service `{service_name}` revoked FHE policy `{policy_name}` must have one exact revocation event"
                                ),
                            ));
                        }
                        expected_fhe_event_sequences.insert(revoke_matches[0].sequence);
                    }
                    SoracloudFhePolicyVersionLifecycleV1::Active => {}
                }
            }
        }
        if history.iter().any(|event| {
            matches!(
                event.action,
                ServiceAction::FhePolicyRegister
                    | ServiceAction::FhePolicyRotate
                    | ServiceAction::FhePolicyRevoke
            ) && !expected_fhe_event_sequences.contains(&event.sequence)
        }) {
            return Err(invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!("service `{service_name}` has an orphaned FHE policy lifecycle event"),
            ));
        }
        for job_event in history
            .iter()
            .filter(|event| event.action == ServiceAction::FheJobRun)
        {
            let policy_name = job_event
                .policy_name
                .as_ref()
                .expect("FHE job field validation requires policy_name");
            let policy_digest = job_event
                .policy_snapshot_hash
                .expect("FHE job field validation requires policy_snapshot_hash");
            let policy = deployment
                .fhe_policy_records
                .get(policy_name)
                .expect("earlier FHE job validation resolved the policy record");
            let version_state = policy
                .versions
                .values()
                .find(|state| state.material.material_digest == policy_digest)
                .expect("earlier FHE job validation resolved the policy material");
            let admission_action = if version_state.material.version.get() == 1 {
                ServiceAction::FhePolicyRegister
            } else {
                ServiceAction::FhePolicyRotate
            };
            let admission_sequence = history
                .iter()
                .find(|event| {
                    event.action == admission_action
                        && event.policy_name.as_ref() == Some(policy_name)
                        && event.policy_snapshot_hash == Some(policy_digest)
                        && event.governance_tx_hash
                            == Some(version_state.admitted_by_transaction_hash)
                })
                .map(|event| event.sequence)
                .expect("FHE lifecycle reverse closure resolved the admission event");
            let deactivation_sequence =
                version_state
                    .deactivated_by_transaction_hash
                    .map(|deactivation_hash| {
                        history
                            .iter()
                            .find(|event| {
                                matches!(
                                    event.action,
                                    ServiceAction::FhePolicyRotate | ServiceAction::FhePolicyRevoke
                                ) && event.policy_name.as_ref() == Some(policy_name)
                                    && event.governance_tx_hash == Some(deactivation_hash)
                            })
                            .map(|event| event.sequence)
                            .expect("FHE lifecycle reverse closure resolved the deactivation event")
                    });
            if admission_sequence >= job_event.sequence
                || deactivation_sequence.is_some_and(|sequence| job_event.sequence >= sequence)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` FHE job event {} must bind policy material active at that exact sequence",
                        job_event.sequence
                    ),
                ));
            }
        }

        let rollover_events = history
            .iter()
            .filter(|event| event.action == ServiceAction::LeaseReportingEpochRollover)
            .copied()
            .collect::<Vec<_>>();
        if let Some(lease) = deployment.service_lease.as_ref() {
            if lease.lease_started_height != first_event.block_height {
                return Err(invalid_soracloud_state(
                    "soracloud_service_deployments",
                    format!(
                        "service `{service_name}` hosted-service lease incarnation must begin at its sole Deploy event"
                    ),
                ));
            }
            let mut reporting_epoch = 1_u64;
            let mut settled_egress_bytes = 0_u128;
            for event in &rollover_events {
                let rollover = event.lease_reporting_epoch_rollover.as_ref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!(
                            "service `{service_name}` reporting-epoch rollover event {} is missing its validated payload",
                            event.sequence
                        ),
                    )
                })?;
                if !lease_rollover_extends_settlement_chain(
                    rollover,
                    lease.lease_started_height,
                    reporting_epoch,
                    settled_egress_bytes,
                ) {
                    return Err(invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!(
                            "service `{service_name}` reporting-epoch rollover history is not one exact settlement chain"
                        ),
                    ));
                }
                reporting_epoch = rollover.new_reporting_epoch;
                settled_egress_bytes = rollover.settled_egress_bytes;
            }
            if let Some(latest_event) = rollover_events.last() {
                let latest_rollover = latest_event
                    .lease_reporting_epoch_rollover
                    .as_ref()
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_service_audit_events",
                            format!(
                                "service `{service_name}` latest reporting-epoch rollover event is missing its validated payload"
                            ),
                        )
                    })?;
                let retains_exact_opener =
                    lease.egress_reporter_checkpoints.iter().any(|checkpoint| {
                        checkpoint.reporting_epoch == latest_rollover.new_reporting_epoch
                            && checkpoint.assignment.service_version
                                == latest_rollover.active_service_version
                            && checkpoint.assignment.placement.replica_slot
                                == latest_rollover.replica_slot
                            && checkpoint.assignment.placement.placement_incarnation
                                == latest_rollover.placement_incarnation
                            && checkpoint.assignment.placement.validator_account_id
                                == latest_rollover.reporter_account_id
                    });
                if !retains_exact_opener {
                    return Err(invalid_soracloud_state(
                        "soracloud_service_audit_events",
                        format!(
                            "service `{service_name}` current reporting epoch must retain the exact reporter checkpoint opened by its latest rollover"
                        ),
                    ));
                }
            }
            if reporting_epoch != lease.reporting_epoch
                || settled_egress_bytes != lease.settled_egress_bytes
            {
                return Err(invalid_soracloud_state(
                    "soracloud_service_audit_events",
                    format!(
                        "service `{service_name}` reporting-epoch audit history must exactly reconstruct lease settlement state"
                    ),
                ));
            }
        } else if !rollover_events.is_empty() {
            return Err(invalid_soracloud_state(
                "soracloud_service_audit_events",
                format!(
                    "service `{service_name}` has lease rollover events without a hosted-service lease"
                ),
            ));
        }
    }
    Ok(())
}

/// Validate apartment records without reacquiring their authoritative audit view.
#[allow(
    clippy::too_many_lines,
    reason = "moved original first-release restore validation remains an ordered fail-closed boundary over the caller-held views"
)]
#[inline(never)]
fn validate_soracloud_agent_apartment_records(
    agent_apartments: &StorageView<'_, String, SoraAgentApartmentRecordV1>,
    agent_apartment_audit_events: &StorageView<'_, u64, SoraAgentApartmentAuditEventV1>,
) -> Result<(), json::Error> {
    for (key, apartment) in agent_apartments.iter() {
        apartment.validate().map_err(|error| {
            invalid_soracloud_state("soracloud_agent_apartments", error.to_string())
        })?;
        if key.as_str() != apartment.manifest.apartment_name.as_ref() {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "storage key must match the embedded apartment_name",
            ));
        }
        let accounted_bytes = apartment
            .persistent_state
            .key_sizes
            .values()
            .try_fold(0_u64, |total, bytes| total.checked_add(*bytes))
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "persistent-state byte accounting overflows u64",
                )
            })?;
        if accounted_bytes != apartment.persistent_state.total_bytes
            || accounted_bytes > apartment.manifest.state_quota_bytes.get()
        {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "persistent-state total_bytes must equal exact key-size accounting within the manifest quota",
            ));
        }
        let deployed_event = agent_apartment_audit_events
            .get(&apartment.deployed_sequence)
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "agent apartment is missing its exact deployment audit event",
                )
            })?;
        if deployed_event.action != iroha_data_model::soracloud::SoraAgentApartmentActionV1::Deploy
            || deployed_event.apartment_name != apartment.manifest.apartment_name
            || deployed_event.manifest_hash != apartment.manifest_hash
            || deployed_event.restart_count != 0
            || apartment.lease_started_height != deployed_event.block_height
        {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "agent apartment deployment projection is inconsistent",
            ));
        }
        let renewed_event = agent_apartment_audit_events
            .iter()
            .filter_map(|(_sequence, event)| {
                (event.apartment_name == apartment.manifest.apartment_name
                    && event.block_height == apartment.last_renewed_height
                    && matches!(
                        event.action,
                        iroha_data_model::soracloud::SoraAgentApartmentActionV1::Deploy
                            | iroha_data_model::soracloud::SoraAgentApartmentActionV1::LeaseRenew
                    ))
                .then_some(event)
            })
            .last()
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "agent apartment is missing its exact last-renewed audit event",
                )
            })?;
        let expected_renew_action = if renewed_event.sequence == apartment.deployed_sequence {
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::Deploy
        } else {
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::LeaseRenew
        };
        if renewed_event.action != expected_renew_action
            || renewed_event.apartment_name != apartment.manifest.apartment_name
            || renewed_event.lease_expires_height != apartment.lease_expires_height
            || renewed_event.manifest_hash != apartment.manifest_hash
        {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "agent apartment must exactly match its last-renewed audit projection",
            ));
        }
        let expected_process_generation = u64::from(apartment.restart_count)
            .checked_add(1)
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "agent process generation overflows u64",
                )
            })?;
        if apartment.process_generation != expected_process_generation {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "process_generation must equal restart_count + 1",
            ));
        }
        if apartment.restart_count == 0 {
            if apartment.last_restart_sequence.is_some()
                || apartment.last_restart_reason.is_some()
                || apartment.process_started_sequence != apartment.deployed_sequence
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "never-restarted apartment must retain its deployment process generation",
                ));
            }
        } else {
            let restart_sequence = apartment.last_restart_sequence.ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "restarted apartment is missing last_restart_sequence",
                )
            })?;
            let restart_event = agent_apartment_audit_events
                .get(&restart_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "restarted apartment is missing its exact restart audit event",
                    )
                })?;
            if restart_event.action
                != iroha_data_model::soracloud::SoraAgentApartmentActionV1::Restart
                || restart_event.apartment_name != apartment.manifest.apartment_name
                || restart_event.restart_count != apartment.restart_count
                || restart_event.reason.as_deref() != apartment.last_restart_reason.as_deref()
                || apartment.process_started_sequence != restart_sequence
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "agent apartment restart projection is inconsistent",
                ));
            }
        }
        let latest_direct_event = agent_apartment_audit_events
            .iter()
            .filter_map(|(sequence, event)| {
                (event.apartment_name == apartment.manifest.apartment_name)
                    .then_some((*sequence, event))
            })
            .max_by_key(|(sequence, _event)| *sequence)
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "agent apartment has no authoritative audit history",
                )
            })?;
        if latest_direct_event.1.lease_expires_height != apartment.lease_expires_height
            || latest_direct_event.1.manifest_hash != apartment.manifest_hash
            || latest_direct_event.1.restart_count != apartment.restart_count
        {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "agent apartment must match its latest direct audit projection",
            ));
        }
        let latest_activity_sequence = agent_apartment_audit_events
            .iter()
            .filter_map(|(sequence, event)| {
                let direct = event.apartment_name == apartment.manifest.apartment_name;
                let sender_enqueue = event.action
                    == iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageEnqueued
                    && event.from_apartment.as_deref() == Some(key.as_str());
                (direct || sender_enqueue).then_some(*sequence)
            })
            .max();
        if latest_activity_sequence != Some(apartment.last_active_sequence) {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "last_active_sequence must equal the latest audit event that mutated the apartment",
            ));
        }
        let run_count = u32::try_from(apartment.autonomy_run_history.len()).map_err(|error| {
            invalid_soracloud_state(
                "soracloud_agent_apartments",
                format!("autonomy run count does not fit u32: {error}"),
            )
        })?;
        let mut spent_budget = 0_u64;
        let mut last_checkpoint_sequence = None;
        for run in &apartment.autonomy_run_history {
            spent_budget = spent_budget.checked_add(run.budget_units).ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "autonomy run budget accounting overflows u64",
                )
            })?;
            last_checkpoint_sequence = Some(
                last_checkpoint_sequence.map_or(run.approved_sequence, |current: u64| {
                    current.max(run.approved_sequence)
                }),
            );
            let expected_run_id = format!("{key}:autonomy:{}", run.approved_sequence);
            let expected_commitment =
                iroha_data_model::soracloud::derive_agent_autonomy_request_commitment(
                    key,
                    &run.artifact_hash,
                    run.provenance_hash.as_deref(),
                    run.budget_units,
                    &run.run_id,
                    &run.run_label,
                    run.workflow_input_json.as_deref(),
                    run.approved_process_generation,
                );
            let event = agent_apartment_audit_events
                .get(&run.approved_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "autonomy run is missing its exact approval audit event",
                    )
                })?;
            let expected_payload_hash = run
                .workflow_input_json
                .as_ref()
                .map(|payload| Hash::new(payload.as_bytes()));
            let expected_checkpoint_key =
                crate::smartcontracts::isi::soracloud::autonomy_checkpoint_key(key, &run.run_id);
            let expected_checkpoint_size =
                crate::smartcontracts::isi::soracloud::autonomy_checkpoint_value_size(
                    &run.artifact_hash,
                    run.provenance_hash.as_deref(),
                    &run.run_label,
                    run.budget_units,
                    run.workflow_input_json.as_deref(),
                );
            if run.run_id != expected_run_id
                || run.request_commitment != expected_commitment
                || run.approved_process_generation > apartment.process_generation
                || event.action
                    != iroha_data_model::soracloud::SoraAgentApartmentActionV1::AutonomyRunApproved
                || event.apartment_name != apartment.manifest.apartment_name
                || event.request_id.as_deref() != Some(run.run_id.as_str())
                || event.run_id.as_deref() != Some(run.run_id.as_str())
                || event.artifact_hash.as_deref() != Some(run.artifact_hash.as_str())
                || event.provenance_hash.as_deref() != run.provenance_hash.as_deref()
                || event.run_label.as_deref() != Some(run.run_label.as_str())
                || event.budget_units != Some(run.budget_units)
                || event.payload_hash != expected_payload_hash
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "autonomy run must exactly match its canonical identity, commitment, and approval event",
                ));
            }
            if apartment
                .persistent_state
                .key_sizes
                .get(&expected_checkpoint_key)
                != Some(&expected_checkpoint_size)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "autonomy run must retain its exact writer-derived checkpoint key and byte size",
                ));
            }
        }
        if apartment.persistent_state.key_sizes.len() != apartment.autonomy_run_history.len()
            || apartment.checkpoint_count != run_count
            || apartment.last_checkpoint_sequence != last_checkpoint_sequence
            || apartment
                .autonomy_budget_remaining_units
                .checked_add(spent_budget)
                != Some(apartment.autonomy_budget_ceiling_units)
        {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "autonomy history must exactly match checkpoint keys, byte accounting, and budget projections",
            ));
        }
        for request in apartment.pending_wallet_requests.values() {
            let event = agent_apartment_audit_events
                .get(&request.created_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "pending wallet request is missing its creation audit event",
                    )
                })?;
            if event.action
                != iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendRequested
                || event.apartment_name != apartment.manifest.apartment_name
                || event.request_id.as_deref() != Some(request.request_id.as_str())
                || event.asset_definition.as_deref() != Some(request.asset_definition.as_str())
                || event.amount.as_ref() != Some(&request.amount)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "pending wallet request must exactly match its creation audit event",
                ));
            }
        }
        let mut approved_wallet_request_ids = std::collections::BTreeSet::new();
        let mut projected_wallet_daily_spend = BTreeMap::<String, (String, u64, Quantity)>::new();
        for (_sequence, event) in agent_apartment_audit_events.iter().filter(
            |(_sequence, event)| {
                event.apartment_name == apartment.manifest.apartment_name
                    && event.action
                        == iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendApproved
            },
        ) {
            let request_id = event.request_id.as_deref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "wallet-spend approval is missing request_id",
                )
            })?;
            if !approved_wallet_request_ids.insert(request_id.to_owned()) {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "wallet request_id must not be approved more than once",
                ));
            }
            let asset_definition = event.asset_definition.as_deref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "wallet-spend approval is missing asset_definition",
                )
            })?;
            let amount = event.amount.as_ref().ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "wallet-spend approval is missing amount",
                )
            })?;
            let day_bucket = crate::smartcontracts::isi::soracloud::wallet_day_bucket(
                event.block_timestamp_ms,
            );
            let aggregate_key = format!("{asset_definition}:{day_bucket}");
            if let Some((_asset, _day, spent)) =
                projected_wallet_daily_spend.get_mut(&aggregate_key)
            {
                *spent = spent.checked_add(amount).map_err(|error| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        format!("wallet daily-spend projection overflows: {error}"),
                    )
                })?;
            } else {
                projected_wallet_daily_spend.insert(
                    aggregate_key,
                    (asset_definition.to_owned(), day_bucket, amount.clone()),
                );
            }
        }
        if apartment.wallet_daily_spend.len() != projected_wallet_daily_spend.len() {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartments",
                "wallet_daily_spend must equal the complete approved-event projection",
            ));
        }
        for (aggregate_key, (asset_definition, day_bucket, spent)) in projected_wallet_daily_spend {
            let entry = apartment
                .wallet_daily_spend
                .get(&aggregate_key)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "wallet_daily_spend is missing an approved-event aggregate",
                    )
                })?;
            if entry.asset_definition != asset_definition
                || entry.day_bucket != day_bucket
                || entry.spent != spent
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "wallet_daily_spend entry does not equal its approved-event aggregate",
                ));
            }
        }
        for message in &apartment.mailbox_queue {
            let event = agent_apartment_audit_events
                .get(&message.enqueued_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "queued apartment message is missing its enqueue audit event",
                    )
                })?;
            if event.action
                != iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageEnqueued
                || event.apartment_name != apartment.manifest.apartment_name
                || event.request_id.as_deref() != Some(message.message_id.as_str())
                || event.from_apartment.as_deref() != Some(message.from_apartment.as_str())
                || event.to_apartment.as_deref() != Some(key.as_str())
                || event.channel.as_deref() != Some(message.channel.as_str())
                || event.payload_hash != Some(message.payload_hash)
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "queued apartment message must exactly match its enqueue audit event",
                ));
            }
        }
        for rule in apartment.artifact_allowlist.values() {
            let event = agent_apartment_audit_events
                .get(&rule.added_sequence)
                .ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartments",
                        "artifact allowlist rule is missing its audit event",
                    )
                })?;
            if event.action
                != iroha_data_model::soracloud::SoraAgentApartmentActionV1::ArtifactAllowed
                || event.apartment_name != apartment.manifest.apartment_name
                || event.artifact_hash.as_deref() != Some(rule.artifact_hash.as_str())
                || event.provenance_hash.as_deref() != rule.provenance_hash.as_deref()
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "artifact allowlist rule must exactly match its audit event",
                ));
            }
        }
        for capability in &apartment.revoked_policy_capabilities {
            if !agent_apartment_audit_events
                .iter()
                .any(|(_sequence, event)| {
                    event.action
                        == iroha_data_model::soracloud::SoraAgentApartmentActionV1::PolicyRevoked
                        && event.apartment_name == apartment.manifest.apartment_name
                        && event.capability.as_deref() == Some(capability.as_str())
                })
            {
                return Err(invalid_soracloud_state(
                    "soracloud_agent_apartments",
                    "revoked apartment capability is missing its authoritative audit event",
                ));
            }
        }
    }
    Ok(())
}

/// Validate apartment history against the same retained apartments and receipts.
#[allow(
    clippy::too_many_lines,
    reason = "moved original first-release restore validation remains an ordered fail-closed boundary over the caller-held views"
)]
#[inline(never)]
fn validate_soracloud_agent_apartment_history(
    agent_apartments: &StorageView<'_, String, SoraAgentApartmentRecordV1>,
    agent_apartment_audit_events: &StorageView<'_, u64, SoraAgentApartmentAuditEventV1>,
    runtime_receipts: &StorageView<'_, Hash, SoraRuntimeReceiptV1>,
) -> Result<(), json::Error> {
    for event in agent_apartment_audit_events
        .iter()
        .map(|(_sequence, event)| event)
    {
        let apartment = agent_apartments
            .get(&event.apartment_name.to_string())
            .ok_or_else(|| {
                invalid_soracloud_state(
                    "soracloud_agent_apartment_audit_events",
                    "agent-apartment audit event has no authoritative apartment record",
                )
            })?;
        if event.manifest_hash != apartment.manifest_hash {
            return Err(invalid_soracloud_state(
                "soracloud_agent_apartment_audit_events",
                "agent-apartment audit manifest hash must match its immutable apartment manifest",
            ));
        }
        match event.action {
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::PolicyRevoked => {
                let capability = event.capability.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "policy-revoked audit event is missing capability",
                    )
                })?;
                if !apartment.revoked_policy_capabilities.contains(capability) {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "policy-revoked audit capability is absent from the monotonic revoked set",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::ArtifactAllowed => {
                let artifact_hash = event.artifact_hash.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "artifact-allowed audit event is missing artifact_hash",
                    )
                })?;
                let current_rule =
                    apartment
                        .artifact_allowlist
                        .get(artifact_hash)
                        .ok_or_else(|| {
                            invalid_soracloud_state(
                                "soracloud_agent_apartment_audit_events",
                                "artifact-allowed audit hash is absent from the retained allowlist",
                            )
                        })?;
                if current_rule.added_sequence < event.sequence
                    || (current_rule.added_sequence == event.sequence
                        && current_rule.provenance_hash.as_deref()
                            != event.provenance_hash.as_deref())
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "artifact-allowed audit event is newer than or inconsistent with the retained rule",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::AutonomyRunApproved => {
                if !apartment
                    .autonomy_run_history
                    .iter()
                    .any(|run| run.approved_sequence == event.sequence)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "autonomy-run approval has no retained run-history record",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::AutonomyRunExecuted => {
                let run_id = event.run_id.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "autonomy-run execution is missing run_id",
                    )
                })?;
                let run = apartment
                    .autonomy_run_history
                    .iter()
                    .find(|run| run.run_id == run_id)
                    .ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_agent_apartment_audit_events",
                            "autonomy-run execution has no exact retained approved run",
                        )
                    })?;
                let execution_count = agent_apartment_audit_events
                    .iter()
                    .filter(|(_sequence, candidate)| {
                        candidate.action
                            == iroha_data_model::soracloud::SoraAgentApartmentActionV1::AutonomyRunExecuted
                            && candidate.apartment_name == event.apartment_name
                            && candidate.run_id.as_deref() == Some(run_id)
                    })
                    .count();
                if execution_count != 1 {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "each approved autonomy run can retain at most one authoritative execution outcome",
                    ));
                }
                let outcome_shape_matches = match event.succeeded {
                    Some(true) => event.reason.is_none(),
                    Some(false) => event
                        .reason
                        .as_ref()
                        .is_some_and(|reason| !reason.trim().is_empty()),
                    None => false,
                };
                if event.sequence <= run.approved_sequence
                    || event.request_id.as_deref() != Some(run.run_id.as_str())
                    || event.artifact_hash.as_deref() != Some(run.artifact_hash.as_str())
                    || event.provenance_hash.as_deref() != run.provenance_hash.as_deref()
                    || event.run_label.as_deref() != Some(run.run_label.as_str())
                    || event.budget_units != Some(run.budget_units)
                    || !outcome_shape_matches
                    || event.asset_definition.is_some()
                    || event.amount.is_some()
                    || event.capability.is_some()
                    || event.from_apartment.is_some()
                    || event.to_apartment.is_some()
                    || event.channel.is_some()
                    || event.payload_hash.is_some()
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "autonomy-run execution must exactly bind its retained approval and writer-produced outcome shape",
                    ));
                }
                if let Some(receipt_id) = event.runtime_receipt_id {
                    let receipt = runtime_receipts.get(&receipt_id).ok_or_else(|| {
                        invalid_soracloud_state(
                            "soracloud_agent_apartment_audit_events",
                            "successful autonomy execution references no authoritative runtime receipt",
                        )
                    })?;
                    let receipt_link_count = agent_apartment_audit_events
                        .iter()
                        .filter(|(_sequence, candidate)| {
                            candidate.action
                                == iroha_data_model::soracloud::SoraAgentApartmentActionV1::AutonomyRunExecuted
                                && candidate.runtime_receipt_id == Some(receipt_id)
                        })
                        .count();
                    if event.succeeded != Some(true)
                        || receipt.mailbox_message_id.is_some()
                        || receipt.emitted_sequence >= event.sequence
                        || event.service_name.as_deref() != Some(receipt.service_name.as_ref())
                        || event.service_version.as_deref()
                            != Some(receipt.service_version.as_str())
                        || event.handler_name.as_deref() != Some(receipt.handler_name.as_ref())
                        || receipt_link_count != 1
                    {
                        return Err(invalid_soracloud_state(
                            "soracloud_agent_apartment_audit_events",
                            "successful autonomy execution must uniquely bind a prior local-read receipt and its exact service revision/handler",
                        ));
                    }
                } else if event.succeeded != Some(false) {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "only failed autonomy execution may omit an authoritative runtime receipt",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendRequested => {
                let request_id = event.request_id.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend request audit event is missing request_id",
                    )
                })?;
                let asset_definition = event.asset_definition.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend request audit event is missing asset_definition",
                    )
                })?;
                let amount = event.amount.as_ref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend request audit event is missing amount",
                    )
                })?;
                let expected_request_id =
                    format!("{}:wallet:{}", event.apartment_name, event.sequence);
                let retained_pending = apartment
                    .pending_wallet_requests
                    .get(request_id)
                    .is_some_and(|request| {
                        request.created_sequence == event.sequence
                            && request.asset_definition == asset_definition
                            && &request.amount == amount
                    });
                let later_approval = agent_apartment_audit_events.iter().any(
                    |(sequence, candidate)| {
                        *sequence > event.sequence
                            && candidate.action
                                == iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendApproved
                            && candidate.apartment_name == event.apartment_name
                            && candidate.request_id.as_deref() == Some(request_id)
                            && candidate.asset_definition.as_deref()
                                == Some(asset_definition)
                            && candidate.amount.as_ref() == Some(amount)
                    },
                );
                if request_id != expected_request_id || !(retained_pending || later_approval) {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend request must have its canonical id and remain pending or resolve to an exact later approval",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendApproved => {
                let request_id = event.request_id.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend approval audit event is missing request_id",
                    )
                })?;
                let asset_definition = event.asset_definition.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend approval audit event is missing asset_definition",
                    )
                })?;
                let amount = event.amount.as_ref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend approval audit event is missing amount",
                    )
                })?;
                let auto_approved_id =
                    format!("{}:wallet:{}", event.apartment_name, event.sequence);
                let matching_request = agent_apartment_audit_events.iter().any(
                    |(sequence, candidate)| {
                        *sequence < event.sequence
                            && candidate.action
                                == iroha_data_model::soracloud::SoraAgentApartmentActionV1::WalletSpendRequested
                            && candidate.apartment_name == event.apartment_name
                            && candidate.request_id.as_deref() == Some(request_id)
                            && candidate.asset_definition.as_deref()
                                == Some(asset_definition)
                        && candidate.amount.as_ref() == Some(amount)
                    },
                );
                if apartment.pending_wallet_requests.contains_key(request_id)
                    || (request_id != auto_approved_id && !matching_request)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "wallet-spend approval must consume pending state and be canonical auto-approval or resolve an exact prior request",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageEnqueued => {
                let request_id = event.request_id.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit event is missing request_id",
                    )
                })?;
                let from_apartment = event.from_apartment.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit event is missing from_apartment",
                    )
                })?;
                let to_apartment = event.to_apartment.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit event is missing to_apartment",
                    )
                })?;
                let channel = event.channel.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit event is missing channel",
                    )
                })?;
                let payload_hash = event.payload_hash.ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit event is missing payload_hash",
                    )
                })?;
                if agent_apartments.get(&from_apartment.to_owned()).is_none() {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-enqueued audit sender has no authoritative apartment record",
                    ));
                }
                let expected_message_id = format!("{to_apartment}:mail:{}", event.sequence);
                let retained_queued = apartment.mailbox_queue.iter().any(|message| {
                    message.message_id == request_id
                        && message.enqueued_sequence == event.sequence
                        && message.from_apartment == from_apartment
                        && message.channel == channel
                        && message.payload_hash == payload_hash
                });
                let later_acknowledgement = agent_apartment_audit_events.iter().any(
                    |(sequence, candidate)| {
                        *sequence > event.sequence
                            && candidate.action
                                == iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageAcknowledged
                            && candidate.apartment_name == event.apartment_name
                            && candidate.request_id.as_deref() == Some(request_id)
                            && candidate.from_apartment.as_deref() == Some(from_apartment)
                            && candidate.to_apartment.as_deref() == Some(to_apartment)
                            && candidate.channel.as_deref() == Some(channel)
                            && candidate.payload_hash == Some(payload_hash)
                    },
                );
                if to_apartment != event.apartment_name.as_ref()
                    || request_id != expected_message_id
                    || !(retained_queued || later_acknowledgement)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message enqueue must have canonical routing/id and remain queued or resolve to an exact later acknowledgement",
                    ));
                }
            }
            iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageAcknowledged => {
                let request_id = event.request_id.as_deref().ok_or_else(|| {
                    invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message-acknowledged audit event is missing request_id",
                    )
                })?;
                let matching_enqueue = agent_apartment_audit_events.iter().any(
                    |(sequence, candidate)| {
                        *sequence < event.sequence
                            && candidate.action
                                == iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageEnqueued
                            && candidate.apartment_name == event.apartment_name
                            && candidate.request_id.as_deref() == Some(request_id)
                            && candidate.from_apartment == event.from_apartment
                            && candidate.to_apartment == event.to_apartment
                            && candidate.channel == event.channel
                        && candidate.payload_hash == event.payload_hash
                    },
                );
                let acknowledgement_count = agent_apartment_audit_events
                    .iter()
                    .filter(|(_sequence, candidate)| {
                        candidate.action
                            == iroha_data_model::soracloud::SoraAgentApartmentActionV1::MessageAcknowledged
                            && candidate.apartment_name == event.apartment_name
                            && candidate.request_id.as_deref() == Some(request_id)
                    })
                    .count();
                if !matching_enqueue
                    || acknowledgement_count != 1
                    || apartment
                        .mailbox_queue
                        .iter()
                        .any(|message| message.message_id == request_id)
                {
                    return Err(invalid_soracloud_state(
                        "soracloud_agent_apartment_audit_events",
                        "message acknowledgement must uniquely consume an exact prior enqueue",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn lease_usage_assignment_version_is_writer_reachable(
    assignment_service_version: &str,
    finalize_reporter: bool,
    event_to_version: &str,
    rollout: Option<&iroha_data_model::soracloud::SoraServiceRolloutStateV1>,
) -> bool {
    // The live writer authenticates a former reporter against its retained
    // checkpoint, so its one terminal event may legitimately follow promotion
    // or rollback of the revision that originally admitted that checkpoint.
    finalize_reporter
        || assignment_service_version == event_to_version
        || rollout.is_some_and(|rollout| {
            rollout.stage == iroha_data_model::soracloud::SoraRolloutStageV1::Canary
                && (assignment_service_version == rollout.baseline_version
                    || assignment_service_version == rollout.candidate_version)
        })
}

fn lease_rollover_extends_settlement_chain(
    rollover: &iroha_data_model::soracloud::SoraServiceLeaseReportingEpochRolloverV1,
    lease_started_height: u64,
    previous_reporting_epoch: u64,
    settled_egress_bytes: u128,
) -> bool {
    rollover.lease_started_height == lease_started_height
        && rollover.previous_reporting_epoch == previous_reporting_epoch
        && previous_reporting_epoch.checked_add(1) == Some(rollover.new_reporting_epoch)
        && settled_egress_bytes.checked_add(rollover.settled_egress_bytes_delta)
            == Some(rollover.settled_egress_bytes)
}

fn replay_soracloud_service_lease_usage(
    prior: &iroha_data_model::soracloud::SoraServiceLeaseStateV1,
    usage: &iroha_data_model::soracloud::SoraServiceLeaseUsageAuditV1,
    rollover: Option<&iroha_data_model::soracloud::SoraServiceLeaseReportingEpochRolloverV1>,
    block_height: u64,
    accounted_storage_bytes: u64,
) -> Result<iroha_data_model::soracloud::SoraServiceLeaseStateV1, String> {
    use iroha_data_model::soracloud::{
        SORA_SERVICE_LEASE_MAX_EGRESS_BYTES_PER_REPORTER_BLOCK_V1,
        SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1, SoraServiceLeaseEgressCheckpointV1,
        SoraServiceLeaseStatusV1,
    };

    if prior.status == SoraServiceLeaseStatusV1::Suspended {
        return Err("suspended hosted-service leases have no first-release writer".to_owned());
    }
    let mut next = prior.clone();
    if usage.reporting_epoch == prior.reporting_epoch {
        if rollover.is_some() {
            return Err("same-epoch lease usage must not carry rollover material".to_owned());
        }
        if let Some(checkpoint) = next
            .egress_reporter_checkpoints
            .iter_mut()
            .find(|checkpoint| {
                checkpoint.reporting_epoch == usage.reporting_epoch
                    && checkpoint.assignment.service_version == usage.assignment.service_version
                    && checkpoint.assignment.placement.replica_slot
                        == usage.assignment.placement.replica_slot
                    && checkpoint.assignment.placement.placement_incarnation
                        == usage.assignment.placement.placement_incarnation
                    && checkpoint.assignment.placement.validator_account_id
                        == usage.assignment.placement.validator_account_id
            })
        {
            if checkpoint.assignment != usage.assignment {
                return Err(
                    "lease usage must retain the exact originally admitted assignment evidence"
                        .to_owned(),
                );
            }
            if usage.replica_accounted_egress_bytes == checkpoint.accounted_egress_bytes
                && usage.finalize_reporter == checkpoint.finalize_reporter
            {
                return Err("an exact reporter no-op must not consume an audit sequence".to_owned());
            }
            if checkpoint.finalize_reporter
                && !usage.finalize_reporter
                && usage.replica_accounted_egress_bytes != checkpoint.accounted_egress_bytes
            {
                return Err(
                    "a finalized reporter checkpoint must reopen at its exact terminal byte value before increasing"
                        .to_owned(),
                );
            }
            if usage.replica_accounted_egress_bytes < checkpoint.accounted_egress_bytes {
                return Err("lease usage must not decrease reporter bytes".to_owned());
            }
            if checkpoint.finalize_reporter && usage.finalize_reporter {
                return Err("an already-finalized reporter cannot finalize again".to_owned());
            }
            let delta = usage.replica_accounted_egress_bytes - checkpoint.accounted_egress_bytes;
            let elapsed_blocks = block_height.saturating_sub(checkpoint.last_updated_height);
            let maximum_delta = elapsed_blocks
                .checked_mul(SORA_SERVICE_LEASE_MAX_EGRESS_BYTES_PER_REPORTER_BLOCK_V1)
                .unwrap_or(u64::MAX);
            if delta > maximum_delta {
                return Err("lease usage exceeds the elapsed-block egress bound".to_owned());
            }
            checkpoint.accounted_egress_bytes = usage.replica_accounted_egress_bytes;
            checkpoint.last_updated_height = block_height;
            checkpoint.finalize_reporter = usage.finalize_reporter;
        } else {
            if usage.replica_accounted_egress_bytes != 0 || usage.finalize_reporter {
                return Err(
                    "a new reporter checkpoint must open at zero and remain active".to_owned(),
                );
            }
            if next.egress_reporter_checkpoints.len()
                >= SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1
            {
                return Err("reporter checkpoint limit is exhausted".to_owned());
            }
            next.egress_reporter_checkpoints
                .push(SoraServiceLeaseEgressCheckpointV1 {
                    reporting_epoch: usage.reporting_epoch,
                    assignment: usage.assignment.clone(),
                    accounted_egress_bytes: 0,
                    last_updated_height: block_height,
                    finalize_reporter: false,
                });
        }
    } else {
        let rollover = rollover.ok_or_else(|| {
            "successor-epoch lease usage must carry exact rollover material".to_owned()
        })?;
        let successor = prior
            .reporting_epoch
            .checked_add(1)
            .ok_or_else(|| "lease reporting epoch overflows u64".to_owned())?;
        if usage.reporting_epoch != successor
            || usage.replica_accounted_egress_bytes != 0
            || usage.finalize_reporter
            || prior.egress_reporter_checkpoints.len()
                != SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1
        {
            return Err(
                "lease rollover trigger is not the one canonical successor transition".to_owned(),
            );
        }
        if next
            .egress_reporter_checkpoints
            .iter()
            .any(|checkpoint| !checkpoint.finalize_reporter)
        {
            return Err(
                "every prior-epoch reporter checkpoint must be finalized before rollover"
                    .to_owned(),
            );
        }
        let settled_delta = next
            .egress_reporter_checkpoints
            .iter()
            .try_fold(0_u128, |total, checkpoint| {
                total.checked_add(u128::from(checkpoint.accounted_egress_bytes))
            })
            .ok_or_else(|| "lease rollover settlement overflows u128".to_owned())?;
        let settled = prior
            .settled_egress_bytes
            .checked_add(settled_delta)
            .ok_or_else(|| "cumulative lease settlement overflows u128".to_owned())?;
        if rollover.lease_started_height != prior.lease_started_height
            || rollover.previous_reporting_epoch != prior.reporting_epoch
            || rollover.new_reporting_epoch != successor
            || rollover.reporter_account_id != usage.assignment.placement.validator_account_id
            || rollover.active_service_version != usage.assignment.service_version
            || rollover.replica_slot != usage.assignment.placement.replica_slot
            || rollover.placement_incarnation != usage.assignment.placement.placement_incarnation
            || usize::try_from(rollover.finalized_checkpoint_count).ok()
                != Some(SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1)
            || rollover.settled_egress_bytes_delta != settled_delta
            || rollover.settled_egress_bytes != settled
        {
            return Err(
                "lease rollover audit does not match the exact replayed settlement".to_owned(),
            );
        }
        next.reporting_epoch = successor;
        next.settled_egress_bytes = settled;
        next.egress_reporter_checkpoints = vec![SoraServiceLeaseEgressCheckpointV1 {
            reporting_epoch: successor,
            assignment: usage.assignment.clone(),
            accounted_egress_bytes: 0,
            last_updated_height: block_height,
            finalize_reporter: false,
        }];
    }
    next.egress_reporter_checkpoints.sort_by(|left, right| {
        (
            left.reporting_epoch,
            left.assignment.service_version.as_str(),
            left.assignment.placement.replica_slot,
            left.assignment.placement.placement_incarnation,
            &left.assignment.placement.validator_account_id,
        )
            .cmp(&(
                right.reporting_epoch,
                right.assignment.service_version.as_str(),
                right.assignment.placement.replica_slot,
                right.assignment.placement.placement_incarnation,
                &right.assignment.placement.validator_account_id,
            ))
    });
    next.refresh_accounted_egress_bytes()
        .map_err(|error| error.to_string())?;
    match next
        .status_at(block_height, accounted_storage_bytes)
        .map_err(|error| error.to_string())?
    {
        SoraServiceLeaseStatusV1::Active => {
            next.status = SoraServiceLeaseStatusV1::Active;
            next.last_status_reason = None;
        }
        SoraServiceLeaseStatusV1::Exhausted => {
            next.status = SoraServiceLeaseStatusV1::Exhausted;
            next.last_status_reason =
                Some("prepaid runtime balance exhausted by accounted egress usage".to_owned());
        }
        SoraServiceLeaseStatusV1::Expired => {
            next.status = SoraServiceLeaseStatusV1::Expired;
            next.last_status_reason =
                Some("service lease expired before additional usage could be billed".to_owned());
        }
        SoraServiceLeaseStatusV1::Suspended => {
            return Err("suspended hosted-service lease is not replayable in v1".to_owned());
        }
    }
    Ok(next)
}

#[cfg(test)]
mod soracloud_service_lease_replay_tests {
    use core::num::NonZeroU16;

    use super::{
        lease_rollover_extends_settlement_chain,
        lease_usage_assignment_version_is_writer_reachable, replay_soracloud_service_lease_usage,
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        soracloud::{
            SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1,
            SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1,
            SORA_SERVICE_LEASE_REPORTING_EPOCH_ROLLOVER_VERSION_V1,
            SORA_SERVICE_LEASE_STATE_VERSION_V1, SORA_SERVICE_LEASE_USAGE_AUDIT_VERSION_V1,
            SoraInrouGuestIsaV1, SoraInrouReplicaHostAvailabilityV1, SoraInrouReplicaPlacementV1,
            SoraServiceLeaseClockV1, SoraServiceLeaseEgressCheckpointV1,
            SoraServiceLeaseReporterAssignmentV1, SoraServiceLeaseReportingEpochRolloverV1,
            SoraServiceLeaseStateV1, SoraServiceLeaseStatusV1, SoraServiceLeaseUsageAuditV1,
        },
    };
    use iroha_model_base::peer::PeerId;

    fn sample_assignment(service_version: &str) -> SoraServiceLeaseReporterAssignmentV1 {
        let key_pair = KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519)
            .expect("derive deterministic lease reporter");
        SoraServiceLeaseReporterAssignmentV1 {
            schema_version: SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1,
            service_version: service_version.to_owned(),
            placement: SoraInrouReplicaPlacementV1 {
                replica_slot: 1,
                economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
                lease_started_height: 1,
                placement_incarnation: Hash::new(b"lease-replay-placement"),
                host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                validator_account_id: AccountId::new(key_pair.public_key().clone()),
                peer_id: PeerId::from(key_pair.public_key().clone()).to_string(),
                selected_guest_isa: SoraInrouGuestIsaV1::Aarch64,
            },
            placement_reconciled_at_ms: 1,
        }
    }

    fn finalized_lease(
        assignment: SoraServiceLeaseReporterAssignmentV1,
    ) -> SoraServiceLeaseStateV1 {
        let lease = SoraServiceLeaseStateV1 {
            schema_version: SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: SoraServiceLeaseStatusV1::Active,
            quota_class: "replay-test".to_owned(),
            replica_count: NonZeroU16::new(1).expect("one replica"),
            deployment_deposit: "1".parse().expect("deployment deposit"),
            prepaid_runtime_balance: "100".parse().expect("prepaid balance"),
            runtime_price_per_block: "0.001".parse().expect("runtime price"),
            storage_price_per_gib_block: "0.001".parse().expect("storage price"),
            egress_price_per_mib: "0.001".parse().expect("egress price"),
            lease_started_height: 1,
            lease_expires_height: 100,
            reporting_epoch: 1,
            settled_egress_bytes: 0,
            egress_reporter_checkpoints: vec![SoraServiceLeaseEgressCheckpointV1 {
                reporting_epoch: 1,
                assignment,
                accounted_egress_bytes: 10,
                last_updated_height: 10,
                finalize_reporter: true,
            }],
            accounted_egress_bytes: 10,
            last_status_reason: None,
        };
        lease.validate().expect("valid finalized lease fixture");
        lease
    }

    #[test]
    fn retired_revision_terminal_usage_remains_writer_reachable() {
        let assignment = sample_assignment("retired");
        assert!(lease_usage_assignment_version_is_writer_reachable(
            "retired", true, "current", None,
        ));
        assert!(!lease_usage_assignment_version_is_writer_reachable(
            "retired", false, "current", None,
        ));

        let mut lease = finalized_lease(assignment.clone());
        lease.egress_reporter_checkpoints[0].finalize_reporter = false;
        let usage = SoraServiceLeaseUsageAuditV1 {
            schema_version: SORA_SERVICE_LEASE_USAGE_AUDIT_VERSION_V1,
            reporting_epoch: 1,
            assignment,
            replica_accounted_egress_bytes: 11,
            finalize_reporter: true,
        };
        let terminal = replay_soracloud_service_lease_usage(&lease, &usage, None, 11, 0)
            .expect("retired reporter's one terminal monotonic update must replay");
        assert!(terminal.egress_reporter_checkpoints[0].finalize_reporter);
        assert_eq!(
            terminal.egress_reporter_checkpoints[0].accounted_egress_bytes,
            11
        );
    }

    #[test]
    fn baseline_reporter_rollover_extends_candidate_head_settlement_chain() {
        let assignment = sample_assignment("baseline");
        let rollover = SoraServiceLeaseReportingEpochRolloverV1 {
            schema_version: SORA_SERVICE_LEASE_REPORTING_EPOCH_ROLLOVER_VERSION_V1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            previous_reporting_epoch: 3,
            new_reporting_epoch: 4,
            reporter_account_id: assignment.placement.validator_account_id.clone(),
            active_service_version: assignment.service_version.clone(),
            replica_slot: 1,
            placement_incarnation: assignment.placement.placement_incarnation,
            finalized_checkpoint_count: u32::try_from(
                SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1,
            )
            .expect("checkpoint bound fits u32"),
            settled_egress_bytes_delta: 7,
            settled_egress_bytes: 12,
        };
        rollover.validate().expect("valid baseline rollover");
        let event_to_version = "candidate";
        assert_ne!(rollover.active_service_version, event_to_version);
        assert!(lease_rollover_extends_settlement_chain(&rollover, 1, 3, 5,));
    }

    #[test]
    fn replay_retains_distinct_placement_incarnations_for_one_reporter() {
        let mut incarnations = [
            Hash::new(b"prior-placement"),
            Hash::new(b"returned-placement"),
        ];
        incarnations.sort_unstable();
        let mut original = sample_assignment("current");
        original.placement.placement_incarnation = incarnations[1];
        let mut replacement = original.clone();
        replacement.placement.placement_incarnation = incarnations[0];
        let mut lease = finalized_lease(original.clone());
        lease.egress_reporter_checkpoints[0].finalize_reporter = false;
        let mut usage = SoraServiceLeaseUsageAuditV1 {
            schema_version: SORA_SERVICE_LEASE_USAGE_AUDIT_VERSION_V1,
            reporting_epoch: 1,
            assignment: replacement.clone(),
            replica_accounted_egress_bytes: 0,
            finalize_reporter: false,
        };
        let opened = replay_soracloud_service_lease_usage(&lease, &usage, None, 11, 0)
            .expect("the replacement placement opens its own zero counter");
        opened
            .validate()
            .expect("replacement checkpoints remain canonically ordered");
        assert_eq!(opened.egress_reporter_checkpoints.len(), 2);
        assert_eq!(opened.accounted_egress_bytes, 10);
        assert_eq!(
            opened.egress_reporter_checkpoints[0].assignment,
            replacement
        );
        assert_eq!(
            opened.egress_reporter_checkpoints[1],
            lease.egress_reporter_checkpoints[0]
        );

        usage.assignment = original;
        usage.replica_accounted_egress_bytes = 11;
        usage.finalize_reporter = true;
        let finalized = replay_soracloud_service_lease_usage(&opened, &usage, None, 12, 0)
            .expect("the predecessor can deliver its exact terminal usage after replacement");
        assert_eq!(
            finalized.egress_reporter_checkpoints[0],
            opened.egress_reporter_checkpoints[0]
        );
        assert!(finalized.egress_reporter_checkpoints[1].finalize_reporter);
        assert_eq!(finalized.accounted_egress_bytes, 11);

        usage.assignment = replacement;
        usage.replica_accounted_egress_bytes = 1;
        usage.finalize_reporter = false;
        let increased = replay_soracloud_service_lease_usage(&finalized, &usage, None, 13, 0)
            .expect("the replacement counter increases independently");
        increased
            .validate()
            .expect("both placement counters remain valid");
        assert_eq!(increased.accounted_egress_bytes, 12);
        assert_eq!(
            increased.egress_reporter_checkpoints[0].accounted_egress_bytes,
            1
        );
        assert_eq!(
            increased.egress_reporter_checkpoints[1].accounted_egress_bytes,
            11
        );
    }

    #[test]
    fn replay_rollover_rejects_another_placement_incarnation() {
        let assignment = sample_assignment("current");
        let mut lease = finalized_lease(assignment.clone());
        let checkpoint = lease.egress_reporter_checkpoints[0].clone();
        lease.egress_reporter_checkpoints = (0
            ..SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1)
            .map(|index| {
                let mut checkpoint = checkpoint.clone();
                checkpoint.assignment.service_version = format!("retired-{index:04}");
                checkpoint
            })
            .collect();
        lease
            .refresh_accounted_egress_bytes()
            .expect("bounded reporter sum");
        lease.validate().expect("full finalized reporting epoch");
        let usage = SoraServiceLeaseUsageAuditV1 {
            schema_version: SORA_SERVICE_LEASE_USAGE_AUDIT_VERSION_V1,
            reporting_epoch: 2,
            assignment: assignment.clone(),
            replica_accounted_egress_bytes: 0,
            finalize_reporter: false,
        };
        let mut rollover = SoraServiceLeaseReportingEpochRolloverV1 {
            schema_version: SORA_SERVICE_LEASE_REPORTING_EPOCH_ROLLOVER_VERSION_V1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height: 1,
            previous_reporting_epoch: 1,
            new_reporting_epoch: 2,
            reporter_account_id: assignment.placement.validator_account_id.clone(),
            active_service_version: assignment.service_version.clone(),
            replica_slot: 1,
            placement_incarnation: Hash::new(b"another-rollover-placement"),
            finalized_checkpoint_count: u32::try_from(
                SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1,
            )
            .expect("checkpoint bound fits u32"),
            settled_egress_bytes_delta: lease.accounted_egress_bytes,
            settled_egress_bytes: lease.accounted_egress_bytes,
        };
        let error = replay_soracloud_service_lease_usage(&lease, &usage, Some(&rollover), 11, 0)
            .expect_err("rollover metadata cannot retarget the opener's placement incarnation");
        assert!(error.contains("exact replayed settlement"), "{error}");
        rollover.placement_incarnation = assignment.placement.placement_incarnation;
        let rolled = replay_soracloud_service_lease_usage(&lease, &usage, Some(&rollover), 11, 0)
            .expect("matching rollover and opener identities replay");
        rolled.validate().expect("valid successor lease");
        assert_eq!(rolled.egress_reporter_checkpoints[0].assignment, assignment);
        assert_eq!(rolled.accounted_egress_bytes, lease.accounted_egress_bytes);
    }

    #[test]
    fn replay_requires_exact_terminal_value_before_reopened_growth() {
        let assignment = sample_assignment("current");
        let lease = finalized_lease(assignment.clone());
        let mut usage = SoraServiceLeaseUsageAuditV1 {
            schema_version: SORA_SERVICE_LEASE_USAGE_AUDIT_VERSION_V1,
            reporting_epoch: 1,
            assignment,
            replica_accounted_egress_bytes: 11,
            finalize_reporter: false,
        };

        let error = replay_soracloud_service_lease_usage(&lease, &usage, None, 11, 0)
            .expect_err("reopen-and-increase must not replay");
        assert!(error.contains("exact terminal byte value"), "{error}");

        usage.replica_accounted_egress_bytes = 10;
        let reopened = replay_soracloud_service_lease_usage(&lease, &usage, None, 11, 0)
            .expect("exact terminal value reopens the reporter");
        assert!(!reopened.egress_reporter_checkpoints[0].finalize_reporter);

        usage.replica_accounted_egress_bytes = 11;
        let increased = replay_soracloud_service_lease_usage(&reopened, &usage, None, 12, 0)
            .expect("a reopened reporter may grow monotonically in a later block");
        assert_eq!(
            increased.egress_reporter_checkpoints[0].accounted_egress_bytes,
            11
        );
    }
}

fn register_soracloud_sequence(
    authoritative_sequences: &mut std::collections::BTreeSet<u64>,
    field: &str,
    sequence: u64,
) -> Result<(), json::Error> {
    if authoritative_sequences.insert(sequence) {
        Ok(())
    } else {
        Err(invalid_soracloud_state(
            field,
            format!("authoritative sequence `{sequence}` collides with another Soracloud record"),
        ))
    }
}

fn invalid_soracloud_state(field: &str, message: impl Into<String>) -> json::Error {
    json::Error::InvalidField {
        field: format!("world.{field}"),
        message: message.into(),
    }
}
impl MusubiPersistedState<'_> {
    #[allow(clippy::too_many_lines)]
    fn validate(self) -> Result<(), json::Error> {
        let namespace_bindings = self.namespace_bindings.view();
        let packages = self.packages.view();
        let package_metadata = self.package_metadata.view();
        let package_members = self.package_members.view();
        let package_invitations = self.package_invitations.view();
        let maintainer_directory = self.maintainer_directory.view();
        let releases = self.releases.view();
        let archives = self.archives.view();
        let provider_bundle_attestations = self.provider_bundle_attestations.view();
        let archive_locations = self.archive_locations.view();
        let archive_availability = self.archive_availability.view();
        let archive_reverse_references = self.archive_reverse_references.view();
        let resolver_index = self.resolver_index.view();
        validate_musubi_resolver_checkpoint_structure(
            self.resolver_index_checkpoints,
            self.resolver_index_revision,
        )?;
        let public_directory = self.public_directory.view();
        let aliases = self.aliases.view();
        let alias_history = self.alias_history.view();
        let governance_decisions = self.governance_decisions.view();
        let mut decision_actions = Vec::new();
        for (decision_id, consumption) in governance_decisions.iter() {
            consumption.validate().map_err(|error| {
                invalid_musubi_state("musubi_governance_decisions", error.to_string())
            })?;
            let decision = &consumption.decision;
            if decision_id != &decision.decision_id {
                return Err(invalid_musubi_state(
                    "musubi_governance_decisions",
                    "governance-decision key does not match its embedded decision id",
                ));
            }
            decision_actions.push(decision.action_digest);
        }
        for (package_id, metadata) in package_metadata.iter() {
            metadata.package.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_metadata", error.to_string())
            })?;
            metadata.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_metadata", error.to_string())
            })?;
            if package_id != &metadata.package || packages.get(package_id).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_package_metadata",
                    "metadata key/identity is inconsistent with the package store",
                ));
            }
        }
        let mut member_accounts = BTreeMap::<MusubiPackageIdV1, Vec<AccountId>>::new();
        let mut owner_accounts = BTreeMap::<MusubiPackageIdV1, Vec<AccountId>>::new();
        for (member_key, member) in package_members.iter() {
            member.package.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_members", error.to_string())
            })?;
            member.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_members", error.to_string())
            })?;
            let package = packages.get(&member.package).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_package_members",
                    "member references a missing package",
                )
            })?;
            if member_key != &member.key()
                || member.governance_revision > package.revisions.governance
            {
                return Err(invalid_musubi_state(
                    "musubi_package_members",
                    "member key or governance revision is inconsistent with its package",
                ));
            }
            let directory_key = MusubiMaintainerDirectoryKeyV1::accepted(
                member.package.clone(),
                member.account.clone(),
            );
            if maintainer_directory.get(&directory_key)
                != Some(&MusubiMaintainerDirectoryEntryV1::Accepted(member.clone()))
            {
                return Err(invalid_musubi_state(
                    "musubi_maintainer_directory",
                    "accepted member is missing from the exact maintainer directory",
                ));
            }
            member_accounts
                .entry(member.package.clone())
                .or_default()
                .push(member.account.clone());
            if matches!(
                member.role,
                iroha_data_model::musubi::MusubiPackageRoleV1::Owner
            ) {
                owner_accounts
                    .entry(member.package.clone())
                    .or_default()
                    .push(member.account.clone());
            }
        }
        for (invite_id, invitation) in package_invitations.iter() {
            invitation.package.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_invitations", error.to_string())
            })?;
            invitation.validate().map_err(|error| {
                invalid_musubi_state("musubi_package_invitations", error.to_string())
            })?;
            let package = packages.get(&invitation.package).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_package_invitations",
                    "invitation references a missing package",
                )
            })?;
            let revision_is_invalid =
                if invitation.state == iroha_data_model::musubi::MusubiInvitationStateV1::Pending {
                    invitation.expected_governance_revision != package.revisions.governance
                } else {
                    invitation.expected_governance_revision > package.revisions.governance
                };
            if invite_id != &invitation.invite_id || revision_is_invalid {
                return Err(invalid_musubi_state(
                    "musubi_package_invitations",
                    "invitation key or pending governance revision is inconsistent with its package",
                ));
            }
            let directory_key = MusubiMaintainerDirectoryKeyV1::pending(
                invitation.package.clone(),
                invitation.invited_account.clone(),
                invitation.invite_id,
            );
            let indexed = maintainer_directory.get(&directory_key);
            if invitation.state == iroha_data_model::musubi::MusubiInvitationStateV1::Pending {
                if indexed
                    != Some(&MusubiMaintainerDirectoryEntryV1::PendingInvitation(
                        invitation.clone(),
                    ))
                {
                    return Err(invalid_musubi_state(
                        "musubi_maintainer_directory",
                        "pending invitation is missing from the exact maintainer directory",
                    ));
                }
            } else if indexed.is_some() {
                return Err(invalid_musubi_state(
                    "musubi_maintainer_directory",
                    "non-pending invitation remains selectable in the maintainer directory",
                ));
            }
        }
        let mut pending_directory_counts = BTreeMap::<MusubiPackageIdV1, usize>::new();
        for (directory_key, entry) in maintainer_directory.iter() {
            entry.validate().map_err(|error| {
                invalid_musubi_state("musubi_maintainer_directory", error.to_string())
            })?;
            if directory_key != &entry.key() {
                return Err(invalid_musubi_state(
                    "musubi_maintainer_directory",
                    "maintainer directory key disagrees with its embedded entry",
                ));
            }
            let authoritative = match entry {
                MusubiMaintainerDirectoryEntryV1::Accepted(member) => package_members
                    .get(&member.key())
                    .is_some_and(|stored| stored == member),
                MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation) => {
                    let count = pending_directory_counts
                        .entry(invitation.package.clone())
                        .or_default();
                    *count = count.saturating_add(1);
                    if *count > MUSUBI_MAX_PENDING_INVITATIONS_V1 {
                        return Err(invalid_musubi_state(
                            "musubi_maintainer_directory",
                            "package exceeds the pending-invitation bound",
                        ));
                    }
                    package_invitations
                        .get(&invitation.invite_id)
                        .is_some_and(|stored| stored == invitation)
                }
            };
            if !authoritative {
                return Err(invalid_musubi_state(
                    "musubi_maintainer_directory",
                    "maintainer directory entry lacks an exact authoritative record",
                ));
            }
        }
        for (package_id, package) in packages.iter() {
            package
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_packages", error.to_string()))?;
            if package_id != &package.package {
                return Err(invalid_musubi_state(
                    "musubi_packages",
                    "package key does not match the embedded package identity",
                ));
            }
            let binding = namespace_bindings
                .get(&package.claimed_namespace)
                .ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_packages",
                        "package references a missing immutable namespace binding",
                    )
                })?;
            if binding.digest() != package.claimed_namespace_binding
                || binding.home_dataspace != package.package.home_dataspace
                || binding.scope != package.package.scope
            {
                return Err(invalid_musubi_state(
                    "musubi_packages",
                    "package identity disagrees with its immutable namespace binding",
                ));
            }
            let metadata = package_metadata.get(package_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_package_metadata",
                    "package is missing its authoritative metadata projection",
                )
            })?;
            if metadata.revision != package.revisions.metadata {
                return Err(invalid_musubi_state(
                    "musubi_package_metadata",
                    "metadata revision disagrees with the package revision",
                ));
            }
            let actual_members = member_accounts.remove(package_id).unwrap_or_default();
            let actual_owners = owner_accounts.remove(package_id).unwrap_or_default();
            if actual_members != package.member_accounts || actual_owners != package.owners {
                return Err(invalid_musubi_state(
                    "musubi_package_members",
                    "authoritative member roles disagree with package owner/member indexes",
                ));
            }
        }
        let mut current_location_ids =
            BTreeMap::<ArchiveId, Vec<iroha_data_model::musubi::MusubiArchiveLocationIdV1>>::new();
        let mut location_providers =
            BTreeMap::<ArchiveId, BTreeSet<iroha_data_model::sorafs::capacity::ProviderId>>::new();
        for (attestation_key, record) in provider_bundle_attestations.iter() {
            record.validate().map_err(|error| {
                invalid_musubi_state("musubi_provider_bundle_attestations", error.to_string())
            })?;
            if attestation_key != &record.key {
                return Err(invalid_musubi_state(
                    "musubi_provider_bundle_attestations",
                    "provider-attestation key does not match the stored record",
                ));
            }
            let archive = archives.get(&record.key.archive_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_provider_bundle_attestations",
                    "provider attestation references a missing archive",
                )
            })?;
            let receipt = &archive.staging_receipt.payload.binding;
            let binding = &record.attestation.payload.binding;
            if record.registered_at_height < archive.registered_at_height
                || binding.network_id != receipt.network_id
                || binding.archive_id != archive.archive_id
                || binding.bundle_digest != archive.commitment.bundle_digest
                || binding.descriptor_digest != archive.commitment.descriptor_digest
                || binding.semantic_release_manifest_digest
                    != receipt.semantic_release_manifest_digest
                || binding.source_tree_digest != archive.commitment.source_tree_digest
            {
                return Err(invalid_musubi_state(
                    "musubi_provider_bundle_attestations",
                    "provider attestation does not match the archive and ingress receipt commitments",
                ));
            }
        }
        for (location_key, location) in archive_locations.iter() {
            location.validate().map_err(|error| {
                invalid_musubi_state("musubi_archive_locations", error.to_string())
            })?;
            let archive = archives.get(&location.archive_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_archive_locations",
                    "archive location references a missing archive",
                )
            })?;
            let mut attestation_references = Vec::with_capacity(location.providers.len());
            let mut verification_lock_digest = None;
            for provider_id in &location.providers {
                let key = MusubiProviderBundleAttestationKeyV1 {
                    archive_id: location.archive_id,
                    replication_order: location.replication_order,
                    provider_id: *provider_id,
                };
                let record = provider_bundle_attestations.get(&key).ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_archive_locations",
                        "archive location references a missing exact provider attestation",
                    )
                })?;
                let digest = record.attestation.payload.binding.verification_lock_digest;
                if verification_lock_digest.is_some_and(|expected| expected != digest) {
                    return Err(invalid_musubi_state(
                        "musubi_archive_locations",
                        "archive-location provider attestations disagree on the verification lock",
                    ));
                }
                verification_lock_digest = Some(digest);
                attestation_references.push(MusubiProviderBundleAttestationRefV1 {
                    provider_id: *provider_id,
                    digest: record.attestation_digest,
                });
            }
            let attestation_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
                location.archive_id,
                location.replication_order,
                &attestation_references,
            )
            .map_err(|error| invalid_musubi_state("musubi_archive_locations", error.to_string()))?;
            if attestation_set_digest != location.provider_attestation_set_digest {
                return Err(invalid_musubi_state(
                    "musubi_archive_locations",
                    "archive-location provider-attestation set digest is not exact",
                ));
            }
            if location_key != &location.key() || location.revision > archive.location_revision {
                return Err(invalid_musubi_state(
                    "musubi_archive_locations",
                    "archive-location key or revision is inconsistent with its archive",
                ));
            }
            if location.state != MusubiArchiveLocationStateV1::Retired {
                current_location_ids
                    .entry(location.archive_id)
                    .or_default()
                    .push(location.location_id);
                location_providers
                    .entry(location.archive_id)
                    .or_default()
                    .extend(location.providers.iter().copied());
            }
        }
        for (archive_id, archive) in archives.iter() {
            archive
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_archives", error.to_string()))?;
            if archive_id != &archive.archive_id {
                return Err(invalid_musubi_state(
                    "musubi_archives",
                    "archive key does not match the embedded archive identity",
                ));
            }
            let mut expected_locations =
                current_location_ids.remove(archive_id).unwrap_or_default();
            expected_locations.sort();
            if expected_locations != archive.location_ids {
                return Err(invalid_musubi_state(
                    "musubi_archives",
                    "archive location directory is not the exact current non-retired set",
                ));
            }
        }
        for (archive_id, availability) in archive_availability.iter() {
            availability.validate().map_err(|error| {
                invalid_musubi_state("musubi_archive_availability", error.to_string())
            })?;
            let archive = archives.get(archive_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_archive_availability",
                    "availability projection references a missing archive",
                )
            })?;
            let provider_bound = location_providers.get(archive_id).map_or(0, BTreeSet::len);
            if archive_id != &availability.archive_id
                || usize::from(availability.active_locations) > archive.location_ids.len()
                || usize::from(availability.healthy_replicas) > provider_bound
                || availability.index_revision > self.resolver_index_revision
            {
                return Err(invalid_musubi_state(
                    "musubi_archive_availability",
                    "availability key, counts, or revision disagrees with authoritative archive state",
                ));
            }
        }
        for (archive_id, _) in archives.iter() {
            if archive_availability.get(archive_id).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_archive_availability",
                    "archive is missing its authoritative availability projection",
                ));
            }
        }
        let mut expected_references = BTreeMap::<ArchiveId, Vec<MusubiReleaseIdV1>>::new();
        for (archive_id, _) in archives.iter() {
            expected_references.insert(*archive_id, Vec::new());
        }
        for (release_id, release) in releases.iter() {
            release
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_releases", error.to_string()))?;
            if release_id != &release.manifest.release
                || packages.get(&release_id.package).is_none()
            {
                return Err(invalid_musubi_state(
                    "musubi_releases",
                    "release key or package reference is inconsistent",
                ));
            }
            let archive = archives.get(&release.manifest.archive_id).ok_or_else(|| {
                invalid_musubi_state("musubi_releases", "release references a missing archive")
            })?;
            let receipt = &archive.staging_receipt.payload.binding;
            if release.manifest.semantic_digest() != receipt.semantic_release_manifest_digest
                || release.published_by != receipt.publisher
            {
                return Err(invalid_musubi_state(
                    "musubi_releases",
                    "release does not match its archive ingress receipt",
                ));
            }
            let references = expected_references
                .get_mut(&release.manifest.archive_id)
                .expect("validated archive has a reverse-reference accumulator");
            references.push(release_id.clone());
            if let iroha_data_model::musubi::MusubiArtifactGovernanceStateV1::TakenDown(takedown) =
                &release.artifact_governance
                && !decision_actions.contains(&takedown.action_digest)
            {
                return Err(invalid_musubi_state(
                    "musubi_releases",
                    "artifact takedown does not reference a retained governance decision",
                ));
            }
        }
        for (archive_id, references) in archive_reverse_references.iter() {
            references.validate().map_err(|error| {
                invalid_musubi_state("musubi_archive_reverse_references", error.to_string())
            })?;
            let expected = expected_references.get(archive_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_archive_reverse_references",
                    "reverse-reference record names a missing archive",
                )
            })?;
            if archive_id != &references.archive_id || &references.releases != expected {
                return Err(invalid_musubi_state(
                    "musubi_archive_reverse_references",
                    "archive reverse references are not the exact release set",
                ));
            }
        }
        let mut expected_replication_shortfall_releases = 0_u64;
        for (archive_id, expected) in &expected_references {
            if archive_reverse_references.get(archive_id).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_archive_reverse_references",
                    format!(
                        "archive is missing its reverse-reference set of {} releases",
                        expected.len()
                    ),
                ));
            }
            let availability = archive_availability
                .get(archive_id)
                .expect("every validated archive has an availability projection");
            if availability.availability != MusubiStorageAvailabilityV1::Selectable {
                let release_count = u64::try_from(expected.len()).map_err(|_| {
                    invalid_musubi_state(
                        "musubi_replication_shortfall_releases",
                        "archive reverse-reference count overflows u64",
                    )
                })?;
                expected_replication_shortfall_releases = expected_replication_shortfall_releases
                    .checked_add(release_count)
                    .ok_or_else(|| {
                        invalid_musubi_state(
                            "musubi_replication_shortfall_releases",
                            "replication-shortfall release count overflows u64",
                        )
                    })?;
            }
        }
        if self.replication_shortfall_releases != expected_replication_shortfall_releases {
            return Err(invalid_musubi_state(
                "musubi_replication_shortfall_releases",
                format!(
                    "persisted count {} does not match the exact derived count {expected_replication_shortfall_releases}",
                    self.replication_shortfall_releases
                ),
            ));
        }
        let mut latest_selectable =
            BTreeMap::<MusubiPackageIdV1, Option<iroha_data_model::musubi::MusubiVersionV1>>::new();
        for (package_id, _) in packages.iter() {
            latest_selectable.insert(package_id.clone(), None);
        }
        for (release_id, row) in resolver_index.iter() {
            row.validate().map_err(|error| {
                invalid_musubi_state("musubi_resolver_index", error.to_string())
            })?;
            let release = releases.get(release_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_resolver_index",
                    "resolver row references a missing release",
                )
            })?;
            let archive = archives.get(&release.manifest.archive_id).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_resolver_index",
                    "resolver row references a missing archive",
                )
            })?;
            let availability = archive_availability
                .get(&release.manifest.archive_id)
                .ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_resolver_index",
                        "resolver row is missing its authoritative storage projection",
                    )
                })?;
            if release_id != &row.release
                || row.release_digest != release.release_digest
                || row.archive_id != release.manifest.archive_id
                || row.source_digest != archive.commitment.source_tree_digest
                || row.interface_digest != release.manifest.interface_digest
                || row.abi != release.manifest.abi
                || row.dependencies.as_slice() != release.manifest.dependencies.as_slice()
                || row.selection.yank != release.yank
                || row.selection.governance != release.artifact_governance
                || row.selection.storage != *availability
                || row.index_revision > self.resolver_index_revision
            {
                return Err(invalid_musubi_state(
                    "musubi_resolver_index",
                    "resolver row diverges from authoritative release/archive projections",
                ));
            }
            if row.selection.fresh_selectable() {
                let latest = latest_selectable
                    .get_mut(&release_id.package)
                    .expect("validated release package has a directory accumulator");
                if latest
                    .as_ref()
                    .is_none_or(|version| version < &release_id.version)
                {
                    *latest = Some(release_id.version.clone());
                }
            }
        }
        for (release_id, _) in releases.iter() {
            if resolver_index.get(release_id).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_resolver_index",
                    "release is missing its exact resolver row",
                ));
            }
        }
        for (selector, entry) in public_directory.iter() {
            entry.validate().map_err(|error| {
                invalid_musubi_state("musubi_public_directory", error.to_string())
            })?;
            let package = packages.get(&entry.package).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_public_directory",
                    "directory entry references a missing package",
                )
            })?;
            let expected_latest = latest_selectable
                .get(&entry.package)
                .expect("validated directory package has a latest-version accumulator");
            if selector != &entry.selector
                || entry.selector.namespace != package.claimed_namespace
                || entry.selector.name != entry.package.name
                || entry.metadata_revision != package.revisions.metadata
                || &entry.latest_selectable != expected_latest
                || entry.index_revision > self.resolver_index_revision
            {
                return Err(invalid_musubi_state(
                    "musubi_public_directory",
                    "directory entry diverges from its package and resolver rows",
                ));
            }
        }
        for (package_id, package) in packages.iter() {
            let selector = MusubiPackageSelectorV1 {
                namespace: package.claimed_namespace.clone(),
                name: package_id.name.clone(),
            };
            if public_directory.get(&selector).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_public_directory",
                    "package is missing its canonical public-directory entry",
                ));
            }
        }
        for (alias, record) in aliases.iter() {
            record
                .alias
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_aliases", error.to_string()))?;
            record
                .target
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_aliases", error.to_string()))?;
            if alias != &record.alias
                || packages.get(&record.target).is_none()
                || record.pricing_revision == 0
                || record.paid_xor == 0
                || record.registered_at_height == 0
                || record.history_revision == 0
            {
                return Err(invalid_musubi_state(
                    "musubi_aliases",
                    "alias record is intrinsically invalid or references a missing package",
                ));
            }
        }
        let mut histories = BTreeMap::<MusubiAliasNameV1, Vec<&MusubiAliasHistoryEntryV1>>::new();
        for (history_key, entry) in alias_history.iter() {
            entry
                .validate()
                .map_err(|error| invalid_musubi_state("musubi_alias_history", error.to_string()))?;
            if history_key != &entry.key() || aliases.get(&entry.alias).is_none() {
                return Err(invalid_musubi_state(
                    "musubi_alias_history",
                    "alias-history key or alias reference is inconsistent",
                ));
            }
            if packages.get(&entry.target).is_none()
                || entry
                    .previous_target
                    .as_ref()
                    .is_some_and(|target| packages.get(target).is_none())
            {
                return Err(invalid_musubi_state(
                    "musubi_alias_history",
                    "alias history references a missing package",
                ));
            }
            if entry
                .governance_action
                .is_some_and(|digest| !decision_actions.contains(&digest))
            {
                return Err(invalid_musubi_state(
                    "musubi_alias_history",
                    "alias retarget does not reference a retained governance decision",
                ));
            }
            histories
                .entry(entry.alias.clone())
                .or_default()
                .push(entry);
        }
        for (alias, record) in aliases.iter() {
            let entries = histories.get(alias).ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_alias_history",
                    "alias is missing its complete history",
                )
            })?;
            let expected_len = usize::try_from(record.history_revision).map_err(|_| {
                invalid_musubi_state(
                    "musubi_alias_history",
                    "alias history revision does not fit usize",
                )
            })?;
            if entries.len() != expected_len {
                return Err(invalid_musubi_state(
                    "musubi_alias_history",
                    "alias history revisions are not dense from one",
                ));
            }
            let mut previous_target = None;
            let mut previous_height = 0_u64;
            for (index, entry) in entries.iter().enumerate() {
                let expected_revision = u64::try_from(index + 1).map_err(|_| {
                    invalid_musubi_state(
                        "musubi_alias_history",
                        "alias history index overflows u64",
                    )
                })?;
                if entry.revision != expected_revision
                    || (index == 0 && entry.finalized_height != record.registered_at_height)
                    || (index > 0
                        && (entry.previous_target.as_ref() != previous_target.as_ref()
                            || previous_target.as_ref() == Some(&entry.target)
                            || entry.finalized_height < previous_height))
                {
                    return Err(invalid_musubi_state(
                        "musubi_alias_history",
                        "alias history has a gap or broken target chain",
                    ));
                }
                previous_target = Some(entry.target.clone());
                previous_height = entry.finalized_height;
            }
            if previous_target.as_ref() != Some(&record.target) {
                return Err(invalid_musubi_state(
                    "musubi_alias_history",
                    "alias history final target disagrees with the current alias",
                ));
            }
        }
        Ok(())
    }
}
fn validate_musubi_governance_provenance(world: &World) -> Result<(), json::Error> {
    let decisions = world.musubi_governance_decisions.view();
    let proposals = world.governance_proposals.view();
    let packages = world.musubi_packages.view();
    let package_members = world.musubi_package_members.view();
    let releases = world.musubi_releases.view();
    let aliases = world.musubi_aliases.view();
    let alias_history = world.musubi_alias_history.view();
    let registry_policy = world.musubi_registry_policy.view();
    let parliament_attempts = world.parliament_attempts.view();
    let mut actions_by_digest = BTreeMap::new();
    let mut policy_actions = Vec::new();
    let mut owner_recovery_revisions = BTreeSet::new();
    let mut owner_recovery_history: BTreeMap<MusubiPackageIdV1, Vec<(u64, u64)>> = BTreeMap::new();
    for (decision_id, consumption) in decisions.iter() {
        consumption.validate().map_err(|error| {
            invalid_musubi_state("musubi_governance_decisions", error.to_string())
        })?;
        let decision = &consumption.decision;
        let proposal = proposals.get(decision_id).ok_or_else(|| {
            invalid_musubi_state(
                "musubi_governance_decisions",
                "consumed Parliament decision has no retained governance proposal",
            )
        })?;
        let action = proposal.as_musubi_registry_governance().ok_or_else(|| {
            invalid_musubi_state(
                "musubi_governance_decisions",
                "consumed Parliament decision does not reference a Musubi action",
            )
        })?;
        action.validate().map_err(|error| {
            invalid_musubi_state("musubi_governance_decisions", error.to_string())
        })?;
        if decision.decision_id != *decision_id || proposal.kind.fingerprint() != *decision_id {
            return Err(invalid_musubi_state(
                "musubi_governance_decisions",
                "consumed Parliament decision key is not the exact typed proposal fingerprint",
            ));
        }
        if proposal.status != GovernanceProposalStatus::Enacted
            || action.action_digest() != decision.action_digest
        {
            return Err(invalid_musubi_state(
                "musubi_governance_decisions",
                "consumed Parliament decision disagrees with its enacted proposal",
            ));
        }
        let proposal_content_id =
            iroha_data_model::governance::types::ProposalContentId::new(*decision_id);
        let enacted_attempts =
            crate::governance::parliament::canonical_governance_attempt_ids_v1(proposal_content_id)
                .filter_map(|attempt_id| parliament_attempts.get(&attempt_id))
                .filter(|attempt| {
                    attempt.attempt().status
                        == iroha_data_model::governance::types::GovernanceAttemptStatusV1::Enacted
                        && attempt.terminal_height() == Some(decision.enacted_at_height)
                        && attempt.certificate().is_some_and(|certificate| {
                            certificate.proposal_content_id == proposal_content_id
                                && certificate.enact_at_height == decision.enacted_at_height
                        })
                })
                .count();
        if enacted_attempts != 1 {
            return Err(invalid_musubi_state(
                "musubi_governance_decisions",
                "consumed Parliament decision has no unique enacted attempt at its claimed height",
            ));
        }
        if actions_by_digest
            .insert(decision.action_digest, (action, consumption))
            .is_some()
        {
            return Err(invalid_musubi_state(
                "musubi_governance_decisions",
                "the same Parliament action was consumed more than once",
            ));
        }
        if let iroha_data_model::musubi::MusubiParliamentActionV1::SetRegistryPolicy(replacement) =
            action
        {
            policy_actions.push((replacement, consumption.consumed_at_height));
        }
    }
    policy_actions.sort_by_key(|(replacement, _)| replacement.policy.revision);
    let mut reconstructed_policy = MusubiRegistryPolicyV1::default();
    let mut previous_policy_consumed_at = None;
    let mut pricing_policies = BTreeMap::new();
    pricing_policies.insert(
        reconstructed_policy.alias_pricing.revision,
        reconstructed_policy.alias_pricing,
    );
    for (replacement, consumed_at_height) in policy_actions {
        if previous_policy_consumed_at.is_some_and(|previous| consumed_at_height < previous) {
            return Err(invalid_musubi_state(
                "musubi_registry_policy",
                "policy decision consumption heights do not follow policy revision order",
            ));
        }
        previous_policy_consumed_at = Some(consumed_at_height);
        if replacement.expected_revision != reconstructed_policy.revision {
            return Err(invalid_musubi_state(
                "musubi_registry_policy",
                "retained policy decisions do not form one dense revision history",
            ));
        }
        replacement
            .policy
            .validate_successor(&reconstructed_policy)
            .map_err(|error| invalid_musubi_state("musubi_registry_policy", error.to_string()))?;
        if pricing_policies
            .insert(
                replacement.policy.alias_pricing.revision,
                replacement.policy.alias_pricing,
            )
            .is_some_and(|previous| previous != replacement.policy.alias_pricing)
        {
            return Err(invalid_musubi_state(
                "musubi_registry_policy",
                "a pricing revision was reused for different alias prices",
            ));
        }
        reconstructed_policy = replacement.policy.clone();
    }
    if registry_policy.get() != &reconstructed_policy {
        return Err(invalid_musubi_state(
            "musubi_registry_policy",
            "current policy is not the exact result of retained Parliament decisions",
        ));
    }
    for (_, alias) in aliases.iter() {
        let pricing = pricing_policies
            .get(&alias.pricing_revision)
            .ok_or_else(|| {
                invalid_musubi_state(
                    "musubi_aliases",
                    "alias references an unknown historical pricing revision",
                )
            })?;
        alias
            .validate(pricing)
            .map_err(|error| invalid_musubi_state("musubi_aliases", error.to_string()))?;
    }
    for (action, consumption) in actions_by_digest.values().copied() {
        let digest = action.action_digest();
        match action {
            iroha_data_model::musubi::MusubiParliamentActionV1::RecoverPackageOwners(recovery) => {
                let resulting_revision =
                    recovery.expected_revision.checked_add(1).ok_or_else(|| {
                        invalid_musubi_state(
                            "musubi_governance_decisions",
                            "owner-recovery governance result revision overflows",
                        )
                    })?;
                if !owner_recovery_revisions.insert((recovery.package.clone(), resulting_revision))
                {
                    return Err(invalid_musubi_state(
                        "musubi_governance_decisions",
                        "more than one owner recovery targets the same package result revision",
                    ));
                }
                owner_recovery_history
                    .entry(recovery.package.clone())
                    .or_default()
                    .push((resulting_revision, consumption.consumed_at_height));
                let package = packages.get(&recovery.package).ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_governance_decisions",
                        "owner-recovery action references a missing package",
                    )
                })?;
                if package.revisions.governance < resulting_revision {
                    return Err(invalid_musubi_state(
                        "musubi_governance_decisions",
                        "owner-recovery action has no persisted governance revision effect",
                    ));
                }
                if package.revisions.governance == resulting_revision {
                    if package.owners.as_slice() != recovery.owners.as_slice() {
                        return Err(invalid_musubi_state(
                            "musubi_governance_decisions",
                            "current owner-recovery projection does not contain the exact enacted owners",
                        ));
                    }
                    for owner in &recovery.owners {
                        let key =
                            MusubiPackageMemberKeyV1::new(recovery.package.clone(), owner.clone());
                        let member = package_members.get(&key).ok_or_else(|| {
                            invalid_musubi_state(
                                "musubi_package_members",
                                "current recovered owner has no exact member projection",
                            )
                        })?;
                        if member.role != MusubiPackageRoleV1::Owner
                            || member.governance_revision != resulting_revision
                            || member.accepted_at_height != consumption.consumed_at_height
                        {
                            return Err(invalid_musubi_state(
                                "musubi_package_members",
                                "current owner-recovery projection disagrees with its decision consumption height",
                            ));
                        }
                    }
                }
            }
            iroha_data_model::musubi::MusubiParliamentActionV1::RetargetAlias(retarget) => {
                let revision = retarget.expected_revision.checked_add(1).ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_alias_history",
                        "alias-retarget revision overflows",
                    )
                })?;
                let key = MusubiAliasHistoryKeyV1::new(retarget.alias.clone(), revision);
                let entry = alias_history.get(&key).ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_alias_history",
                        "alias-retarget action has no exact persisted history entry",
                    )
                })?;
                if entry.target != retarget.target
                    || entry.governance_action != Some(digest)
                    || entry.finalized_height != consumption.consumed_at_height
                {
                    return Err(invalid_musubi_state(
                        "musubi_alias_history",
                        "alias-retarget history does not match the enacted action and decision consumption height",
                    ));
                }
            }
            iroha_data_model::musubi::MusubiParliamentActionV1::TakedownArtifact(takedown) => {
                let release = releases.get(&takedown.release).ok_or_else(|| {
                    invalid_musubi_state(
                        "musubi_releases",
                        "artifact-takedown action references a missing release",
                    )
                })?;
                let expected_revision = takedown
                    .expected_artifact_governance_revision
                    .checked_add(1);
                let iroha_data_model::musubi::MusubiArtifactGovernanceStateV1::TakenDown(persisted) =
                    &release.artifact_governance
                else {
                    return Err(invalid_musubi_state(
                        "musubi_releases",
                        "artifact-takedown action has no persisted takedown state",
                    ));
                };
                if persisted.action_digest != digest
                    || persisted.reason != takedown.reason
                    || persisted.applied_at_height != consumption.consumed_at_height
                    || expected_revision != Some(release.revisions.artifact_governance)
                {
                    return Err(invalid_musubi_state(
                        "musubi_releases",
                        "artifact-takedown state does not match the enacted action and decision consumption height",
                    ));
                }
            }
            iroha_data_model::musubi::MusubiParliamentActionV1::SetRegistryPolicy(_) => {}
        }
    }
    for (_, mut history) in owner_recovery_history {
        history.sort_by_key(|(revision, _)| *revision);
        let mut previous_consumed_at = None;
        for (_, consumed_at_height) in history {
            if previous_consumed_at.is_some_and(|previous| consumed_at_height < previous) {
                return Err(invalid_musubi_state(
                    "musubi_governance_decisions",
                    "owner-recovery decision consumption heights do not follow governance revision order",
                ));
            }
            previous_consumed_at = Some(consumed_at_height);
        }
    }
    Ok(())
}
fn invalid_global_beacon_persistence(message: impl Into<String>) -> json::Error {
    json::Error::InvalidField {
        field: "world.global_beacon".to_owned(),
        message: message.into(),
    }
}

fn validate_global_beacon_persistence(world: &World) -> Result<(), json::Error> {
    let dkg = world.global_beacon_dkg.view();
    let key_sessions = world.global_beacon_key_sessions.view();
    let active_sessions = world.global_beacon_active_session.view();
    let latest_pulses = world.global_beacon_latest_pulse.view();
    let pulses = world.global_beacon_pulses.view();
    let pulse_slots = world.global_beacon_pulse_slots.view();

    for (session_id, snapshot) in dkg.iter() {
        snapshot.validate().map_err(|error| {
            invalid_global_beacon_persistence(format!(
                "invalid active DKG snapshot {}: {error}",
                hex::encode(session_id)
            ))
        })?;
        if session_id != &snapshot.session.session_id {
            return Err(invalid_global_beacon_persistence(
                "active DKG storage key differs from its embedded session id",
            ));
        }
        if key_sessions.get(session_id).is_some() {
            return Err(invalid_global_beacon_persistence(
                "one beacon session is both active DKG and finalized",
            ));
        }
    }

    for (key, _) in active_sessions.iter() {
        if *key != GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY {
            return Err(invalid_global_beacon_persistence(
                "active-session pointer uses a noncanonical singleton key",
            ));
        }
    }
    for (key, _) in latest_pulses.iter() {
        if *key != GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY {
            return Err(invalid_global_beacon_persistence(
                "latest-pulse link uses a noncanonical singleton key",
            ));
        }
    }
    let active_session = active_sessions
        .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
        .copied();
    for (session_id, record) in key_sessions.iter() {
        record.validate().map_err(|error| {
            invalid_global_beacon_persistence(format!(
                "invalid finalized key session {}: {error}",
                hex::encode(session_id)
            ))
        })?;
        if session_id != &record.session.session_id {
            return Err(invalid_global_beacon_persistence(
                "finalized key storage key differs from its embedded session id",
            ));
        }
        let lifecycle_is_live =
            record.activated_at_height.is_some() && record.retired_at_height.is_none();
        if lifecycle_is_live != (active_session == Some(*session_id)) {
            return Err(invalid_global_beacon_persistence(
                "active-session pointer and key lifecycle metadata disagree",
            ));
        }
    }
    if active_session.is_some_and(|session_id| key_sessions.get(&session_id).is_none()) {
        return Err(invalid_global_beacon_persistence(
            "active-session pointer references a missing finalized key",
        ));
    }

    let mut ordered_pulses = Vec::with_capacity(pulses.len());
    if pulse_slots.len() != pulses.len() {
        return Err(invalid_global_beacon_persistence(
            "derived pulse-slot index cardinality differs from finalized history",
        ));
    }
    for (pulse_id, pulse) in pulses.iter() {
        let link = validate_persisted_global_threshold_beacon_pulse_v1(pulse).map_err(|error| {
            invalid_global_beacon_persistence(format!(
                "invalid finalized pulse {}: {error}",
                hex::encode(pulse_id)
            ))
        })?;
        if pulse_id != &pulse.pulse_id || pulse_id != &link.pulse_id {
            return Err(invalid_global_beacon_persistence(
                "pulse storage key differs from its canonical pulse id",
            ));
        }
        let logical_session =
            iroha_data_model::governance::types::BeaconSessionId::for_network_v1(&pulse.network_id);
        if pulse_slots.get(&(logical_session, pulse.height)) != Some(pulse_id) {
            return Err(invalid_global_beacon_persistence(
                "derived pulse-slot index differs from finalized history",
            ));
        }
        let key_session = key_sessions.get(&pulse.session_id).ok_or_else(|| {
            invalid_global_beacon_persistence("pulse references a missing finalized key session")
        })?;
        if !key_session.is_active_at(pulse.height)
            || pulse.network_id != key_session.session.network_id
            || pulse.roster_hash != key_session.session.roster_hash
            || pulse.transcript_hash != key_session.session.transcript_hash
        {
            return Err(invalid_global_beacon_persistence(
                "pulse is outside its key lifecycle or immutable session binding",
            ));
        }
        ordered_pulses.push(pulse);
    }
    ordered_pulses.sort_by_key(|pulse| (pulse.height, pulse.round, pulse.pulse_id));
    for pair in ordered_pulses.windows(2) {
        let previous = pair[0];
        let current = pair[1];
        if (current.height, current.round) <= (previous.height, previous.round) {
            return Err(invalid_global_beacon_persistence(
                "finalized pulse history is not strictly monotonic",
            ));
        }
    }
    let unavailable_beacon_pulse_slots = world
        .parliament_attempts
        .view()
        .iter()
        .flat_map(|(_, attempt)| attempt.unavailable_beacon_pulse_slots_v1())
        .collect::<BTreeSet<_>>();
    for (_, pulse) in pulses.iter() {
        let logical_session =
            iroha_data_model::governance::types::BeaconSessionId::for_network_v1(&pulse.network_id);
        if unavailable_beacon_pulse_slots.contains(&(logical_session, pulse.height)) {
            return Err(invalid_global_beacon_persistence(
                "finalized pulse conflicts with a Parliament slot terminally classified as unavailable",
            ));
        }
    }

    let latest = latest_pulses
        .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
        .copied();
    match ordered_pulses.last() {
        Some(last) => {
            let expected = GlobalThresholdBeaconPulseLinkV1 {
                pulse_id: last.pulse_id,
                seed: last.seed,
                height: last.height,
                round: last.round,
            };
            if latest != Some(expected) {
                return Err(invalid_global_beacon_persistence(
                    "latest-pulse link does not name the history tail",
                ));
            }
        }
        None => {
            if let Some(origin) = latest {
                origin.validate_origin().map_err(|error| {
                    invalid_global_beacon_persistence(format!(
                        "invalid genesis beacon origin: {error}"
                    ))
                })?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod global_beacon_persistence_tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        governance::types::{BodyElectionAttemptId, ParliamentBody},
    };
    use iroha_model_base::peer::PeerId;

    #[test]
    fn restore_rejects_pulse_after_sortition_slot_was_terminally_unavailable() {
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xC1; 32])),
        );
        let (key_record, pulse) =
            crate::beacon::signed_persisted_pulse_fixture_for_world(network_id, 41, &budget);
        let roster = (1_u8..=4)
            .map(|marker| {
                KeyPair::try_from_seed(vec![marker; 32], Algorithm::Ed25519)
                    .map(|key| PeerId::new(key.public_key().clone()))
                    .expect("derive deterministic Parliament candidate")
            })
            .collect::<Vec<_>>();
        let (governance_attempt_id, _, mut attempt) =
            crate::beacon::tests::pending_batched_sortition_attempt(
                &network_id,
                &roster,
                pulse.height,
            );
        let election_attempt_id = BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            ParliamentBody::RulesCommittee,
            0,
        );
        attempt
            .fail_body_election_no_roster(
                governance_attempt_id,
                election_attempt_id,
                false,
                pulse.height + 1,
            )
            .expect("terminally classify the missing sortition slot");

        let link = validate_persisted_global_threshold_beacon_pulse_v1(&pulse)
            .expect("canonical persisted pulse link");
        let mut world = World::new();
        world
            .global_beacon_key_sessions
            .insert(pulse.session_id, key_record);
        world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, pulse.session_id);
        world.global_beacon_pulses.insert(pulse.pulse_id, pulse);
        world.global_beacon_pulse_slots.insert(
            (
                iroha_data_model::governance::types::BeaconSessionId::for_network_v1(
                    &pulse.network_id,
                ),
                pulse.height,
            ),
            pulse.pulse_id,
        );
        world
            .global_beacon_latest_pulse
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, link);
        world
            .parliament_attempts
            .insert(governance_attempt_id, attempt);

        let error = validate_global_beacon_persistence(&world)
            .expect_err("restart must reject a pulse contradicting terminal Parliament state");
        assert!(
            error.to_string().contains("terminally classified"),
            "unexpected restore rejection: {error}"
        );
    }
}

fn invalid_tle_ovn_persistence(field: &'static str, message: impl Into<String>) -> json::Error {
    json::Error::InvalidField {
        field: field.to_owned(),
        message: message.into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistedTimedOvnPhaseV1 {
    Registered,
    RegistrationClosed,
    SurvivorsFrozen,
    Sealed,
    Released,
}

fn persisted_timed_ovn_phase_v1(lifecycle: &TimedOvnLifecycleStateV1) -> PersistedTimedOvnPhaseV1 {
    match lifecycle {
        TimedOvnLifecycleStateV1::Registered(_) => PersistedTimedOvnPhaseV1::Registered,
        TimedOvnLifecycleStateV1::RegistrationClosed(_) => {
            PersistedTimedOvnPhaseV1::RegistrationClosed
        }
        TimedOvnLifecycleStateV1::SurvivorsFrozen(_) | TimedOvnLifecycleStateV1::CorpusOpen(_) => {
            PersistedTimedOvnPhaseV1::SurvivorsFrozen
        }
        TimedOvnLifecycleStateV1::Sealed(_) => PersistedTimedOvnPhaseV1::Sealed,
        TimedOvnLifecycleStateV1::Released(_) => PersistedTimedOvnPhaseV1::Released,
    }
}

fn timed_ovn_phase_matches_ballot_status_v1(
    status: iroha_data_model::governance::types::BallotAttemptStatusV1,
    failure_kind: Option<iroha_data_model::governance::types::ParliamentBallotFailureKindV1>,
    phase: PersistedTimedOvnPhaseV1,
) -> bool {
    use iroha_data_model::governance::types::BallotAttemptStatusV1 as BallotStatus;
    use iroha_data_model::governance::types::ParliamentBallotFailureKindV1 as FailureKind;
    match (status, failure_kind) {
        (BallotStatus::Registration, None) => phase == PersistedTimedOvnPhaseV1::Registered,
        (BallotStatus::SurvivorFreeze, None) => {
            phase == PersistedTimedOvnPhaseV1::RegistrationClosed
        }
        (BallotStatus::TimedCommitment, None) => phase == PersistedTimedOvnPhaseV1::SurvivorsFrozen,
        (BallotStatus::AwaitingRelease | BallotStatus::Opening, None) => {
            phase == PersistedTimedOvnPhaseV1::Sealed
        }
        (BallotStatus::Finalized, None) => phase == PersistedTimedOvnPhaseV1::Released,
        (
            BallotStatus::NoResult | BallotStatus::Superseded,
            Some(FailureKind::RegistrationDeadlineExpired),
        ) => phase == PersistedTimedOvnPhaseV1::Registered,
        (
            BallotStatus::NoResult | BallotStatus::Superseded,
            Some(FailureKind::SurvivorDeadlineExpired),
        ) => phase == PersistedTimedOvnPhaseV1::RegistrationClosed,
        (
            BallotStatus::NoResult | BallotStatus::Superseded,
            Some(FailureKind::CommitmentDeadlineExpired),
        ) => phase == PersistedTimedOvnPhaseV1::SurvivorsFrozen,
        (
            BallotStatus::NoResult | BallotStatus::Superseded,
            Some(FailureKind::ReleasePulseUnavailable | FailureKind::OpeningDeadlineExpired),
        ) => phase == PersistedTimedOvnPhaseV1::Sealed,
        (
            BallotStatus::NoResult,
            Some(
                FailureKind::ConfirmationJuryCapacityUnavailable
                | FailureKind::RandomnessRedrawBudgetExhausted,
            ),
        ) => phase == PersistedTimedOvnPhaseV1::Released,
        _ => false,
    }
}

fn validate_tle_ovn_persistence(world: &World) -> Result<(), json::Error> {
    let mut validated_key_sessions = BTreeMap::new();
    let parliament_attempts = world.parliament_attempts.view();
    let timed_ovn_evidence = world.timed_ovn_evidence.view();
    let tle_key_session_rosters = world.tle_key_session_rosters.view();
    let tle_key_session_lifecycles = world.tle_key_session_lifecycles.view();
    let finalized_beacon_heights = world
        .global_beacon_pulses
        .view()
        .iter()
        .map(|(_, pulse)| pulse.height)
        .collect::<BTreeSet<_>>();
    for (key_session_id, public_state) in world.tle_key_sessions.view().iter() {
        if key_session_id != &public_state.key_session_id {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_sessions",
                "TLE key-session storage key differs from its embedded canonical id",
            ));
        }
        let validated = public_state.clone().validate().map_err(|error| {
            invalid_tle_ovn_persistence(
                "tle_key_sessions",
                format!("invalid persisted adaptive TLE key session {key_session_id}: {error}"),
            )
        })?;
        let ordered_roster = tle_key_session_rosters.get(key_session_id).ok_or_else(|| {
            invalid_tle_ovn_persistence(
                "tle_key_session_rosters",
                format!("TLE key session {key_session_id} is missing its frozen ordered roster"),
            )
        })?;
        validate_tle_key_session_roster_binding_v1(public_state, ordered_roster).map_err(|_| {
            invalid_tle_ovn_persistence(
                "tle_key_session_rosters",
                format!(
                    "TLE key session {key_session_id} has an invalid frozen ordered roster binding"
                ),
            )
        })?;
        let lifecycle = tle_key_session_lifecycles
            .get(key_session_id)
            .copied()
            .ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "tle_key_session_lifecycles",
                    format!("TLE key session {key_session_id} is missing lifecycle metadata"),
                )
            })?
            .validate()
            .map_err(|error| {
                invalid_tle_ovn_persistence(
                    "tle_key_session_lifecycles",
                    format!("invalid TLE key-session lifecycle {key_session_id}: {error}"),
                )
            })?;
        if lifecycle.key_session_id != *key_session_id {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_session_lifecycles",
                "TLE lifecycle storage key differs from its embedded session id",
            ));
        }
        validated_key_sessions.insert(*key_session_id, validated);
    }
    for (key_session_id, _) in tle_key_session_rosters.iter() {
        if !validated_key_sessions.contains_key(key_session_id) {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_session_rosters",
                format!(
                    "frozen ordered roster references missing TLE key session {key_session_id}"
                ),
            ));
        }
    }
    for (key_session_id, _) in tle_key_session_lifecycles.iter() {
        if !validated_key_sessions.contains_key(key_session_id) {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_session_lifecycles",
                format!(
                    "TLE lifecycle metadata references missing public session {key_session_id}"
                ),
            ));
        }
    }
    let mut lifecycle_rows = tle_key_session_lifecycles.iter().collect::<Vec<_>>();
    lifecycle_rows.sort_by(|(left_id, left), (right_id, right)| {
        left.activation_height
            .cmp(&right.activation_height)
            .then_with(|| left_id.cmp(right_id))
    });
    for adjacent in lifecycle_rows.windows(2) {
        let (_, left) = adjacent[0];
        let (_, right) = adjacent[1];
        if right.activation_height <= left.selectable_through_height {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_session_lifecycles",
                "TLE key-session new-ballot selection intervals overlap",
            ));
        }
    }
    let active_tle_sessions = world.tle_active_key_session.view();
    let mut active_key_session_id = None;
    for (key, key_session_id) in active_tle_sessions.iter() {
        if *key != TLE_KEY_SESSION_SINGLETON_KEY {
            return Err(invalid_tle_ovn_persistence(
                "tle_active_key_session",
                "active TLE session pointer uses a noncanonical singleton key",
            ));
        }
        if !validated_key_sessions.contains_key(key_session_id)
            || tle_key_session_lifecycles.get(key_session_id).is_none()
        {
            return Err(invalid_tle_ovn_persistence(
                "tle_active_key_session",
                "active TLE session pointer references a missing or invalid public session",
            ));
        }
        if active_key_session_id.replace(*key_session_id).is_some() {
            return Err(invalid_tle_ovn_persistence(
                "tle_active_key_session",
                "multiple active TLE session pointers are persisted",
            ));
        }
    }
    let ordered_lifecycles = lifecycle_rows
        .iter()
        .map(|(_, lifecycle)| **lifecycle)
        .collect::<Vec<_>>();
    validate_tle_key_session_lifecycle_head_v1(&ordered_lifecycles, active_key_session_id)
        .map_err(|message| invalid_tle_ovn_persistence("tle_active_key_session", message))?;

    for (ballot_attempt_id, lifecycle) in timed_ovn_evidence.iter() {
        if ballot_attempt_id.as_bytes() != &lifecycle.ballot_attempt_id() {
            return Err(invalid_tle_ovn_persistence(
                "timed_ovn_evidence",
                "timed-OVN storage key differs from its embedded ballot-attempt id",
            ));
        }
        let key_session = validated_key_sessions
            .get(&lifecycle.tle_key_session_id())
            .ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "timed-OVN lifecycle references a missing TLE key session",
                )
            })?;
        let (lifecycle_binding, registered_participant_hashes) = lifecycle
            .validated_parliament_reducer_binding(key_session)
            .map_err(|error| {
                invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    format!("invalid persisted timed-OVN lifecycle {ballot_attempt_id}: {error}"),
                )
            })?;

        let session = lifecycle.session();
        if session.parameter_hash != crate::governance::timed_ovn::timed_ovn_parameter_hash_v1() {
            return Err(invalid_tle_ovn_persistence(
                "timed_ovn_evidence",
                "timed-OVN lifecycle does not use the fixed v1 parameter profile",
            ));
        }
        let governance_attempt_id = iroha_data_model::governance::types::GovernanceAttemptId::new(
            session.governance_attempt_id,
        );
        let governance_attempt =
            parliament_attempts
                .get(&governance_attempt_id)
                .ok_or_else(|| {
                    invalid_tle_ovn_persistence(
                        "timed_ovn_evidence",
                        "timed-OVN lifecycle references a missing Parliament attempt",
                    )
                })?;
        let ballot = governance_attempt
            .ballot(ballot_attempt_id)
            .ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "timed-OVN lifecycle references a missing Parliament ballot attempt",
                )
            })?;
        if !governance_attempt
            .timed_ovn_reducer_binding_matches(ballot_attempt_id, &lifecycle_binding)
        {
            return Err(invalid_tle_ovn_persistence(
                "timed_ovn_evidence",
                "timed-OVN lifecycle bindings differ from the Parliament reducer",
            ));
        }
        let body = governance_attempt
            .body(&ballot.attempt().body_instance_id)
            .ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "timed-OVN ballot references a missing sealed Parliament body",
                )
            })?;
        let eligible_participant_hashes = body
            .assignments()
            .iter()
            .filter(|assignment| {
                !body
                    .excluded_assignments()
                    .contains(&assignment.assignment_id)
            })
            .map(|assignment| {
                iroha_data_model::governance::types::parliament_ballot_participant_hash_v1(
                    *ballot_attempt_id,
                    &assignment.member,
                )
            })
            .collect::<BTreeSet<_>>();
        if registered_participant_hashes
            .iter()
            .any(|participant_hash| !eligible_participant_hashes.contains(participant_hash))
        {
            return Err(invalid_tle_ovn_persistence(
                "timed_ovn_evidence",
                "timed-OVN registration corpus is not the authenticated nonexcluded body-member subset",
            ));
        }
    }

    let mut active_resource_reservations = Vec::new();
    for (governance_attempt_id, governance_attempt) in parliament_attempts.iter() {
        if governance_attempt.attempt().status
            != iroha_data_model::governance::types::GovernanceAttemptStatusV1::Active
        {
            continue;
        }
        for (ballot_attempt_id, ballot) in governance_attempt.ballot_attempts() {
            if matches!(
                ballot.attempt().status,
                iroha_data_model::governance::types::BallotAttemptStatusV1::Finalized
                    | iroha_data_model::governance::types::BallotAttemptStatusV1::NoResult
                    | iroha_data_model::governance::types::BallotAttemptStatusV1::Superseded
            ) || governance_attempt
                .active_ballot_for_body(&ballot.attempt().body_instance_id)
                .is_none_or(|active| active.attempt().id != *ballot_attempt_id)
                || governance_attempt
                    .body(&ballot.attempt().body_instance_id)
                    .is_none_or(|body| {
                        body.instance().status
                            != iroha_data_model::governance::types::BodyInstanceStatusV1::Balloting
                    })
            {
                continue;
            }
            let release_height = ballot.release_height().ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "parliament_attempts",
                    "active timed-OVN ballot is missing its release height",
                )
            })?;
            active_resource_reservations.push((
                *governance_attempt_id,
                *ballot_attempt_id,
                [
                    (
                        ballot.registered_at_height(),
                        ballot.commitment_close_height(),
                    ),
                    (release_height, ballot.opening_deadline_height()),
                ],
            ));
        }
    }
    for left_index in 0..active_resource_reservations.len() {
        for right_index in left_index + 1..active_resource_reservations.len() {
            let (left_attempt, left_ballot, left_windows) =
                active_resource_reservations[left_index];
            let (right_attempt, right_ballot, right_windows) =
                active_resource_reservations[right_index];
            if super::parliament_timed_ovn_resource_windows_overlap_v1(left_windows, right_windows)
            {
                return Err(invalid_tle_ovn_persistence(
                    "parliament_attempts",
                    format!(
                        "active timed-OVN resource reservations overlap between {left_attempt:?}/{left_ballot:?} and {right_attempt:?}/{right_ballot:?}"
                    ),
                ));
            }
        }
    }

    let concurrent_casting_contexts = timed_ovn_evidence
        .iter()
        .filter(|(ballot_attempt_id, lifecycle)| {
            let phase = persisted_timed_ovn_phase_v1(lifecycle);
            if !matches!(
                phase,
                PersistedTimedOvnPhaseV1::Registered
                    | PersistedTimedOvnPhaseV1::RegistrationClosed
                    | PersistedTimedOvnPhaseV1::SurvivorsFrozen
            ) {
                return false;
            }
            let governance_attempt_id =
                iroha_data_model::governance::types::GovernanceAttemptId::new(
                    lifecycle.session().governance_attempt_id,
                );
            let Some(attempt) = parliament_attempts.get(&governance_attempt_id) else {
                return false;
            };
            if attempt.attempt().status
                != iroha_data_model::governance::types::GovernanceAttemptStatusV1::Active
            {
                return false;
            }
            let Some(ballot) = attempt.ballot(ballot_attempt_id) else {
                return false;
            };
            let Some(body) = attempt.body(&ballot.attempt().body_instance_id) else {
                return false;
            };
            body.instance().status
                == iroha_data_model::governance::types::BodyInstanceStatusV1::Balloting
                && attempt
                    .active_ballot_for_body(&ballot.attempt().body_instance_id)
                    .is_some_and(|active| active.attempt().id == **ballot_attempt_id)
                && timed_ovn_phase_matches_ballot_status_v1(
                    ballot.attempt().status,
                    ballot.failure_kind(),
                    phase,
                )
        })
        .count();
    let maximum_casting_contexts = usize::try_from(
        iroha_data_model::parliament_casting::MAX_PARLIAMENT_CONCURRENT_CASTING_CONTEXTS_V1,
    )
    .expect("u32 casting-context bound fits usize");
    if concurrent_casting_contexts > maximum_casting_contexts {
        return Err(invalid_tle_ovn_persistence(
            "timed_ovn_evidence",
            "concurrent cast-capable timed-OVN contexts exceed the protocol maximum",
        ));
    }

    for (governance_attempt_id, governance_attempt) in parliament_attempts.iter() {
        for (ballot_attempt_id, ballot) in governance_attempt.ballot_attempts() {
            if ballot.failure_kind()
                == Some(
                    iroha_data_model::governance::types::ParliamentBallotFailureKindV1::ReleasePulseUnavailable,
                )
            {
                ballot.release_beacon_session_id().ok_or_else(|| {
                    invalid_tle_ovn_persistence(
                        "parliament_attempts",
                        "release-pulse failure is missing its committed beacon session",
                    )
                })?;
                let release_height = ballot.release_height().ok_or_else(|| {
                    invalid_tle_ovn_persistence(
                        "parliament_attempts",
                        "release-pulse failure is missing its committed height",
                    )
                })?;
                if finalized_beacon_heights.contains(&release_height) {
                    return Err(invalid_tle_ovn_persistence(
                        "parliament_attempts",
                        "release-pulse failure conflicts with an authoritative finalized pulse",
                    ));
                }
            }
            let lifecycle = timed_ovn_evidence.get(ballot_attempt_id).ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "Parliament ballot attempt is missing its authoritative timed-OVN lifecycle",
                )
            })?;
            if lifecycle.session().governance_attempt_id != *governance_attempt_id.as_bytes() {
                return Err(invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "timed-OVN lifecycle belongs to a different Parliament attempt",
                ));
            }
            if !timed_ovn_phase_matches_ballot_status_v1(
                ballot.attempt().status,
                ballot.failure_kind(),
                persisted_timed_ovn_phase_v1(lifecycle),
            ) {
                return Err(invalid_tle_ovn_persistence(
                    "timed_ovn_evidence",
                    "Parliament ballot phase disagrees with its timed-OVN lifecycle",
                ));
            }
        }
    }
    let mut counted_fresh_ballots = BTreeMap::<_, u32>::new();
    for (_, governance_attempt) in parliament_attempts.iter() {
        for (_, ballot) in governance_attempt.ballot_attempts() {
            let Some(key_session_id) = ballot.tle_key_session_id() else {
                continue;
            };
            let lifecycle = tle_key_session_lifecycles
                .get(&key_session_id)
                .ok_or_else(|| {
                    invalid_tle_ovn_persistence(
                        "parliament_attempts",
                        "Parliament ballot references missing TLE lifecycle metadata",
                    )
                })?;
            if !(lifecycle.activation_height..=lifecycle.selectable_through_height)
                .contains(&ballot.registered_at_height())
            {
                return Err(invalid_tle_ovn_persistence(
                    "parliament_attempts",
                    "Parliament ballot was registered outside its TLE session selection interval",
                ));
            }
            let count = counted_fresh_ballots.entry(key_session_id).or_insert(0);
            *count = count.checked_add(1).ok_or_else(|| {
                invalid_tle_ovn_persistence(
                    "parliament_attempts",
                    "TLE fresh-ballot use count overflowed",
                )
            })?;
        }
    }
    for (key_session_id, lifecycle) in tle_key_session_lifecycles.iter() {
        if lifecycle.fresh_ballot_uses
            != counted_fresh_ballots
                .get(key_session_id)
                .copied()
                .unwrap_or(0)
        {
            return Err(invalid_tle_ovn_persistence(
                "tle_key_session_lifecycles",
                format!(
                    "TLE key session {key_session_id} fresh-ballot counter disagrees with committed Parliament history"
                ),
            ));
        }
    }
    Ok(())
}

fn validate_tle_ovn_snapshot_network_v1(
    world: &World,
    expected_network_id: &iroha_data_model::NetworkId,
) -> Result<(), String> {
    let expected_network_binding = *expected_network_id.as_bytes();
    for (key_session_id, key_session) in world.tle_key_sessions.view().iter() {
        if key_session.network_id != expected_network_binding {
            return Err(format!(
                "restored TLE key session {key_session_id:?} belongs to a different exact NetworkId"
            ));
        }
    }
    for (ballot_attempt_id, lifecycle) in world.timed_ovn_evidence.view().iter() {
        if lifecycle.session().network_id != expected_network_binding {
            return Err(format!(
                "restored timed-OVN lifecycle {ballot_attempt_id:?} belongs to a different exact NetworkId"
            ));
        }
    }
    Ok(())
}

fn validate_parliament_attempt_encoded_size_bounds_v1(world: &World) -> Result<(), json::Error> {
    let parliament_attempts_view = world.parliament_attempts.view();
    for (attempt_id, attempt) in parliament_attempts_view.iter() {
        attempt
            .validate_encoded_size_v1()
            .map_err(|error| json::Error::InvalidField {
                field: "parliament_attempts".into(),
                message: format!(
                    "persisted Parliament attempt {attempt_id:?} violates the authoritative encoded-size bound: {error}"
                ),
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod timed_ovn_persistence_phase_tests {
    use super::*;
    use crate::{
        governance::timed_ovn::{
            TimedOvnLifecycleStateV1, TimedOvnSessionPublicV1, timed_ovn_parameter_hash_v1,
        },
        tle_release::tests::public_key_session_fixture_for_context_v1,
    };
    use iroha_data_model::governance::types::{
        BallotAttemptStatusV1 as BallotStatus, ParliamentBallotFailureKindV1 as FailureKind,
    };

    #[test]
    fn ballot_status_accepts_only_its_authoritative_timed_ovn_phase() {
        use PersistedTimedOvnPhaseV1 as Phase;

        let phases = [
            Phase::Registered,
            Phase::RegistrationClosed,
            Phase::SurvivorsFrozen,
            Phase::Sealed,
            Phase::Released,
        ];
        let exact = [
            (BallotStatus::Registration, Phase::Registered),
            (BallotStatus::SurvivorFreeze, Phase::RegistrationClosed),
            (BallotStatus::TimedCommitment, Phase::SurvivorsFrozen),
            (BallotStatus::AwaitingRelease, Phase::Sealed),
            (BallotStatus::Opening, Phase::Sealed),
            (BallotStatus::Finalized, Phase::Released),
        ];
        for (status, expected) in exact {
            for phase in phases {
                assert_eq!(
                    timed_ovn_phase_matches_ballot_status_v1(status, None, phase),
                    phase == expected,
                    "status {status:?}, phase {phase:?}"
                );
            }
        }
        let terminal = [
            (FailureKind::RegistrationDeadlineExpired, Phase::Registered),
            (
                FailureKind::SurvivorDeadlineExpired,
                Phase::RegistrationClosed,
            ),
            (
                FailureKind::CommitmentDeadlineExpired,
                Phase::SurvivorsFrozen,
            ),
            (FailureKind::ReleasePulseUnavailable, Phase::Sealed),
            (FailureKind::OpeningDeadlineExpired, Phase::Sealed),
        ];
        for status in [BallotStatus::NoResult, BallotStatus::Superseded] {
            assert!(
                phases
                    .into_iter()
                    .all(|phase| !timed_ovn_phase_matches_ballot_status_v1(status, None, phase)),
                "terminal status without a derived failure must fail closed"
            );
            for (failure_kind, expected) in terminal {
                for phase in phases {
                    assert_eq!(
                        timed_ovn_phase_matches_ballot_status_v1(status, Some(failure_kind), phase,),
                        phase == expected,
                        "terminal status {status:?}, failure {failure_kind:?}, phase {phase:?}"
                    );
                }
            }
        }
        for phase in phases {
            for failure_kind in [
                FailureKind::ConfirmationJuryCapacityUnavailable,
                FailureKind::RandomnessRedrawBudgetExhausted,
            ] {
                assert_eq!(
                    timed_ovn_phase_matches_ballot_status_v1(
                        BallotStatus::NoResult,
                        Some(failure_kind),
                        phase,
                    ),
                    phase == Phase::Released,
                    "post-opening NoResult must retain its released timed-OVN evidence"
                );
                assert!(
                    !timed_ovn_phase_matches_ballot_status_v1(
                        BallotStatus::Superseded,
                        Some(failure_kind),
                        phase,
                    ),
                    "terminal post-opening failure must not become retryable"
                );
            }
        }
        for status in [
            BallotStatus::Registration,
            BallotStatus::SurvivorFreeze,
            BallotStatus::TimedCommitment,
            BallotStatus::AwaitingRelease,
            BallotStatus::Opening,
            BallotStatus::Finalized,
        ] {
            for phase in phases {
                assert!(
                    !timed_ovn_phase_matches_ballot_status_v1(
                        status,
                        Some(FailureKind::OpeningDeadlineExpired),
                        phase,
                    ),
                    "nonterminal status with a failure kind must fail closed"
                );
            }
        }
    }

    #[test]
    fn restored_tle_ovn_state_must_match_the_authoritative_network() {
        let authoritative_network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA1; 32])),
        );
        let foreign_network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xB1; 32])),
        );
        let foreign_key_state = public_key_session_fixture_for_context_v1(
            *foreign_network.as_bytes(),
            0xB2,
            [0xB3; 32],
        );
        let foreign_key_session_id = foreign_key_state.key_session_id;
        let foreign_key = foreign_key_state
            .clone()
            .validate()
            .expect("foreign-network TLE fixture is internally valid");
        let ballot_attempt_id = BallotAttemptId::new([0xB4; 32]);
        let lifecycle = TimedOvnLifecycleStateV1::open_registration(
            TimedOvnSessionPublicV1 {
                network_id: *foreign_network.as_bytes(),
                proposal_content_id: [0xB5; 32],
                governance_attempt_id: [0xB6; 32],
                body_instance_id: [0xB7; 32],
                ballot_attempt_id: *ballot_attempt_id.as_bytes(),
                parameter_hash: timed_ovn_parameter_hash_v1(),
                tle_key_session_id: foreign_key_session_id,
                tle_key_transcript_hash: foreign_key.public_state().transcript_hash,
                tle_master_public_key: *foreign_key.master_public_key().as_bytes(),
            },
            10,
            20,
            &foreign_key,
        )
        .expect("foreign-network lifecycle is self-consistent with its TLE session");
        let mut world = World::default();
        world
            .tle_key_sessions
            .insert(foreign_key_session_id, foreign_key_state);
        world
            .timed_ovn_evidence
            .insert(ballot_attempt_id, lifecycle);

        validate_tle_ovn_snapshot_network_v1(&world, &foreign_network)
            .expect("same-network restored TLE/OVN state is admitted");
        let error = validate_tle_ovn_snapshot_network_v1(&world, &authoritative_network)
            .expect_err("self-consistent foreign-network TLE/OVN state must fail closed");
        assert!(
            error.contains("different exact NetworkId"),
            "rejection identifies the cross-network restore: {error}"
        );
    }

    fn world_with_frozen_tle_roster_binding_v1() -> (World, TleKeySessionId, Vec<PeerId>) {
        let ordered_roster = (0..4)
            .map(|_| PeerId::new(crate::state::checked_keypair().public_key().clone()))
            .collect::<Vec<_>>();
        let public_state = public_key_session_fixture_for_context_v1(
            [0xC1; 32],
            0xC2,
            crate::beacon::global_threshold_beacon_roster_hash_v1(&ordered_roster),
        );
        let key_session_id = public_state.key_session_id;
        let mut world = World::default();
        world.tle_key_sessions.insert(key_session_id, public_state);
        world
            .tle_key_session_rosters
            .insert(key_session_id, ordered_roster.clone());
        world.tle_key_session_lifecycles.insert(
            key_session_id,
            TleKeySessionLifecycleV1::new(key_session_id, 1, 100, 1)
                .expect("valid frozen-roster lifecycle fixture"),
        );
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, key_session_id);
        (world, key_session_id, ordered_roster)
    }

    #[test]
    fn restore_requires_an_exact_bijective_frozen_tle_roster_binding() {
        let (mut world, key_session_id, ordered_roster) = world_with_frozen_tle_roster_binding_v1();
        validate_tle_ovn_persistence(&world)
            .expect("an exact public session/ordered-roster pair restores");

        world.tle_key_session_rosters = Storage::default();
        let missing = validate_tle_ovn_persistence(&world)
            .expect_err("a session without its frozen roster must fail restore");
        assert!(
            matches!(
                &missing,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_rosters"
                        && message.contains("missing its frozen ordered roster")
            ),
            "unexpected missing-roster rejection: {missing}"
        );

        let mut reordered_roster = ordered_roster.clone();
        reordered_roster.swap(0, 1);
        world
            .tle_key_session_rosters
            .insert(key_session_id, reordered_roster);
        let reordered = validate_tle_ovn_persistence(&world)
            .expect_err("a reordered roster must fail its session hash binding");
        assert!(
            matches!(
                &reordered,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_rosters"
                        && message.contains("invalid frozen ordered roster binding")
            ),
            "unexpected reordered-roster rejection: {reordered}"
        );

        let duplicate_roster = vec![ordered_roster[0].clone(); ordered_roster.len()];
        let duplicate_public_state = public_key_session_fixture_for_context_v1(
            [0xC1; 32],
            0xC3,
            crate::beacon::global_threshold_beacon_roster_hash_v1(&duplicate_roster),
        );
        let duplicate_key_session_id = duplicate_public_state.key_session_id;
        let mut duplicated = World::default();
        duplicated
            .tle_key_sessions
            .insert(duplicate_key_session_id, duplicate_public_state);
        duplicated
            .tle_key_session_rosters
            .insert(duplicate_key_session_id, duplicate_roster);
        let duplicate = validate_tle_ovn_persistence(&duplicated)
            .expect_err("duplicate PeerIds cannot occupy distinct frozen seats");
        assert!(
            matches!(
                &duplicate,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_rosters"
                        && message.contains("invalid frozen ordered roster binding")
            ),
            "unexpected duplicate-seat rejection: {duplicate}"
        );

        let mut orphaned = World::default();
        orphaned
            .tle_key_session_rosters
            .insert(key_session_id, ordered_roster);
        let orphan = validate_tle_ovn_persistence(&orphaned)
            .expect_err("a roster without its public session must fail restore");
        assert!(
            matches!(
                &orphan,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_rosters"
                        && message.contains("references missing TLE key session")
            ),
            "unexpected orphan-roster rejection: {orphan}"
        );
    }

    #[test]
    fn restore_rejects_missing_misbound_or_miscounted_tle_lifecycle_metadata() {
        let (mut world, _, _) = world_with_frozen_tle_roster_binding_v1();
        world.tle_key_session_lifecycles = Storage::default();
        let missing = validate_tle_ovn_persistence(&world)
            .expect_err("a public TLE session without lifecycle metadata must fail restore");
        assert!(
            matches!(
                &missing,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_lifecycles"
                        && message.contains("missing lifecycle metadata")
            ),
            "unexpected missing-lifecycle rejection: {missing}"
        );

        let (mut world, key_session_id, _) = world_with_frozen_tle_roster_binding_v1();
        let mut misbound = *world
            .tle_key_session_lifecycles
            .view()
            .get(&key_session_id)
            .expect("fixture lifecycle");
        misbound.key_session_id = TleKeySessionId::new([0xDD; 32]);
        world
            .tle_key_session_lifecycles
            .insert(key_session_id, misbound);
        let mismatch = validate_tle_ovn_persistence(&world)
            .expect_err("a lifecycle stored under another session id must fail restore");
        assert!(
            matches!(
                &mismatch,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_lifecycles"
                        && message.contains("storage key differs")
            ),
            "unexpected lifecycle-id rejection: {mismatch}"
        );

        let (mut world, key_session_id, _) = world_with_frozen_tle_roster_binding_v1();
        let mut miscounted = *world
            .tle_key_session_lifecycles
            .view()
            .get(&key_session_id)
            .expect("fixture lifecycle");
        miscounted.fresh_ballot_uses = 1;
        world
            .tle_key_session_lifecycles
            .insert(key_session_id, miscounted);
        let mismatch = validate_tle_ovn_persistence(&world)
            .expect_err("a lifecycle counter without committed ballots must fail restore");
        assert!(
            matches!(
                &mismatch,
                json::Error::InvalidField { field, message }
                    if field == "tle_key_session_lifecycles"
                        && message.contains("counter disagrees")
            ),
            "unexpected lifecycle-counter rejection: {mismatch}"
        );

        let (mut world, key_session_id, _) = world_with_frozen_tle_roster_binding_v1();
        world.tle_active_key_session = Storage::default();
        let missing_head = validate_tle_ovn_persistence(&world)
            .expect_err("an open lifecycle head without its active pointer must fail restore");
        assert!(
            matches!(
                &missing_head,
                json::Error::InvalidField { field, message }
                    if field == "tle_active_key_session"
                        && message.contains("open latest lifecycle head")
            ),
            "unexpected missing-head rejection: {missing_head}"
        );

        let mut closed = *world
            .tle_key_session_lifecycles
            .view()
            .get(&key_session_id)
            .expect("fixture lifecycle");
        closed
            .cut_over_after(50)
            .expect("close the fixture lifecycle explicitly");
        world
            .tle_key_session_lifecycles
            .insert(key_session_id, closed);
        validate_tle_ovn_persistence(&world)
            .expect("a closed latest lifecycle restores without an active pointer");
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, key_session_id);
        let stale_closed_head = validate_tle_ovn_persistence(&world)
            .expect_err("a closed lifecycle head cannot retain an active pointer");
        assert!(
            matches!(
                &stale_closed_head,
                json::Error::InvalidField { field, message }
                    if field == "tle_active_key_session"
                        && message.contains("closed latest lifecycle head")
            ),
            "unexpected closed-head rejection: {stale_closed_head}"
        );

        let (mut world, first_key_session_id, ordered_roster) =
            world_with_frozen_tle_roster_binding_v1();
        let second_public_state = public_key_session_fixture_for_context_v1(
            [0xC1; 32],
            0xC3,
            crate::beacon::global_threshold_beacon_roster_hash_v1(&ordered_roster),
        );
        let second_key_session_id = second_public_state.key_session_id;
        world
            .tle_key_sessions
            .insert(second_key_session_id, second_public_state);
        world
            .tle_key_session_rosters
            .insert(second_key_session_id, ordered_roster);
        world.tle_key_session_lifecycles.insert(
            second_key_session_id,
            TleKeySessionLifecycleV1::new(second_key_session_id, 101, 100, 1)
                .expect("nonoverlapping successor lifecycle"),
        );
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, second_key_session_id);
        let open_history = validate_tle_ovn_persistence(&world)
            .expect_err("a non-latest open lifecycle must fail restore");
        assert!(
            matches!(
                &open_history,
                json::Error::InvalidField { field, message }
                    if field == "tle_active_key_session"
                        && message.contains("non-latest")
            ),
            "unexpected open-history rejection: {open_history}"
        );

        let mut first_lifecycle = *world
            .tle_key_session_lifecycles
            .view()
            .get(&first_key_session_id)
            .expect("first fixture lifecycle");
        first_lifecycle
            .cut_over_after(100)
            .expect("close the predecessor at the successor boundary");
        world
            .tle_key_session_lifecycles
            .insert(first_key_session_id, first_lifecycle);
        world
            .tle_active_key_session
            .insert(TLE_KEY_SESSION_SINGLETON_KEY, first_key_session_id);
        let stale_head = validate_tle_ovn_persistence(&world)
            .expect_err("a stale active lifecycle head must fail restore");
        assert!(
            matches!(
                &stale_head,
                json::Error::InvalidField { field, message }
                    if field == "tle_active_key_session"
                        && message.contains("latest lifecycle head")
            ),
            "unexpected stale-head rejection: {stale_head}"
        );
    }
}

#[cfg(test)]
mod parliament_attempt_size_restore_tests {
    use super::*;

    #[test]
    fn mode_independent_restore_prefix_accepts_small_and_rejects_oversized_attempts() {
        let mut world = World::default();
        let small =
            crate::governance::parliament::tests::active_timed_ovn_reservation_attempt_fixture_v1(
                0xE1, 0xE2, 27,
            );
        world.parliament_attempts.insert(small.attempt().id, small);
        validate_parliament_attempt_encoded_size_bounds_v1(&world)
            .expect("ordinary attempt fits the unconditional restore prefix");

        let oversized =
            crate::governance::parliament::tests::oversized_attempt_state_fixture_v1(0xE3);
        world
            .parliament_attempts
            .insert(oversized.attempt().id, oversized);
        let error = validate_parliament_attempt_encoded_size_bounds_v1(&world)
            .expect_err("oversized attempt must fail before either restore-mode branch");
        assert!(
            matches!(
                &error,
                json::Error::InvalidField { field, message }
                    if field == "parliament_attempts"
                        && message.contains("authoritative encoded-size bound")
            ),
            "restore rejection identifies the authoritative attempt bound: {error}"
        );
    }
}

#[cfg(test)]
mod validation_fee_registry_restore_tests {
    use super::*;
    use crate::query::store::LiveQueryStore;
    use iroha_data_model::{
        governance::types::{GovernanceCertificateId, ProposalKind, ValidationFeePolicyProposal},
        parameter::Parameter,
        validation_fee::{
            VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            ValidationFeeChargingMode, ValidationFeeParliamentAuthorizationV1,
            ValidationFeePolicyRegistryEntryV1, ValidationFeePolicyRegistryV1,
            ValidationFeePolicyV1,
        },
    };

    const REGISTRY_CANDIDATE_SEED: u8 = 20;
    const RESTORED_HEIGHT: u64 = 20;

    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive deterministic validation-fee restore account");
        AccountId::new(key_pair.public_key().clone())
    }

    fn candidates(first_seed: u8) -> Vec<AccountId> {
        (first_seed..first_seed + 24).map(account).collect()
    }

    fn network_id() -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed([0x91; 32]),
        ))
    }

    fn registry_world_with_policy_network(
        stored_candidate_seed: u8,
        policy_network_id: iroha_data_model::NetworkId,
    ) -> (World, ValidationFeePolicyRegistryV1) {
        let parliament_network_id = network_id();
        let proposal_operator = account(250);
        let enacted_at_height = RESTORED_HEIGHT;

        let wrapper = iroha_data_model::smart_contract::ContractAddress::derive(
            &policy_network_id,
            &account(249),
            1,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("restore wrapper");
        let mut binding = crate::validation_fee::tests::treasury_payout_binding(
            wrapper,
            b"restore conversion wrapper",
        );
        binding.ds_asset_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("validation", "fees").expect("fee domain"),
            "ds".parse().expect("fee name"),
        );
        let pool = iroha_data_model::smart_contract::ContractAddress::derive(
            &policy_network_id,
            &account(246),
            2,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("restore pool");
        binding.pool_vault_account_id = pool.subject_id();
        binding.pool_contract_address = pool;
        let lifecycle_kind = ProposalKind::ValidationFeePayoutLifecycle(
            iroha_data_model::governance::types::ValidationFeePayoutLifecycleProposal {
                proposal_operator: proposal_operator.clone(),
                payout_binding: binding.clone(),
            },
        );
        let lifecycle_fixture =
            crate::governance::parliament::tests::enacted_parliament_attempt_restore_fixture_v1(
                &lifecycle_kind,
                candidates(REGISTRY_CANDIDATE_SEED),
                &parliament_network_id,
                enacted_at_height,
            );
        let lifecycle_certificate = lifecycle_fixture
            .attempt
            .certificate()
            .cloned()
            .expect("finalized lifecycle certificate");
        let lifecycle_entry = iroha_data_model::validation_fee::ValidationFeePayoutPolicyEntryV1 {
            revision: 1,
            proposal_id: lifecycle_kind.fingerprint(),
            payout_binding: binding.clone(),
            lifecycle_seal: binding.lifecycle_seal().expect("lifecycle seal"),
            parliament_authorization: ValidationFeeParliamentAuthorizationV1 {
                proposal_operator: proposal_operator.clone(),
                proposal_fingerprint: lifecycle_kind.fingerprint(),
                governance_certificate_id: GovernanceCertificateId::derive_v1(
                    &lifecycle_certificate,
                ),
                governance_certificate: lifecycle_certificate,
                enacted_at_height,
            },
        };
        let policy = ValidationFeePolicyV1 {
            retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
            effective_from_ms: 1793451600000,
            notice_published_at_ms: 1790859600000,
            schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            network_id: policy_network_id,
            policy_version: 1,
            previous_policy_hash: None,
            ds_asset_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("validation", "fees").expect("fee domain"),
                "ds".parse().expect("fee asset name"),
            ),
            ds_scale: VALIDATION_FEE_DS_SCALE,
            fee: iroha_data_model::validation_fee::initial_validation_fee_amount(),
            treasury_account_id: binding.treasury_account_id.clone(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
            exemption_classes: vec![
                iroha_data_model::validation_fee::VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS
                    .to_owned(),
            ],
            reward_custody: binding.custody(),
        };
        let kind = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
            proposal_operator: proposal_operator.clone(),
            policy: policy.clone(),
        });
        let registry_fixture =
            crate::governance::parliament::tests::enacted_parliament_attempt_restore_fixture_v1(
                &kind,
                candidates(REGISTRY_CANDIDATE_SEED),
                &parliament_network_id,
                enacted_at_height,
            );
        let registry_attempt = registry_fixture.attempt;
        let certificate = registry_attempt
            .certificate()
            .cloned()
            .expect("enacted registry attempt retains its certificate");
        let authorization = ValidationFeeParliamentAuthorizationV1 {
            proposal_operator: proposal_operator.clone(),
            proposal_fingerprint: kind.fingerprint(),
            governance_certificate_id: GovernanceCertificateId::derive_v1(&certificate),
            governance_certificate: certificate,
            enacted_at_height,
        };
        let registry = ValidationFeePolicyRegistryV1 {
            registered_policies: vec![
                ValidationFeePolicyRegistryEntryV1::from_enactment(policy, authorization)
                    .expect("canonical validation-fee registry entry"),
            ],
            payout_policies:
                iroha_data_model::validation_fee::ValidationFeePayoutPolicyRegistryV1 {
                    entries: vec![lifecycle_entry],
                },
        };
        registry
            .validate()
            .expect("restore fixture registry is intrinsically valid");

        let mut stored_fixture =
            crate::governance::parliament::tests::enacted_parliament_attempt_restore_fixture_v1(
                &kind,
                candidates(stored_candidate_seed),
                &parliament_network_id,
                enacted_at_height,
            );
        stored_fixture
            .tle_key_sessions
            .extend(lifecycle_fixture.tle_key_sessions);
        stored_fixture
            .tle_key_session_rosters
            .extend(lifecycle_fixture.tle_key_session_rosters);
        stored_fixture
            .timed_ovn_evidence
            .extend(lifecycle_fixture.timed_ovn_evidence);
        for (id, lifecycle) in lifecycle_fixture.tle_key_session_lifecycles {
            if let Some((_, existing)) = stored_fixture
                .tle_key_session_lifecycles
                .iter_mut()
                .find(|(key, _)| *key == id)
            {
                existing.fresh_ballot_uses = existing
                    .fresh_ballot_uses
                    .checked_add(lifecycle.fresh_ballot_uses)
                    .expect("combined TLE fixture uses");
            } else {
                stored_fixture
                    .tle_key_session_lifecycles
                    .push((id, lifecycle));
            }
        }
        let stored_attempt = stored_fixture.attempt;
        assert_eq!(
            stored_attempt.attempt().id,
            registry_attempt.attempt().id,
            "same proposal and attempt sequence share one canonical attempt id"
        );
        if stored_candidate_seed != REGISTRY_CANDIDATE_SEED {
            assert_ne!(
                stored_attempt.certificate(),
                registry_attempt.certificate(),
                "different exact rosters must produce different enacted certificates"
            );
        }
        let mut world = World::default();
        let npos = iroha_data_model::parameter::system::SumeragiNposParameters::default();
        assert_eq!(binding.xor_asset_id, npos.xor_asset_definition_id);
        world.accounts.insert(
            proposal_operator.clone(),
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
        world.asset_definitions.insert(
            binding.xor_asset_id.clone(),
            iroha_data_model::asset::AssetDefinition::new(
                binding.xor_asset_id.clone(),
                "XOR".to_owned(),
                iroha_primitives::numeric::NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&proposal_operator),
        );
        // This World projection contains a live definition, so it must retain
        // its registration incarnation just as a committed registration does.
        let registration_header = iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).expect("registration height"),
            None,
            None,
            0,
            0,
        );
        world.axt_asset_incarnations.insert(
            binding.xor_asset_id.clone(),
            iroha_data_model::nexus::AxtAssetIncarnationV1::derive(
                &parliament_network_id,
                &binding.xor_asset_id,
                &registration_header.hash(),
                &Hash::new(b"validation-fee restore fixture XOR registration"),
                0,
            ),
        );
        world.governance_proposals.insert(
            lifecycle_kind.fingerprint(),
            GovernanceProposalRecord {
                proposer: proposal_operator.clone(),
                kind: lifecycle_kind,
                created_height: 1,
                status: GovernanceProposalStatus::Enacted,
            },
        );
        world.parliament_attempts.insert(
            lifecycle_fixture.attempt.attempt().id,
            lifecycle_fixture.attempt,
        );

        world.governance_proposals.insert(
            kind.fingerprint(),
            GovernanceProposalRecord {
                proposer: proposal_operator,
                kind,
                created_height: 1,
                status: GovernanceProposalStatus::Enacted,
            },
        );
        world
            .parliament_attempts
            .insert(stored_attempt.attempt().id, stored_attempt);
        for key_session in stored_fixture.tle_key_sessions {
            world
                .tle_key_sessions
                .insert(key_session.key_session_id, key_session);
        }
        for (key_session_id, ordered_roster) in stored_fixture.tle_key_session_rosters {
            world
                .tle_key_session_rosters
                .insert(key_session_id, ordered_roster);
        }
        let mut open_key_session_id = None;
        for (key_session_id, lifecycle) in stored_fixture.tle_key_session_lifecycles {
            if !lifecycle.selection_is_closed() {
                assert!(
                    open_key_session_id.replace(key_session_id).is_none(),
                    "restore fixture must have at most one open TLE lifecycle head"
                );
            }
            world
                .tle_key_session_lifecycles
                .insert(key_session_id, lifecycle);
        }
        if let Some(key_session_id) = open_key_session_id {
            world
                .tle_active_key_session
                .insert(TLE_KEY_SESSION_SINGLETON_KEY, key_session_id);
        }
        for (ballot_attempt_id, lifecycle) in stored_fixture.timed_ovn_evidence {
            world
                .timed_ovn_evidence
                .insert(ballot_attempt_id, lifecycle);
        }
        {
            let mut parameters = world.parameters.block();
            parameters
                .get_mut()
                .set_parameter(Parameter::Custom(npos.into_custom_parameter()));
            parameters
                .get_mut()
                .set_parameter(Parameter::Custom(registry.clone().into_custom_parameter()));
            parameters.commit();
        }
        (world, registry)
    }

    fn registry_world(stored_candidate_seed: u8) -> (World, ValidationFeePolicyRegistryV1) {
        registry_world_with_policy_network(stored_candidate_seed, network_id())
    }

    // Decode only the World projection. This exercises the actual protected
    // registry parser; it grants no native execution identity or history.
    fn restore_policy_projection(world: &World) -> Result<World, StateRestoreError> {
        let encoded = json::to_json(world).expect("serialize protected registry projection");
        let ivm = IVM::new(0);
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let seed = IvmSeed {
            operation_index_budget: &operation_index_budget,
            operation_index_refusal: &operation_index_refusal,
            ivm: &ivm,
            _marker: PhantomData,
        };
        parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world")?,
            &seed,
        )
    }

    fn restore_world_with_network(
        world: World,
        restored_network_id: iroha_data_model::NetworkId,
    ) -> Result<Box<State>, StateRestoreError> {
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            "validation-fee-restore"
                .parse()
                .expect("validation-fee restore chain id"),
            restored_network_id,
        );
        for height in 1..=RESTORED_HEIGHT {
            state.push_block_hash_for_testing(HashOf::from_untyped_unchecked(Hash::new(
                height.to_le_bytes(),
            )));
        }
        let resolver_revision = MusubiResolverIndexRevisionV1::default();
        let genesis_hash = state
            .block_hashes
            .view()
            .iter()
            .next()
            .copied()
            .expect("restore fixture retains its genesis hash");
        let genesis_checkpoint = MusubiRegistrySnapshotV1 {
            finalized_height: 1,
            finalized_block_hash: *genesis_hash.as_ref(),
            index_revision: resolver_revision.get(),
        };
        genesis_checkpoint
            .validate()
            .expect("restore fixture genesis resolver checkpoint is canonical");
        {
            let mut world = state.world.block();
            assert!(
                world
                    .musubi_resolver_index_checkpoints
                    .insert(resolver_revision, genesis_checkpoint)
                    .is_none(),
                "restore fixture installs exactly one genesis resolver checkpoint"
            );
            world.commit();
        }
        let snapshot = json::to_value(&state).expect("serialize validation-fee restore fixture");
        KuraSeed {
            operation_index_budget: crate::state::kagemusha_operation_indexes::default_budget(),
            execution_budget: iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            lane_manifests: state.lane_manifests.read().clone(),
            kura: Kura::blank_kura_for_testing(),
            query_handle: LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            telemetry: crate::telemetry::StateTelemetry::default(),
        }
        .into_state_from_json(snapshot)
    }

    fn restore_world(world: World) -> Result<Box<State>, StateRestoreError> {
        restore_world_with_network(world, network_id())
    }

    fn assert_registry_restore_error(error: &StateRestoreError, expected: &str) {
        assert!(
            matches!(
                error,
                StateRestoreError::Serialization(json::Error::InvalidField { field, message })
                    if field == "parameters" && message.contains(expected)
            ),
            "restore rejection must identify the protected registry provenance: {error}"
        );
    }

    #[test]
    fn restore_accepts_exact_validation_fee_registry_governance_provenance() {
        let (world, registry) = registry_world(REGISTRY_CANDIDATE_SEED);
        crate::validation_fee::validate_persisted_policy_registry_governance_v1(&world.view())
            .expect("exact registry proposal and attempt provenance");
        let restored = restore_policy_projection(&world)
            .expect("exact protected registry provenance restores its World projection");
        crate::validation_fee::validate_persisted_policy_registry_governance_v1(&restored.view())
            .expect("decoded registry retains the exact proposal and attempt provenance");
        assert_eq!(
            restored
                .parameters
                .view()
                .get()
                .custom()
                .get(&ValidationFeePolicyRegistryV1::parameter_id()),
            Some(&registry.into_custom_parameter()),
        );
        assert!(
            matches!(
                restore_world(world),
                Err(StateRestoreError::NativeExecutionReplayRequired)
            ),
            "decoded policy provenance cannot authorize an unexecuted native history"
        );
    }

    #[test]
    fn restore_rejects_validation_fee_registry_with_missing_governance_provenance() {
        let (world, registry) = registry_world(REGISTRY_CANDIDATE_SEED);
        let authorization = &registry.registered_policies[0].parliament_authorization;
        {
            let mut proposals = world.governance_proposals.block();
            assert!(
                proposals
                    .remove(authorization.proposal_fingerprint)
                    .is_some()
            );
            proposals.commit();
        }
        registry
            .validate()
            .expect("missing proposal provenance does not corrupt the registry payload");
        let registry_error =
            crate::validation_fee::validate_persisted_policy_registry_governance_v1(&world.view())
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("the registry validator must reject its missing exact proposal");
        assert!(
            registry_error.contains("authorized governance proposal is missing"),
            "registry validation identifies the missing proposal: {registry_error}"
        );
        let error = restore_world(world)
            .err()
            .expect("an internally valid registry cannot restore without its proposal");
        assert!(
            matches!(
                &error,
                StateRestoreError::Serialization(json::Error::InvalidField { field, message })
                    if field == "parliament_attempts"
                        && message.contains("missing exact governance proposal")
            ),
            "the complete restore boundary rejects the same missing proposal before publication: {error}"
        );
    }

    #[test]
    fn restore_validator_rejects_validation_fee_registry_with_missing_authorized_attempt() {
        let (world, registry) = registry_world(REGISTRY_CANDIDATE_SEED);
        let authorization = &registry.registered_policies[0].parliament_authorization;
        {
            let mut attempts = world.parliament_attempts.block();
            assert!(
                attempts
                    .remove(authorization.governance_certificate.governance_attempt_id)
                    .is_some()
            );
            attempts.commit();
        }
        registry
            .validate()
            .expect("missing cross-store attempt does not corrupt the registry payload");
        let error =
            crate::validation_fee::validate_persisted_policy_registry_governance_v1(&world.view())
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("the registry must retain its exact authorized Parliament attempt");
        assert!(
            error.contains("authorized Parliament attempt is missing"),
            "restore validator identifies the missing attempt: {error}"
        );
        assert!(
            restore_world(world).is_err(),
            "the complete restore boundary must also reject the missing attempt"
        );
    }

    #[test]
    fn restore_rejects_validation_fee_registry_for_another_exact_network() {
        let foreign_network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::prehashed([0x92; 32])),
        );
        let (world, registry) =
            registry_world_with_policy_network(REGISTRY_CANDIDATE_SEED, foreign_network);
        registry
            .validate()
            .expect("foreign-network registry remains intrinsically valid");
        let restored = restore_policy_projection(&world)
            .expect("foreign policy is structurally valid before its runtime network check");
        let context = State::new_with_chain_and_network_id_for_testing(
            restored,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            "validation-fee-restore".parse().unwrap(),
            network_id(),
        );
        // This context provides the runtime validator's exact network only;
        // no fabricated history or execution authority is installed.
        let error = crate::validation_fee::validate_persisted_policy_registry_runtime_v1(
            &context.view(),
            RESTORED_HEIGHT,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("a restored registry cannot target another exact network");
        assert!(
            error.contains("fee policy network mismatch"),
            "restore rejection identifies the foreign validation-fee network: {error}"
        );
        assert!(matches!(
            restore_world(world),
            Err(StateRestoreError::NativeExecutionReplayRequired)
        ));
    }

    #[test]
    fn emergency_fast_build_cannot_bypass_validation_fee_registry_network_binding() {
        let foreign_policy_network = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::prehashed([0x92; 32])),
        );
        let (world, _) =
            registry_world_with_policy_network(REGISTRY_CANDIDATE_SEED, foreign_policy_network);
        let block_hashes: Vec<HashOf<BlockHeader>> = (1..=RESTORED_HEIGHT)
            .map(|height| HashOf::from_untyped_unchecked(Hash::new(height.to_le_bytes())))
            .collect();
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let incarnations = derive_static_lane_incarnations(&nexus.lane_catalog);
        let activation: BTreeMap<_, _> = incarnations.keys().map(|&id| (id, 0)).collect();
        let lineage = incarnations
            .iter()
            .map(|(&id, &incarnation)| {
                (
                    id,
                    LaneIncarnationLineage {
                        incarnation,
                        generation: 0,
                        activation_height: 0,
                    },
                )
            })
            .collect();
        let canonical_runtime = Cell::new(SnapshotNexusRuntime::from_nexus(
            &nexus,
            &incarnations,
            &activation,
            &lineage,
        ));
        let kura = Kura::blank_kura_for_testing();
        let error = build_state(
            BuildStateInputs {
                execution_budget: iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                lane_manifests: Arc::new(LaneManifestRegistry::empty()),
                canonical_runtime,
                native_execution_tip: None,
                world,
                block_hashes: BlockHashes::new(block_hashes),
                transactions: TransactionsStorage::try_new(kura.transaction_history_budget())
                    .expect("fund emergency-fast fixture membership"),
                commit_topology: Cell::new(Vec::new()),
                prev_commit_topology: Cell::new(Vec::new()),
                ivm: IVM::new(0),
                nexus: iroha_config::parameters::actual::Nexus::default(),
                chain_id: "validation-fee-emergency-fast"
                    .parse()
                    .expect("validation-fee emergency-fast chain id"),
                network_id: network_id(),
                nexus_runtime_restored_from_snapshot: false,
                kura,
                query_handle: LiveQueryStore::start_test(),
                #[cfg(feature = "telemetry")]
                telemetry: crate::telemetry::StateTelemetry::default(),
            },
            false,
            true,
        )
        .err()
        .expect("emergency-fast construction cannot bypass exact fee-policy network binding");
        assert!(
            error.to_string().contains("fee policy network mismatch"),
            "emergency-fast rejection identifies the foreign validation-fee network: {error}"
        );
    }

    #[test]
    fn restore_rejects_validation_fee_registry_with_mismatched_enacted_attempt() {
        let (world, registry) = registry_world(80);
        registry
            .validate()
            .expect("mismatched cross-store provenance does not corrupt the registry payload");
        let error = restore_world(world)
            .err()
            .expect("an internally valid registry cannot restore with another certificate");
        assert_registry_restore_error(
            &error,
            "authorized Parliament attempt does not retain the exact enacted certificate",
        );
    }
}

/// Validate one complete persisted DA pin-index cut without rebuilding or
/// accepting records according to a process-local cache.
fn validate_da_pin_persistence_cut(
    by_ticket: &impl mv::storage::StorageReadOnly<StorageTicketId, DaPinIntentWithLocation>,
    by_alias: &impl mv::storage::StorageReadOnly<String, StorageTicketId>,
    by_manifest: &impl mv::storage::StorageReadOnly<ManifestDigest, StorageTicketId>,
    by_lane_epoch: &impl mv::storage::StorageReadOnly<(LaneId, u64, u64), StorageTicketId>,
    cut: &'static str,
) -> Result<(), json::Error> {
    let invalid = |field: &str, reason: &str| json::Error::InvalidField {
        field: format!("world.{field}"),
        message: format!("invalid {cut} DA pin-index projection: {reason}"),
    };
    let mut locations = BTreeSet::new();
    for (ticket, record) in by_ticket.iter() {
        if *ticket != record.intent.storage_ticket {
            return Err(invalid(
                "da_pin_intents_by_ticket",
                "ticket key differs from the stored intent",
            ));
        }
        if !locations.insert((
            record.location.block_height,
            record.location.index_in_bundle,
        )) {
            return Err(invalid(
                "da_pin_intents_by_ticket",
                "multiple intents have the same block location",
            ));
        }
        if by_manifest.get(&record.intent.manifest_hash) != Some(ticket) {
            return Err(invalid(
                "da_pin_intents_by_manifest",
                "primary intent lacks its exact manifest index",
            ));
        }
        let lane_epoch = (
            record.intent.lane_id,
            record.intent.epoch,
            record.intent.sequence,
        );
        if by_lane_epoch.get(&lane_epoch) != Some(ticket) {
            return Err(invalid(
                "da_pin_intents_by_lane_epoch",
                "primary intent lacks its exact lane/epoch/sequence index",
            ));
        }
    }
    for (manifest, ticket) in by_manifest.iter() {
        if !by_ticket
            .get(ticket)
            .is_some_and(|record| record.intent.manifest_hash == *manifest)
        {
            return Err(invalid(
                "da_pin_intents_by_manifest",
                "manifest index does not identify its exact primary intent",
            ));
        }
    }
    for (lane_epoch, ticket) in by_lane_epoch.iter() {
        if !by_ticket.get(ticket).is_some_and(|record| {
            (
                record.intent.lane_id,
                record.intent.epoch,
                record.intent.sequence,
            ) == *lane_epoch
        }) {
            return Err(invalid(
                "da_pin_intents_by_lane_epoch",
                "lane/epoch/sequence index does not identify its exact primary intent",
            ));
        }
    }
    for (alias, ticket) in by_alias.iter() {
        if !by_ticket
            .get(ticket)
            .is_some_and(|record| record.intent.alias.as_deref() == Some(alias.as_str()))
        {
            return Err(invalid(
                "da_pin_intents_by_alias",
                "alias does not bind a primary intent declaring that alias",
            ));
        }
    }
    // Alias removal after lane retirement is valid, as is rebinding the same
    // alias in a later record. Not every retained intent must have a binding.
    Ok(())
}

fn validate_da_pin_persistence(world: &World) -> Result<(), json::Error> {
    {
        let tickets = world.da_pin_intents_by_ticket.view();
        let aliases = world.da_pin_intents_by_alias.view();
        let manifests = world.da_pin_intents_by_manifest.view();
        let lane_epochs = world.da_pin_intents_by_lane_epoch.view();
        validate_da_pin_persistence_cut(&tickets, &aliases, &manifests, &lane_epochs, "current")?;
    }
    // Each real MV undo overlay is dropped without committing. Validate all
    // four retained predecessor stores together, preserving their undo logs.
    // This proves index coherence of both cuts, not historical authentication.
    let tickets = world.da_pin_intents_by_ticket.block_and_revert();
    let aliases = world.da_pin_intents_by_alias.block_and_revert();
    let manifests = world.da_pin_intents_by_manifest.block_and_revert();
    let lane_epochs = world.da_pin_intents_by_lane_epoch.block_and_revert();
    validate_da_pin_persistence_cut(&tickets, &aliases, &manifests, &lane_epochs, "predecessor")
}

#[cfg(test)]
#[path = "deserialize_world_da_pin_tests.rs"]
mod da_pin_persistence_tests;

fn validate_domain_endorsement_index_cut(
    endorsements: &impl StorageReadOnly<HashOf<DomainEndorsement>, DomainEndorsementRecord>,
    by_domain: &impl StorageReadOnly<DomainId, Vec<HashOf<DomainEndorsement>>>,
    cut: &str,
) -> Result<(), json::Error> {
    let invalid = |message: &str| json::Error::InvalidField {
        field: "domain_endorsements_by_domain".to_owned(),
        message: format!("invalid {cut} endorsement index: {message}"),
    };
    let mut indexed = BTreeSet::new();
    for (domain, hashes) in by_domain.iter() {
        if hashes.is_empty() {
            return Err(invalid("empty domain entry"));
        }
        let mut previous_height = None;
        for hash in hashes {
            let record = endorsements
                .get(hash)
                .ok_or_else(|| invalid("index references a missing endorsement"))?;
            if &record.endorsement.domain_id != domain {
                return Err(invalid("endorsement belongs to a different domain"));
            }
            if !indexed.insert(*hash) {
                return Err(invalid("endorsement is indexed more than once"));
            }
            if previous_height.is_some_and(|height| height > record.accepted_at_height) {
                return Err(invalid("endorsement acceptance heights decrease"));
            }
            previous_height = Some(record.accepted_at_height);
        }
    }
    if indexed.len() != endorsements.len() {
        return Err(invalid("index omits an authoritative endorsement"));
    }
    Ok(())
}

fn validate_domain_endorsement_index(world: &World) -> Result<(), json::Error> {
    {
        let endorsements = world.domain_endorsements.view();
        let by_domain = world.domain_endorsements_by_domain.view();
        validate_domain_endorsement_index_cut(&endorsements, &by_domain, "current")?;
    }
    // Check the actual retained MV predecessor without deriving intra-block
    // append order from records that only retain an acceptance height.
    let endorsements = world.domain_endorsements.block_and_revert();
    let by_domain = world.domain_endorsements_by_domain.block_and_revert();
    validate_domain_endorsement_index_cut(&endorsements, &by_domain, "predecessor")
}

#[cfg(test)]
#[path = "deserialize_world_domain_endorsement_tests.rs"]
mod domain_endorsement_persistence_tests;

/// A decoded snapshot is quarantined canonical data until same-pool admission and the
/// separately authenticated current/revert chain cuts validate its authority graph.
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
struct NativeScheduleSnapshot {
    revert: Option<mv::json::SnapshotUndoValue<crate::sumeragi::schedule::ConsensusSchedule>>,
    blocks: crate::sumeragi::schedule::ConsensusSchedule,
}
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct NativeLaneCustodySnapshot {
    revert:
        Option<mv::json::SnapshotUndoValue<iroha_data_model::sumeragi_lanes::SumeragiLaneState>>,
    blocks: iroha_data_model::sumeragi_lanes::SumeragiLaneState,
}
fn take_native_lane_custody(
    map: &mut SnapshotJsonMap<'_>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Cell<iroha_data_model::sumeragi_lanes::SumeragiLaneState>, StateRestoreError> {
    // Borrow the original field until both generations have their original-pool owners.
    // A refusal drops only this attempt's decoded graph and copies, not the raw source.
    let field = map
        .fields
        .get("sumeragi_lanes")
        .ok_or_else(|| json::Error::missing_field("sumeragi_lanes"))?;
    let snapshot: NativeLaneCustodySnapshot = match field {
        SnapshotJsonField::Borrowed { raw } => {
            let value: NativeLaneCustodySnapshot = json::from_str(raw)?;
            if json::to_json(&value)?.as_bytes() != raw.as_bytes() {
                return Err(json::Error::InvalidField {
                    field: "sumeragi_lanes".into(),
                    message: "snapshot field is not canonically encoded".into(),
                }
                .into());
            }
            value
        }
        #[cfg(test)]
        SnapshotJsonField::Owned(value) => json::value::from_value(value.clone())?,
    };
    let current = crate::sumeragi::lanes::custody::admit_state(&snapshot.blocks, budget)
        .map_err(StateRestoreError::NativeLaneCustody)?;
    let previous = snapshot
        .revert
        .as_ref()
        .map(|undo| crate::sumeragi::lanes::custody::admit_state(&undo.value, budget))
        .transpose()
        .map_err(StateRestoreError::NativeLaneCustody)?;
    map.remove("sumeragi_lanes");
    // Both nested original-pool signer/sample owners exist before either generation is installed.
    // Outer lane vectors and EBR controls remain separate accounting obligations.
    Ok(Cell::from_values_charged(
        current,
        previous,
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    ))
}

#[cfg(test)]
#[path = "deserialize_world_beacon_custody_tests.rs"]
mod native_beacon_custody_tests;
#[cfg(test)]
#[path = "deserialize_world_lane_custody_tests.rs"]
mod native_lane_custody_tests;

/// Canonical DTO input only: runtime rows cannot be decoded without original admission.
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct NativeBeaconSessionSnapshot {
    revert: std::collections::BTreeMap<
        [u8; 32],
        Option<
            mv::json::SnapshotUndoValue<
                crate::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1,
            >,
        >,
    >,
    blocks: std::collections::BTreeMap<
        [u8; 32],
        crate::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1,
    >,
}
fn take_native_beacon_sessions(
    map: &mut SnapshotJsonMap<'_>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    Storage<[u8; 32], crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1>,
    StateRestoreError,
> {
    use crate::beacon::{
        GlobalThresholdBeaconSessionError, RetainedFinalizedGlobalThresholdBeaconSessionV1,
    };
    let field = map
        .fields
        .get("global_beacon_key_sessions")
        .ok_or_else(|| json::Error::missing_field("global_beacon_key_sessions"))?;
    let snapshot: NativeBeaconSessionSnapshot = match field {
        SnapshotJsonField::Borrowed { raw } => {
            let value: NativeBeaconSessionSnapshot = json::from_str(raw)?;
            if json::to_json(&value)?.as_bytes() != raw.as_bytes() {
                return Err(invalid_global_beacon_persistence(
                    "beacon session snapshot field is not canonical",
                )
                .into());
            }
            value
        }
        #[cfg(test)]
        SnapshotJsonField::Owned(value) => json::value::from_value(value.clone())?,
    };
    let admit = |key: &[u8; 32],
                 value: &crate::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1|
     -> Result<
        crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
        StateRestoreError,
    > {
        if key != &value.session.session_id {
            return Err(invalid_global_beacon_persistence(
                "beacon snapshot storage key differs from its canonical session identity",
            )
            .into());
        }
        RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(value, budget).map_err(|error| {
            match error {
                GlobalThresholdBeaconSessionError::Invalid(error) => {
                    invalid_global_beacon_persistence(error.to_string()).into()
                }
                local => StateRestoreError::BeaconSession(local),
            }
        })
    };
    let mut current = std::collections::BTreeMap::new();
    for (key, value) in &snapshot.blocks {
        current.insert(*key, admit(key, value)?);
    }
    let mut undo = std::collections::BTreeMap::new();
    for (key, value) in &snapshot.revert {
        undo.insert(
            *key,
            value
                .as_ref()
                .map(|undo| admit(key, &undo.value))
                .transpose()?,
        );
    }
    map.remove("global_beacon_key_sessions");
    // Both authenticated graph generations are complete before installing either map.
    // Input JSON graphs, outer maps/EBR and decoder scratch remain separate explicit
    // ownership obligations; none is claimed by these retained graph ledgers.
    Ok(Storage::from_snapshot_parts(current, undo))
}

/// Decode explicit current/undo claims, then admit both original graph and Cell generations.
fn take_native_amx_participant(
    map: &mut SnapshotJsonMap<'_>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    Cell<crate::sumeragi::amx::RetainedNativeAmx, iroha_allocation::AllocationCharge>,
    StateRestoreError,
> {
    #[derive(norito::json::JsonSerialize, norito::json::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct Snapshot {
        // Preserve the original Cell encoder's declaration order during the
        // canonical comparison; both current and explicit undo remain required.
        #[norito(required)]
        revert: Option<mv::json::SnapshotUndoValue<Undo>>,
        blocks: Undo,
    }
    #[derive(norito::json::JsonSerialize, norito::json::JsonDeserialize)]
    #[norito(deny_unknown_fields)]
    struct Undo {
        #[norito(required)]
        value: Option<iroha_data_model::sumeragi_amx::NativeAmxParticipantStateV1>,
    }
    let snapshot: Snapshot = take_required(map, "sumeragi_amx_participant")?;
    let admit = |source: Option<&iroha_data_model::sumeragi_amx::NativeAmxParticipantStateV1>| {
        source
            .map(|source| crate::sumeragi::amx::RetainedNativeAmx::admit(source, budget))
            .transpose()
            .map(|value| value.unwrap_or_default())
            .map_err(|error| match error {
                local @ (crate::sumeragi::amx::NativeAmxAdmissionError::Admission(_)
                | crate::sumeragi::amx::NativeAmxAdmissionError::Allocator { .. }
                | crate::sumeragi::amx::NativeAmxAdmissionError::Codec(_)) => {
                    StateRestoreError::NativeAmx(local)
                }
                invalid => StateRestoreError::Serialization(json::Error::InvalidField {
                    field: "world.sumeragi_amx_participant".into(),
                    message: invalid.to_string(),
                }),
            })
    };
    let current = admit(snapshot.blocks.value.as_ref())?;
    let previous = snapshot
        .revert
        .as_ref()
        .map(|undo| admit(undo.value.value.as_ref()))
        .transpose()?;
    let initial = mv::cell::CellInitialization::try_reserve(budget)
        .map_err(crate::state::scalar_cell_custody::admission_error)?;
    Ok(initial.initialize(current, previous))
}

fn take_native_consensus_schedule(
    map: &mut SnapshotJsonMap<'_>,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Cell<crate::sumeragi::schedule::RetainedConsensusSchedule>, StateRestoreError> {
    use crate::sumeragi::schedule::{RetainedConsensusSchedule, ScheduleError};
    let snapshot: NativeScheduleSnapshot = take_required(map, "consensus_schedule")?;
    let classify = |error: ScheduleError| match error {
        local @ (ScheduleError::Admission(_) | ScheduleError::Allocator { .. }) => {
            StateRestoreError::NativeSchedule(local)
        }
        invalid => StateRestoreError::Serialization(json::Error::InvalidField {
            field: "world.consensus_schedule".into(),
            message: invalid.to_string(),
        }),
    };
    let current = RetainedConsensusSchedule::admit(&snapshot.blocks, budget).map_err(classify)?;
    let undo = snapshot
        .revert
        .as_ref()
        .map(|undo| RetainedConsensusSchedule::admit(&undo.value, budget))
        .transpose()
        .map_err(classify)?;
    // Both exact nested owners exist before either EBR generation is installed. These
    // untracked outer controls are not claimed as covered by the schedule graph's ledger.
    Ok(Cell::from_values_charged(
        current,
        undo,
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    ))
}

#[cfg(test)]
fn expect_completed_restore_rejection(error: StateRestoreError) -> json::Error {
    match error {
        StateRestoreError::Serialization(error) => error,
        local => panic!("unexpected local restore refusal: {local}"),
    }
}

#[allow(clippy::too_many_lines)]
/// Decode the original World allocation before any full rollback validation starts.
/// Its large per-field decoding temporaries must leave the stack before the next
/// phase acquires the complete original writer inventory. The only caller below
/// immediately performs every existing validation and index rebuild in order.
#[inline(never)]
fn decode_world_fields(
    execution_budget: &iroha_allocation::AllocationBudget,
    mut map: SnapshotJsonMap<'_>,
    ivm_seed: &IvmSeed<'_, World>,
) -> Result<World, StateRestoreError> {
    if let Some(actual) = map.source_order.as_ref() {
        let expected = canonical_world_field_order();
        if let Some(unknown) = actual.iter().find(|key| !expected.contains(&key.as_str())) {
            return Err(json::Error::InvalidField {
                field: format!("world.{unknown}"),
                message: "unknown field is not permitted in a signed first-release snapshot"
                    .to_owned(),
            }
            .into());
        }
        if !actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
        {
            return Err(json::Error::InvalidField {
                field: "world".to_owned(),
                message: "snapshot world fields are not in canonical schema order".to_owned(),
            }
            .into());
        }
    }
    let parameters = take_parameters_cell(&mut map, "parameters")?;
    let peers: Cell<Peers> = take_required(&mut map, "peers")?;
    let consensus_schedule = take_native_consensus_schedule(&mut map, execution_budget)?;
    // Derived from the restored World: accelerated restoration recomputes it by a cold capture
    // and compares it with the certified parent World state root before use (S9).
    let state_accumulator = take_required(&mut map, "state_accumulator")?;
    let domain_committees = take_required(&mut map, "domain_committees")?;
    let domain_endorsement_policies = take_required(&mut map, "domain_endorsement_policies")?;
    let domain_endorsements = take_required(&mut map, "domain_endorsements")?;
    let domain_endorsements_by_domain: Storage<DomainId, Vec<HashOf<DomainEndorsement>>> =
        take_required(&mut map, "domain_endorsements_by_domain")?;
    let domains: Storage<DomainId, Domain> = take_required(&mut map, "domains")?;
    let accounts: Storage<AccountId, AccountValue> = take_required(&mut map, "accounts")?;
    let account_aliases = take_required(&mut map, "account_aliases")?;
    let ram_lfe_program_policies = take_ram_lfe_program_policies(&mut map)?;
    validate_ram_lfe_program_policies(&ram_lfe_program_policies)?;
    let identifier_policies = take_required(&mut map, "identifier_policies")?;
    let fee_sponsor_programs = take_required(&mut map, "fee_sponsor_programs")?;
    let fee_sponsor_program_revisions = take_required(&mut map, "fee_sponsor_program_revisions")?;
    let fee_sponsor_enrollments = take_required(&mut map, "fee_sponsor_enrollments")?;
    let fee_sponsor_vaults = take_required(&mut map, "fee_sponsor_vaults")?;
    let fee_sponsor_budget_counters = take_required(&mut map, "fee_sponsor_budget_counters")?;
    let identifier_claims = take_required(&mut map, "identifier_claims")?;
    let account_recovery_policies = take_required(&mut map, "account_recovery_policies")?;
    let account_recovery_requests = take_required(&mut map, "account_recovery_requests")?;
    let asset_definitions: Storage<AssetDefinitionId, AssetDefinition> =
        take_required(&mut map, "asset_definitions")?;
    let asset_definition_alias_bindings =
        take_required(&mut map, "asset_definition_alias_bindings")?;
    let contract_alias_bindings = take_required(&mut map, "contract_alias_bindings")?;
    let assets: Storage<AssetId, AssetValue> = take_required(&mut map, "assets")?;
    let account_rekey_records = take_required(&mut map, "account_rekey_records")?;
    let asset_metadata = take_required(&mut map, "asset_metadata")?;
    let nfts: Storage<NftId, NftValue> = take_required(&mut map, "nfts")?;
    let rwas: Storage<RwaId, RwaValue> = take_required(&mut map, "rwas")?;
    let roles: Storage<RoleId, Role> = take_required(&mut map, "roles")?;
    let account_permissions: Storage<AccountId, Permissions> =
        take_required(&mut map, "account_permissions")?;
    let account_roles: Storage<RoleIdWithOwner, ()> = take_required(&mut map, "account_roles")?;
    let oracle_feeds = take_required(&mut map, "oracle_feeds")?;
    let oracle_observations = take_required(&mut map, "oracle_observations")?;
    let oracle_history = take_required(&mut map, "oracle_history")?;
    let oracle_provider_stats = take_required(&mut map, "oracle_provider_stats")?;
    let oracle_disputes = take_required(&mut map, "oracle_disputes")?;
    let oracle_changes = take_required(&mut map, "oracle_changes")?;
    let defi_oracle_attestations = take_required(&mut map, "defi_oracle_attestations")?;
    let twitter_bindings = take_required(&mut map, "twitter_bindings")?;
    let twitter_bindings_by_uaid = take_required(&mut map, "twitter_bindings_by_uaid")?;
    let viral_reward_budget = take_required(&mut map, "viral_reward_budget")?;
    let viral_campaign_budget = take_required(&mut map, "viral_campaign_budget")?;
    let viral_daily_counters = take_required(&mut map, "viral_daily_counters")?;
    let viral_binding_claims = take_required(&mut map, "viral_binding_claims")?;
    let viral_escrows = take_required(&mut map, "viral_escrows")?;
    let viral_bonus_paid = take_required(&mut map, "viral_bonus_paid")?;
    let axt_policies: Storage<DataSpaceId, AxtPolicyEntry> =
        take_required(&mut map, "axt_policies")?;
    let axt_handle_counters: Storage<DataSpaceId, AxtHandleCounterRecord> =
        take_required(&mut map, "axt_handle_counters")?;
    let counters = axt_handle_counters.view();
    for (_, record) in counters.iter() {
        record
            .validate()
            .map_err(|error| json::Error::InvalidField {
                field: "world.axt_handle_counters".to_owned(),
                message: error.to_string(),
            })?;
    }
    let axt_asset_incarnations: Storage<AssetDefinitionId, AxtAssetIncarnationV1> =
        take_required(&mut map, "axt_asset_incarnations")?;
    let definitions = asset_definitions.view();
    let incarnations = axt_asset_incarnations.view();
    for (asset_definition_id, incarnation) in incarnations.iter() {
        incarnation
            .validate()
            .map_err(|error| json::Error::InvalidField {
                field: "world.axt_asset_incarnations".to_owned(),
                message: error.to_string(),
            })?;
        if definitions.get(asset_definition_id).is_none() {
            return Err(json::Error::InvalidField {
                field: "world.axt_asset_incarnations".to_owned(),
                message: format!(
                    "AXT incarnation references unregistered asset definition {asset_definition_id}"
                ),
            }
            .into());
        }
    }
    for (asset_definition_id, _) in definitions.iter() {
        if incarnations.get(asset_definition_id).is_none() {
            return Err(json::Error::InvalidField {
                field: "world.axt_asset_incarnations".to_owned(),
                message: format!(
                    "registered asset definition {asset_definition_id} has no AXT incarnation"
                ),
            }
            .into());
        }
    }
    let axt_replay_ledger: Storage<AxtHandleReplayKey, AxtReplayRecord> =
        take_required(&mut map, "axt_replay_ledger")?;
    let axt_spend_nonce_ledger: Storage<AxtAnchoredSpendReplayKeyV1, u64> =
        take_required(&mut map, "axt_spend_nonce_ledger")?;
    let axt_source_transfer_replay_ledger: Storage<
        AxtSourceTransferReplayKeyV1,
        AxtSourceTransferReplayRecordV1,
    > = take_required(&mut map, "axt_source_transfer_replay_ledger")?;
    let axt_handle_budget_ledger: Storage<AxtHandleBudgetKey, AxtHandleBudgetRecord> =
        take_required(&mut map, "axt_handle_budget_ledger")?;
    {
        {
            let nonces = axt_spend_nonce_ledger.view();
            for (key, _) in nonces.iter() {
                key.validate().map_err(|error| json::Error::InvalidField {
                    field: "world.axt_spend_nonce_ledger".to_owned(),
                    message: error.to_string(),
                })?;
            }
            let transfers = axt_source_transfer_replay_ledger.view();
            if nonces.iter().count() != transfers.iter().count() {
                return Err(json::Error::InvalidField {
                    field: "world.axt_source_transfer_replay_ledger".to_owned(),
                    message: "source transfers and issuer nonces must be consumed together"
                        .to_owned(),
                }
                .into());
            }
            let mut referenced_nonces = BTreeSet::new();
            for (key, record) in transfers.iter() {
                key.validate().map_err(|error| json::Error::InvalidField {
                    field: "world.axt_source_transfer_replay_ledger".to_owned(),
                    message: error.to_string(),
                })?;
                record
                    .issuer_nonce
                    .validate()
                    .map_err(|error| json::Error::InvalidField {
                        field: "world.axt_source_transfer_replay_ledger".to_owned(),
                        message: error.to_string(),
                    })?;
                if record.consumed_slot == 0
                    || key.network_id != record.issuer_nonce.issuer_context.network_id
                    || key.dataspace_id != record.issuer_nonce.issuer_context.asset_dsid
                    || nonces.get(&record.issuer_nonce) != Some(&record.consumed_slot)
                    || !referenced_nonces.insert(record.issuer_nonce)
                {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_source_transfer_replay_ledger".to_owned(),
                        message:
                            "source transfer replay record does not match its durable issuer nonce"
                                .to_owned(),
                    }
                    .into());
                }
            }
        }
        {
            let ledger = axt_handle_budget_ledger.view();
            for (key, record) in ledger.iter() {
                record
                    .validate_for_key(key)
                    .map_err(|error| json::Error::InvalidField {
                        field: "world.axt_handle_budget_ledger".to_owned(),
                        message: error.to_string(),
                    })?;
            }
        }
        {
            let replay_ledger = axt_replay_ledger.view();
            let budget_ledger = axt_handle_budget_ledger.view();
            for (key, record) in replay_ledger.iter() {
                record
                    .validate_for_key(key)
                    .map_err(|error| json::Error::InvalidField {
                        field: "world.axt_replay_ledger".to_owned(),
                        message: error.to_string(),
                    })?;
                let budget_record = budget_ledger.get(&record.budget_key).ok_or_else(|| {
                    json::Error::InvalidField {
                        field: "world.axt_replay_ledger".to_owned(),
                        message: "AXT replay record references a missing permanent budget family"
                            .to_owned(),
                    }
                })?;
                budget_record
                    .validate_for_key(&record.budget_key)
                    .map_err(|error| json::Error::InvalidField {
                        field: "world.axt_replay_ledger".to_owned(),
                        message: format!(
                            "AXT replay record references invalid budget evidence: {error}"
                        ),
                    })?;
            }
        }
        {
            let policies = axt_policies.view();
            let counters = axt_handle_counters.view();
            for (dataspace, policy) in policies.iter() {
                let counter = counters.get(dataspace);
                if policy.manifest_root != [0; 32] && counter.is_none() {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "active AXT policy for dataspace {} has no permanent counter ratchet",
                            dataspace.as_u64()
                        ),
                    }
                    .into());
                }
                let expected = counter.map_or(0, AxtHandleCounterRecord::next);
                if policy.next_handle_counter != expected {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "active AXT policy counter {} for dataspace {} disagrees with permanent ratchet {}",
                            policy.next_handle_counter,
                            dataspace.as_u64(),
                            expected
                        ),
                    }.into());
                }
                let expected_generation =
                    counter.map_or(0, AxtHandleCounterRecord::authorization_generation);
                if policy.active_handle_era != expected_generation {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT policy generation {} for dataspace {} disagrees with permanent ratchet {}",
                            policy.active_handle_era,
                            dataspace.as_u64(),
                            expected_generation
                        ),
                    }.into());
                }
            }
            let replay = axt_replay_ledger.view();
            for (key, _) in replay.iter() {
                let counter =
                    counters
                        .get(&key.asset_dsid)
                        .ok_or_else(|| json::Error::InvalidField {
                            field: "world.axt_handle_counters".to_owned(),
                            message: format!(
                                "AXT replay key for dataspace {} has no permanent counter ratchet",
                                key.asset_dsid.as_u64()
                            ),
                        })?;
                if counter.next() <= key.sub_nonce {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT replay key sub-nonce {} is not below permanent ratchet {}",
                            key.sub_nonce,
                            counter.next()
                        ),
                    }
                    .into());
                }
                if counter.authorization_generation() < key.handle_era {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT replay-key generation {} exceeds permanent ratchet generation {}",
                            key.handle_era,
                            counter.authorization_generation()
                        ),
                    }
                    .into());
                }
            }
            let budgets = axt_handle_budget_ledger.view();
            for (key, _) in budgets.iter() {
                let counter = counters.get(&key.asset_dsid()).ok_or_else(|| {
                    json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT budget family for dataspace {} has no permanent counter ratchet",
                            key.asset_dsid().as_u64()
                        ),
                    }
                })?;
                if counter.next() <= AxtHandleCounterRecord::initial(0).next() {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT budget family for dataspace {} has an unadvanced permanent ratchet",
                            key.asset_dsid().as_u64()
                        ),
                    }.into());
                }
                if key.authorization_generation() > counter.authorization_generation() {
                    return Err(json::Error::InvalidField {
                        field: "world.axt_handle_counters".to_owned(),
                        message: format!(
                            "AXT budget-family generation {} exceeds permanent ratchet generation {}",
                            key.authorization_generation(),
                            counter.authorization_generation()
                        ),
                    }.into());
                }
            }
        }
    }
    let tx_sequences: Storage<AccountId, u64> = take_required(&mut map, "tx_sequences")?;
    let triggers_value = map
        .remove("triggers")
        .ok_or_else(|| json::Error::missing_field("triggers"))?;
    let triggers = ivm_seed
        .cast::<TriggerSet>()
        .parse_trigger_set(triggers_value)?;
    let executor: Cell<Executor> = take_required(&mut map, "executor")?;
    let executor_data_model: Cell<ExecutorDataModel> =
        take_required(&mut map, "executor_data_model")?;
    let external_event_buf: Cell<Vec<EventBox>> = take_required(&mut map, "external_event_buf")?;
    let verifying_keys = take_required(&mut map, "verifying_keys")?;
    let verifying_keys_by_circuit = take_required(&mut map, "verifying_keys_by_circuit")?;
    let consensus_keys = take_required(&mut map, "consensus_keys")?;
    let consensus_keys_by_pk = take_required(&mut map, "consensus_keys_by_pk")?;
    let sumeragi_lanes = take_native_lane_custody(&mut map, execution_budget)?;
    let sumeragi_amx: Cell<iroha_data_model::sumeragi_amx::SumeragiAmxState> =
        take_required(&mut map, "sumeragi_amx")?;
    sumeragi_amx
        .view()
        .get()
        .validate()
        .map_err(|error| json::Error::InvalidField {
            field: "world.sumeragi_amx".to_owned(),
            message: error.to_string(),
        })?;
    let sumeragi_amx_participant = take_native_amx_participant(&mut map, execution_budget)?;
    let private_dataspaces: Cell<iroha_data_model::private_dataspace::PrivateDataspaceRegistry> =
        take_required(&mut map, "private_dataspaces")?;
    private_dataspaces
        .view()
        .get()
        .validate()
        .map_err(|error| json::Error::InvalidField {
            field: "world.private_dataspaces".to_owned(),
            message: error.to_string(),
        })?;
    let pedersen_params = take_required(&mut map, "pedersen_params")?;
    let poseidon_params = take_required(&mut map, "poseidon_params")?;
    let runtime_upgrades = take_required(&mut map, "runtime_upgrades")?;
    let privacy_consensus_policy: Cell<iroha_data_model::privacy::PrivacyConsensusPolicyV1> =
        take_required(&mut map, "privacy_consensus_policy")?;
    let privacy_exact12_qualification: Cell<
        Option<iroha_data_model::privacy::PrivacyExact12QualificationRecordV1>,
    > = take_required(&mut map, "privacy_exact12_qualification")?;
    let privacy_activations: Storage<
        crate::privacy_state::PrivacyActivationKeyV1,
        iroha_data_model::privacy::PrivacyProtocolActivationRecordV1,
    > = take_required(&mut map, "privacy_activations")?;
    let private_settlement_governance: Storage<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolGovernanceProjectionV1,
    > = take_required(&mut map, "private_settlement_governance")?;
    let private_settlement_pools: Storage<
        PrivateSettlementPoolKeyV1,
        PrivateSettlementPoolStateV1,
    > = take_required(&mut map, "private_settlement_pools")?;
    let private_settlement_roots: Storage<
        PrivateSettlementRootKeyV1,
        PrivateSettlementRootProvenanceV1,
    > = take_required(&mut map, "private_settlement_roots")?;
    let private_settlement_nullifiers: Storage<
        PrivateSettlementNullifierKeyV1,
        PrivateSettlementFinalizationReferenceV1,
    > = take_required(&mut map, "private_settlement_nullifiers")?;
    let private_settlement_outputs: Storage<
        PrivateSettlementOutputKeyV1,
        PrivateSettlementOutputRecordV1,
    > = take_required(&mut map, "private_settlement_outputs")?;
    // A derived index must follow the same current and predecessor cuts as its
    // authoritative outputs. Rebuilding only current recipients leaves phantom
    // reservations when the last block is replaced after a restart.
    let private_settlement_recipient_index = {
        use crate::private_settlement::global_state::rebuild_private_settlement_recipient_index_v1;
        let invalid_outputs = |error: crate::private_settlement::global_state::PrivateSettlementGlobalStateErrorV1| {
            json::Error::InvalidField {
                field: "world.private_settlement_outputs".to_owned(),
                message: error.to_string(),
            }
        };
        let current =
            rebuild_private_settlement_recipient_index_v1(&private_settlement_outputs.view())
                .map_err(invalid_outputs)?;
        let previous = rebuild_private_settlement_recipient_index_v1(
            &private_settlement_outputs.block_and_revert(),
        )
        .map_err(invalid_outputs)?;
        rebuild_derived_storage_with_previous(current, previous)
    };
    let private_settlement_staged_locks: Storage<
        PrivateSettlementStagedLockKeyV1,
        PrivateSettlementStagedLockRecordV1,
    > = take_required(&mut map, "private_settlement_staged_locks")?;
    let private_settlement_receipts: Storage<
        Hash,
        iroha_data_model::nexus::PrivateSettlementReceiptV1,
    > = take_required(&mut map, "private_settlement_receipts")?;
    let private_settlement_aborts: Storage<
        Hash,
        iroha_data_model::nexus::PrivateSettlementAbortReceiptV1,
    > = take_required(&mut map, "private_settlement_aborts")?;
    crate::private_settlement::global_state::validate_private_settlement_persisted_state_v1(
        &private_settlement_governance.view(),
        &private_settlement_pools.view(),
        &private_settlement_roots.view(),
        &private_settlement_nullifiers.view(),
        &private_settlement_outputs.view(),
        &private_settlement_recipient_index.view(),
        &private_settlement_staged_locks.view(),
        &private_settlement_receipts.view(),
        &private_settlement_aborts.view(),
    )
    .map_err(|error| json::Error::InvalidField {
        field: "world.private_settlement_state".to_owned(),
        message: error.to_string(),
    })?;
    let privacy_pgc_accounts: Storage<
        crate::privacy_state::PrivacyPgcAccountKeyV1,
        crate::privacy_state::PrivacyPgcAccountStateV1,
    > = take_required(&mut map, "privacy_pgc_accounts")?;
    let privacy_pgc_pool_invariants: Storage<
        crate::privacy_state::PrivacyPgcPoolInvariantKeyV1,
        crate::privacy_state::PrivacyPgcPoolInvariantV1,
    > = take_required(&mut map, "privacy_pgc_pool_invariants")?;
    let privacy_nullifiers: Storage<
        crate::privacy_state::PrivacyNullifierKeyV1,
        crate::privacy_state::PrivacyStateItemRecordV1,
    > = take_required(&mut map, "privacy_nullifiers")?;
    let privacy_commitments: Storage<
        crate::privacy_state::PrivacyCommitmentKeyV1,
        crate::privacy_state::PrivacyStateItemRecordV1,
    > = take_required(&mut map, "privacy_commitments")?;
    let privacy_roots: Storage<
        crate::privacy_state::PrivacyRootKeyV1,
        crate::privacy_state::PrivacyRootProvenanceV1,
    > = take_required(&mut map, "privacy_roots")?;
    let privacy_root_heads: Storage<
        crate::privacy_state::PrivacyRootHeadKeyV1,
        crate::privacy_state::PrivacyRootHeadRecordV1,
    > = take_required(&mut map, "privacy_root_heads")?;
    crate::privacy_state::validate_privacy_persisted_state_v1(
        privacy_consensus_policy.view().get(),
        &privacy_activations.view(),
        &privacy_pgc_accounts.view(),
        &privacy_pgc_pool_invariants.view(),
        &privacy_nullifiers.view(),
        &privacy_commitments.view(),
        &privacy_roots.view(),
        &privacy_root_heads.view(),
    )
    .map_err(|message| json::Error::InvalidField {
        field: "world.privacy_state".to_owned(),
        message,
    })?;
    if let Some(qualification) = privacy_exact12_qualification.view().get() {
        qualification
            .validate()
            .map_err(|error| json::Error::InvalidField {
                field: "world.privacy_exact12_qualification".to_owned(),
                message: error.to_string(),
            })?;
    }
    crate::privacy_state::validate_privacy_public_reserve_dependencies_v1(
        &privacy_commitments.view(),
        &accounts.view(),
        &asset_definitions.view(),
    )
    .map_err(|message| json::Error::InvalidField {
        field: "world.privacy_state".to_owned(),
        message,
    })?;
    let proofs = take_required(&mut map, "proofs")?;
    let proof_tags = take_required(&mut map, "proof_tags")?;
    let proofs_by_tag = take_required(&mut map, "proofs_by_tag")?;
    let contract_manifests = take_required(&mut map, "contract_manifests")?;
    let contract_code = take_required(&mut map, "contract_code")?;
    let contract_code_uploads = take_required(&mut map, "contract_code_uploads")?;
    let contract_code_upload_chunks = take_required(&mut map, "contract_code_upload_chunks")?;
    let contract_instances = take_required(&mut map, "contract_instances")?;
    let contract_subject_bindings = take_required(&mut map, "contract_subject_bindings")?;
    let smart_contract_state = take_required(&mut map, "smart_contract_state")?;
    reject_legacy_musubi_state(&smart_contract_state)?;
    let musubi_namespace_bindings = take_musubi_namespace_bindings(&mut map)?;
    let musubi_domain_ownership_generations = take_musubi_domain_ownership_generations(&mut map)?;
    let musubi_packages = take_required(&mut map, "musubi_packages")?;
    let musubi_package_metadata = take_required(&mut map, "musubi_package_metadata")?;
    let musubi_package_members = take_required(&mut map, "musubi_package_members")?;
    let musubi_package_invitations = take_required(&mut map, "musubi_package_invitations")?;
    let musubi_maintainer_directory = take_required(&mut map, "musubi_maintainer_directory")?;
    let musubi_releases = take_required(&mut map, "musubi_releases")?;
    let musubi_archives = take_required(&mut map, "musubi_archives")?;
    let musubi_pin_outbox_high_waters = take_musubi_pin_outbox_high_waters(&mut map)?;
    let musubi_provider_bundle_attestations =
        take_required(&mut map, "musubi_provider_bundle_attestations")?;
    let musubi_archive_locations = take_required(&mut map, "musubi_archive_locations")?;
    let musubi_locations_by_pin = take_required(&mut map, "musubi_locations_by_pin")?;
    let musubi_locations_by_replication_order =
        take_required(&mut map, "musubi_locations_by_replication_order")?;
    let musubi_locations_by_provider = take_required(&mut map, "musubi_locations_by_provider")?;
    let musubi_archive_availability = take_required(&mut map, "musubi_archive_availability")?;
    let musubi_archive_reverse_references =
        take_required(&mut map, "musubi_archive_reverse_references")?;
    let musubi_resolver_index = take_required(&mut map, "musubi_resolver_index")?;
    let musubi_resolver_index_checkpoints = take_musubi_resolver_index_checkpoints(&mut map)?;
    let musubi_public_directory = take_required(&mut map, "musubi_public_directory")?;
    let musubi_aliases = take_required(&mut map, "musubi_aliases")?;
    let musubi_alias_history = take_required(&mut map, "musubi_alias_history")?;
    let musubi_governance_decisions = take_required(&mut map, "musubi_governance_decisions")?;
    let musubi_registry_policy = take_musubi_registry_policy(&mut map)?;
    let musubi_resolver_index_revision = take_musubi_resolver_index_revision(&mut map)?;
    let musubi_replication_shortfall_releases =
        take_musubi_replication_shortfall_releases(&mut map, execution_budget)?;
    let soracloud_sequence_watermark: Cell<u64> =
        take_required(&mut map, "soracloud_sequence_watermark")?;
    let soracloud_service_revisions = take_required(&mut map, "soracloud_service_revisions")?;
    let soracloud_service_deployments = take_required(&mut map, "soracloud_service_deployments")?;
    let soracloud_app_infra_states = take_required(&mut map, "soracloud_app_infra_states")?;
    let soracloud_service_runtime = take_required(&mut map, "soracloud_service_runtime")?;
    let soracloud_inrou_replica_runtime =
        take_required(&mut map, "soracloud_inrou_replica_runtime")?;
    let soracloud_service_audit_events = take_required(&mut map, "soracloud_service_audit_events")?;
    let soracloud_app_infra_audit_events =
        take_required(&mut map, "soracloud_app_infra_audit_events")?;
    let soracloud_service_state_entries =
        take_required(&mut map, "soracloud_service_state_entries")?;
    let soracloud_decryption_request_records =
        take_required(&mut map, "soracloud_decryption_request_records")?;
    let soracloud_agent_apartments = take_required(&mut map, "soracloud_agent_apartments")?;
    let soracloud_agent_apartment_audit_events =
        take_required(&mut map, "soracloud_agent_apartment_audit_events")?;
    let soracloud_training_jobs = take_required(&mut map, "soracloud_training_jobs")?;
    let soracloud_training_job_audit_events =
        take_required(&mut map, "soracloud_training_job_audit_events")?;
    let soracloud_model_registries = take_required(&mut map, "soracloud_model_registries")?;
    let soracloud_model_weight_versions =
        take_required(&mut map, "soracloud_model_weight_versions")?;
    let soracloud_model_weight_audit_events =
        take_required(&mut map, "soracloud_model_weight_audit_events")?;
    let soracloud_model_artifacts = take_required(&mut map, "soracloud_model_artifacts")?;
    let soracloud_model_artifact_audit_events =
        take_required(&mut map, "soracloud_model_artifact_audit_events")?;
    let soracloud_uploaded_model_bundles =
        take_required(&mut map, "soracloud_uploaded_model_bundles")?;
    let soracloud_inrou_host_capabilities =
        take_required(&mut map, "soracloud_inrou_host_capabilities")?;
    let soracloud_hf_sources = take_required(&mut map, "soracloud_hf_sources")?;
    let soracloud_hf_shared_lease_pools =
        take_required(&mut map, "soracloud_hf_shared_lease_pools")?;
    let soracloud_hf_shared_lease_members =
        take_required(&mut map, "soracloud_hf_shared_lease_members")?;
    let soracloud_hf_shared_lease_audit_events =
        take_required(&mut map, "soracloud_hf_shared_lease_audit_events")?;
    let soracloud_inrou_service_placements =
        take_required(&mut map, "soracloud_inrou_service_placements")?;
    let soracloud_mailbox_messages = take_required(&mut map, "soracloud_mailbox_messages")?;
    let soracloud_runtime_receipts = take_required(&mut map, "soracloud_runtime_receipts")?;
    let capacity_declarations = take_required(&mut map, "capacity_declarations")?;
    let pin_manifests = take_required(&mut map, "pin_manifests")?;
    let replication_orders = take_required(&mut map, "replication_orders")?;
    SoracloudInrouPersistedStateV1 {
        sequence_watermark: *soracloud_sequence_watermark.view().get(),
        service_revisions: &soracloud_service_revisions,
        service_deployments: &soracloud_service_deployments,
        app_infra_states: &soracloud_app_infra_states,
        service_runtime: &soracloud_service_runtime,
        inrou_replica_runtime: &soracloud_inrou_replica_runtime,
        service_audit_events: &soracloud_service_audit_events,
        app_infra_audit_events: &soracloud_app_infra_audit_events,
        training_job_audit_events: &soracloud_training_job_audit_events,
        model_weight_audit_events: &soracloud_model_weight_audit_events,
        model_artifact_audit_events: &soracloud_model_artifact_audit_events,
        hf_shared_lease_audit_events: &soracloud_hf_shared_lease_audit_events,
        agent_apartment_audit_events: &soracloud_agent_apartment_audit_events,
        service_state_entries: &soracloud_service_state_entries,
        decryption_request_records: &soracloud_decryption_request_records,
        agent_apartments: &soracloud_agent_apartments,
        training_jobs: &soracloud_training_jobs,
        model_registries: &soracloud_model_registries,
        model_weight_versions: &soracloud_model_weight_versions,
        model_artifacts: &soracloud_model_artifacts,
        hf_sources: &soracloud_hf_sources,
        hf_shared_lease_pools: &soracloud_hf_shared_lease_pools,
        hf_shared_lease_members: &soracloud_hf_shared_lease_members,
        inrou_host_capabilities: &soracloud_inrou_host_capabilities,
        inrou_service_placements: &soracloud_inrou_service_placements,
        uploaded_model_bundles: &soracloud_uploaded_model_bundles,
        mailbox_messages: &soracloud_mailbox_messages,
        runtime_receipts: &soracloud_runtime_receipts,
    }
    .validate()?;
    let provider_owners = take_required(&mut map, "provider_owners")?;
    let provider_ingest_completion_authorities =
        take_required(&mut map, "provider_ingest_completion_authorities")?;
    validate_provider_ingest_completion_authorities(
        &provider_owners,
        &provider_ingest_completion_authorities,
    )?;
    validate_capacity_declarations(&capacity_declarations, &provider_owners)?;
    let zk_assets = take_required(&mut map, "zk_assets")?;
    let elections = take_required(&mut map, "elections")?;
    let citizens = take_required(&mut map, "citizens")?;
    let ministry_agenda_proposals = take_required(&mut map, "ministry_agenda_proposals")?;
    let governance_proposals: Storage<[u8; 32], GovernanceProposalRecord> =
        take_required(&mut map, "governance_proposals")?;
    let governance_referenda = take_required(&mut map, "governance_referenda")?;
    let governance_locks = take_required(&mut map, "governance_locks")?;
    let governance_slashes = take_required(&mut map, "governance_slashes")?;
    let governance_last_unlock_sweep_height =
        take_required(&mut map, "governance_last_unlock_sweep_height")?;
    let governance_unlock_stats = take_required(&mut map, "governance_unlock_stats")?;
    let parliament_attempts = take_required(&mut map, "parliament_attempts")?;
    let tle_key_sessions = take_required(&mut map, "tle_key_sessions")?;
    let tle_key_session_rosters = take_required(&mut map, "tle_key_session_rosters")?;
    let tle_key_session_lifecycles = take_required(&mut map, "tle_key_session_lifecycles")?;
    let tle_active_key_session = take_required(&mut map, "tle_active_key_session")?;
    let timed_ovn_evidence = take_required(&mut map, "timed_ovn_evidence")?;
    let validator_candidate_keys = take_required(&mut map, "validator_candidate_keys")?;
    let validator_committee_transitions =
        take_required(&mut map, "validator_committee_transitions")?;
    let global_beacon_dkg = take_required(&mut map, "global_beacon_dkg")?;
    let global_beacon_key_sessions = take_native_beacon_sessions(&mut map, execution_budget)?;
    let global_beacon_active_session = take_required(&mut map, "global_beacon_active_session")?;
    let global_beacon_latest_pulse = take_required(&mut map, "global_beacon_latest_pulse")?;
    let global_beacon_pulses = take_required(&mut map, "global_beacon_pulses")?;
    let repo_agreements = take_required(&mut map, "repo_agreements")?;
    let settlement_receipts = take_required(&mut map, "settlement_receipts")?;
    let kagemusha_mint_credit_operations = map
        .remove("kagemusha_mint_credit_operations")
        .ok_or_else(|| json::MapVisitor::missing_field("kagemusha_mint_credit_operations"))?
        .into_operation_index(
            ivm_seed.operation_index_budget.clone(),
            ivm_seed.operation_index_refusal,
        )?;
    let kagemusha_issuance_operations = map
        .remove("kagemusha_issuance_operations")
        .ok_or_else(|| json::MapVisitor::missing_field("kagemusha_issuance_operations"))?
        .into_operation_index(
            ivm_seed.operation_index_budget.clone(),
            ivm_seed.operation_index_refusal,
        )?;
    let kagemusha_redemption_id_operations = map
        .remove("kagemusha_redemption_id_operations")
        .ok_or_else(|| json::MapVisitor::missing_field("kagemusha_redemption_id_operations"))?
        .into_operation_index(
            ivm_seed.operation_index_budget.clone(),
            ivm_seed.operation_index_refusal,
        )?;
    let kagemusha_terminal_nullifier_operations = map
        .remove("kagemusha_terminal_nullifier_operations")
        .ok_or_else(|| json::MapVisitor::missing_field("kagemusha_terminal_nullifier_operations"))?
        .into_operation_index(
            ivm_seed.operation_index_budget.clone(),
            ivm_seed.operation_index_refusal,
        )?;
    let manifest_aliases = take_required(&mut map, "manifest_aliases")?;
    validate_musubi_location_reverse_indices(
        &musubi_archives,
        &musubi_archive_locations,
        &pin_manifests,
        &replication_orders,
        &musubi_locations_by_pin,
        &musubi_locations_by_replication_order,
        &musubi_locations_by_provider,
    )?;
    validate_automatic_replication_capacity_state(
        &capacity_declarations,
        &provider_owners,
        &provider_ingest_completion_authorities,
        &pin_manifests,
        &replication_orders,
    )?;
    let content_bundles = take_required(&mut map, "content_bundles")?;
    let content_chunks = take_required(&mut map, "content_chunks")?;
    let asset_escrows = take_required(&mut map, "asset_escrows")?;
    let execution_proof_profiles =
        take_optional(&mut map, "execution_proof_profiles")?.unwrap_or_default();
    let execution_proof_verifications =
        take_optional(&mut map, "execution_proof_verifications")?.unwrap_or_default();
    let game_sessions = take_optional(&mut map, "game_sessions")?.unwrap_or_default();
    let nft_sale_offers = take_optional(&mut map, "nft_sale_offers")?.unwrap_or_default();
    let nft_custody_records = take_optional(&mut map, "nft_custody_records")?.unwrap_or_default();

    let vpn_leases = take_required(&mut map, "vpn_leases")?;
    let merge_hint_roots: Cell<Vec<Hash>> = take_required(&mut map, "merge_hint_roots")?;
    let merge_global_state_root: Cell<Option<Hash>> =
        take_required(&mut map, "merge_global_state_root")?;
    let consensus_evidence: Storage<Hash, EvidenceRecord> =
        take_required(&mut map, "consensus_evidence")?;
    let da_pin_intents_by_ticket = take_required(&mut map, "da_pin_intents_by_ticket")?;
    let da_pin_intents_by_alias = take_required(&mut map, "da_pin_intents_by_alias")?;
    let da_pin_intents_by_manifest = take_required(&mut map, "da_pin_intents_by_manifest")?;
    let da_pin_intents_by_lane_epoch = take_required(&mut map, "da_pin_intents_by_lane_epoch")?;
    reject_unknown(&map, "world")?;
    let world = World(Box::new(WorldData {
        parameters,
        peers,
        consensus_schedule,
        state_accumulator,
        domains,
        domains_by_owner: Storage::default(),
        kaigi_relay_registry: Storage::default(),
        kaigi_account_dependencies: Storage::default(),
        accounts,
        uaid_accounts: Storage::default(),
        account_aliases,
        account_aliases_by_account: Storage::default(),
        account_scope_directory: Storage::default(),
        account_scope_accounts: Storage::default(),
        opaque_uaids: Storage::default(),
        ram_lfe_program_policies,
        identifier_policies,
        fee_sponsor_programs,
        fee_sponsor_program_revisions,
        fee_sponsor_enrollments,
        fee_sponsor_vaults,
        fee_sponsor_budget_counters,
        identifier_claims,
        account_rekey_records,
        account_rekey_records_by_account: Storage::default(),
        account_recovery_policies,
        account_recovery_requests,
        asset_definitions,
        asset_definition_aliases: Storage::default(),
        asset_definition_alias_bindings,
        contract_aliases: Storage::default(),
        contract_alias_bindings,
        asset_definition_domains: Storage::default(),
        domain_asset_definitions: Storage::default(),
        asset_definitions_by_owner: Storage::default(),
        asset_definition_holders: Storage::default(),
        asset_definition_assets: Storage::default(),
        assets_by_account: Storage::default(),
        assets_by_domain: Storage::default(),
        asset_definition_nonzero_holders: Storage::default(),
        assets,
        asset_metadata,
        nfts,
        nfts_by_owner: Storage::default(),
        nfts_by_domain: Storage::default(),
        rwas,
        rwas_by_owner: Storage::default(),
        rwas_by_status: Storage::default(),
        rwas_by_frozen: Storage::default(),
        roles,
        account_permissions,
        account_roles,
        oracle_feeds,
        oracle_observations,
        oracle_history,
        oracle_provider_stats,
        oracle_disputes,
        oracle_changes,
        defi_oracle_attestations,
        twitter_bindings,
        twitter_bindings_by_uaid,
        viral_reward_budget,
        viral_campaign_budget,
        viral_daily_counters,
        viral_binding_claims,
        viral_escrows,
        viral_bonus_paid,
        asset_escrows,
        asset_escrows_by_seller: Storage::default(),
        asset_escrows_by_buyer: Storage::default(),
        asset_escrows_by_status: Storage::default(),
        execution_proof_profiles,
        execution_proof_verifications,
        game_sessions,
        nft_sale_offers,
        nft_custody_records,
        nft_custody_by_nft: Storage::default(),
        nft_custody_owner_refs: Storage::default(),
        nft_custody_domain_refs: Storage::default(),

        game_custody_by_account: Storage::default(),
        game_account_references: Storage::default(),
        game_asset_references: Storage::default(),
        vpn_leases,
        vpn_active_lease_by_account: Storage::default(),
        vpn_active_lease_by_address_slot: Storage::default(),
        vpn_settled_leases_by_account: Storage::default(),
        uaid_dataspaces: Storage::default(),
        space_directory_manifests: Storage::default(),
        axt_policies,
        axt_handle_counters,
        axt_asset_incarnations,
        axt_replay_ledger,
        axt_spend_nonce_ledger,
        axt_source_transfer_replay_ledger,
        axt_handle_budget_ledger,
        tx_sequences,
        triggers,
        executor,
        executor_data_model,
        verifying_keys,
        verifying_keys_by_circuit,
        consensus_keys,
        consensus_keys_by_pk,
        sumeragi_lanes,
        sumeragi_amx,
        sumeragi_amx_participant,
        private_dataspaces,
        pedersen_params,
        poseidon_params,
        runtime_upgrades,
        privacy_consensus_policy,
        privacy_exact12_qualification,
        privacy_activations,
        private_settlement_governance,
        private_settlement_pools,
        private_settlement_roots,
        private_settlement_nullifiers,
        private_settlement_outputs,
        private_settlement_recipient_index,
        private_settlement_staged_locks,
        private_settlement_receipts,
        private_settlement_aborts,
        privacy_pgc_accounts,
        privacy_pgc_pool_invariants,
        privacy_nullifiers,
        privacy_commitments,
        privacy_roots,
        privacy_root_heads,
        proofs,
        proofs_by_status: Storage::default(),
        proof_tags,
        proofs_by_tag,
        contract_manifests,
        contract_code,
        contract_code_uploads,
        contract_code_upload_chunks,
        contract_instances,
        contract_subject_bindings,
        contract_subject_addresses: Storage::default(),
        smart_contract_state,
        musubi_namespace_bindings,
        musubi_domain_ownership_generations,
        musubi_packages,
        musubi_package_metadata,
        musubi_package_members,
        musubi_package_invitations,
        musubi_maintainer_directory,
        musubi_releases,
        musubi_archives,
        musubi_pin_outbox_high_waters,
        musubi_provider_bundle_attestations,
        musubi_archive_locations,
        musubi_locations_by_pin,
        musubi_locations_by_replication_order,
        musubi_locations_by_provider,
        musubi_archive_availability,
        musubi_archive_reverse_references,
        musubi_resolver_index,
        musubi_resolver_index_checkpoints,
        musubi_public_directory,
        musubi_aliases,
        musubi_alias_history,
        musubi_governance_decisions,
        musubi_registry_policy,
        musubi_resolver_index_revision,
        musubi_replication_shortfall_releases,
        soracloud_sequence_watermark,
        soracloud_service_revisions,
        soracloud_service_deployments,
        soracloud_app_infra_states,
        soracloud_service_runtime,
        soracloud_inrou_replica_runtime,
        soracloud_service_audit_events,
        soracloud_app_infra_audit_events,
        soracloud_service_state_entries,
        soracloud_decryption_request_records,
        soracloud_agent_apartments,
        soracloud_agent_apartment_audit_events,
        soracloud_training_jobs,
        soracloud_training_job_audit_events,
        soracloud_model_registries,
        soracloud_model_weight_versions,
        soracloud_model_weight_audit_events,
        soracloud_model_artifacts,
        soracloud_model_artifact_audit_events,
        soracloud_uploaded_model_bundles,
        soracloud_inrou_host_capabilities,
        soracloud_hf_sources,
        soracloud_hf_shared_lease_pools,
        soracloud_hf_shared_lease_members,
        soracloud_hf_shared_lease_audit_events,
        soracloud_inrou_service_placements,
        soracloud_mailbox_messages,
        soracloud_runtime_receipts,
        capacity_declarations,
        capacity_fee_ledger: Storage::default(),
        capacity_disputes: Storage::default(),
        provider_owners,
        provider_ingest_completion_authorities,
        da_pin_intents_by_ticket,
        da_pin_intents_by_alias,
        da_pin_intents_by_manifest,
        da_pin_intents_by_lane_epoch,
        sorafs_pricing: Cell::default(),
        provider_credit_ledger: Storage::default(),
        pin_manifests,
        manifest_aliases,
        replication_orders,
        content_bundles,
        content_chunks,
        soradns_directory_records: Storage::default(),
        soradns_directory_pending: Storage::default(),
        soradns_directory_latest: Cell::default(),
        soradns_directory_history: Storage::default(),
        soradns_directory_prev_of: Storage::default(),
        soradns_directory_revocations: Storage::default(),
        soradns_release_signers: Storage::default(),
        soradns_rotation_policy: Cell::default(),
        soradns_last_publish_ms: Cell::default(),
        soradns_history_len: Cell::default(),
        repo_agreements,
        repo_agreements_by_initiator: Storage::default(),
        repo_agreements_by_counterparty: Storage::default(),
        repo_agreements_by_custodian: Storage::default(),
        settlement_receipts,
        kagemusha_mint_credit_operations,
        kagemusha_issuance_operations,
        kagemusha_redemption_id_operations,
        kagemusha_terminal_nullifier_operations,
        domain_committees,
        domain_endorsement_policies,
        domain_endorsements,
        domain_endorsements_by_domain,
        public_lane_validators: Storage::default(),
        public_lane_stake_shares: Storage::default(),
        public_lane_rewards: Storage::default(),
        public_lane_reward_claims: Storage::default(),
        public_lane_reward_accruals: Storage::default(),
        public_lane_reward_reserves: Storage::default(),
        public_lane_stake_custody: Storage::default(),
        public_lane_stake_reserves: Storage::default(),
        zk_assets,
        confidential_policy_transition_index: Storage::default(),
        confidential_policy_transition_counts: Storage::default(),
        elections,
        citizens,
        ministry_agenda_proposals,
        governance_proposals,
        governance_referenda,
        governance_locks,
        governance_lock_expiry_index: Storage::default(),
        validation_fee_proposal_index: Storage::default(),
        governance_slashes,
        governance_last_unlock_sweep_height,
        governance_unlock_stats,
        parliament_attempts,
        parliament_attempt_counts: Cell::default(),
        parliament_member_reference_counts: Storage::default(),
        parliament_timed_ovn_resource_reservations: Storage::default(),
        parliament_timed_ovn_casting_candidates: Storage::default(),
        parliament_required_beacon_pulse_slots: Storage::default(),
        parliament_certified_enactments: Storage::default(),
        parliament_unavailable_beacon_pulse_slots: Storage::default(),
        parliament_tle_key_session_retention_deadlines: Storage::default(),
        tle_key_session_selection_intervals: Storage::default(),
        tle_key_sessions,
        tle_key_session_rosters,
        tle_key_session_lifecycles,
        tle_active_key_session,
        timed_ovn_evidence,
        validator_candidate_keys,
        validator_committee_transitions,
        global_beacon_dkg,
        global_beacon_key_sessions,
        global_beacon_active_session,
        global_beacon_latest_pulse,
        global_beacon_pulses,
        global_beacon_pulse_slots: Storage::default(),
        merge_hint_roots,
        merge_global_state_root,
        consensus_evidence,
        // SCCP v1 state is restored from its own snapshot envelope after `parse_world`.
        sccp_parameters: Cell::default(),
        sccp_reset_nonce: Cell::default(),
        sccp_bridge_keys: Storage::default(),
        sccp_bridge_key_owners: Storage::default(),
        sccp_rosters: Storage::default(),
        sccp_roster_current: Cell::default(),
        sccp_heartbeat_marker: Cell::default(),
        sccp_block_leaves: Storage::default(),
        sccp_block_commitments: Storage::default(),
        sccp_history: Cell::default(),
        sccp_history_leaves: Storage::default(),
        sccp_attestation_subjects: Storage::default(),
        sccp_attestation_status: Storage::default(),
        sccp_attestation_signatures: Storage::default(),
        sccp_attestation_faults: Storage::default(),
        sccp_member_last_signed: Storage::default(),
        sccp_handoff_stalled: Storage::default(),
        sccp_prune_cursor: Cell::default(),
        sccp_outbound_messages: Storage::default(),
        sccp_outbound_by_nonce: Storage::default(),
        sccp_control_messages: Storage::default(),
        sccp_routes: Storage::default(),
        sccp_destination_words: Storage::default(),
        sccp_governance_revisions: Storage::default(),
        sccp_inbound_messages: Storage::default(),
        sccp_pending_counts: Storage::default(),
        sccp_light_clients: Storage::default(),
        sccp_light_client_sets: Storage::default(),
        sccp_light_client_checkpoints: Storage::default(),
        sccp_light_client_stride_index: Storage::default(),
        external_event_buf,
    }));
    Ok(world)
}

fn parse_world(
    execution_budget: &iroha_allocation::AllocationBudget,
    map: SnapshotJsonMap<'_>,
    ivm_seed: &IvmSeed<'_, World>,
) -> Result<World, StateRestoreError> {
    let mut world = decode_world_fields(execution_budget, map, ivm_seed)?;
    crate::smartcontracts::isi::multisig::validate_persisted_proposals(&world.view()).map_err(
        |error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                StateRestoreError::Serialization(json::Error::InvalidField {
                    field: "world.smart_contract_state.multisig/proposal".into(),
                    message: error.to_string(),
                })
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                StateRestoreError::ExecutionDeferred(reason)
            }
        },
    )?;
    validate_domain_endorsement_index(&world)?;
    validate_da_pin_persistence(&world)?;
    validator_committee::validate_persisted_progress(&world.view()).map_err(|message| {
        json::Error::InvalidField {
            field: "world.validator_committee".to_owned(),
            message,
        }
    })?;
    proof_tag_index::validate_proof_tag_index(&world)?;
    verifying_key_index::validate_verifying_key_index(&world)?;
    validate_asset_transfer_control_persistence_v1(&world)?;
    super::retail_daily_limit_state::validate_persistence(&mut world).map_err(|message| {
        json::Error::InvalidField {
            field: "world.smart_contract_state.retail_day_v1".to_owned(),
            message,
        }
    })?;
    world
        .rebuild_global_beacon_pulse_slots()
        .map_err(invalid_global_beacon_persistence)?;
    validate_parliament_attempt_encoded_size_bounds_v1(&world)?;
    validate_no_standalone_governance_state_for_typed_proposals_v1(&world)?;
    {
        let parliament_attempts_view = world.parliament_attempts.view();
        let governance_proposals_view = world.governance_proposals.view();
        let mut parliament_attempts_by_proposal = BTreeMap::<
            iroha_data_model::governance::types::ProposalContentId,
            Vec<&ParliamentAttemptStateV1>,
        >::new();
        for (attempt_id, attempt) in parliament_attempts_view.iter() {
            if attempt_id != &attempt.attempt().id {
                return Err(json::Error::InvalidField {
                    field: "parliament_attempts".into(),
                    message:
                        "Parliament attempt storage key differs from its embedded canonical id"
                            .into(),
                }
                .into());
            }
            attempt
                .validate()
                .map_err(|error| json::Error::InvalidField {
                    field: "parliament_attempts".into(),
                    message: format!("invalid persisted Parliament attempt: {error}"),
                })?;
            let proposal_id = *attempt.proposal_content_id().as_bytes();
            let proposal = governance_proposals_view.get(&proposal_id).ok_or_else(|| {
                json::Error::InvalidField {
                    field: "parliament_attempts".into(),
                    message: "Parliament attempt references a missing exact governance proposal"
                        .to_owned(),
                }
            })?;
            attempt
            .validate_proposal_bindings_v1(&proposal.kind)
            .map_err(|error| json::Error::InvalidField {
                field: "parliament_attempts".into(),
                message: format!(
                    "Parliament attempt differs from its exact governance proposal policy: {error}"
                ),
            })?;
            parliament_attempts_by_proposal
                .entry(attempt.proposal_content_id())
                .or_default()
                .push(attempt);
        }
        validate_tle_ovn_persistence(&world)?;
        validate_global_beacon_persistence(&world)?;
        for (proposal_id, proposal) in governance_proposals_view.iter() {
            if let Some(reason) = proposal.first_release_exact_json_u64_invariant_error() {
                return Err(json::Error::InvalidField {
                    field: "governance_proposals".into(),
                    message: reason.to_owned(),
                }
                .into());
            }
            if proposal.kind.fingerprint() != *proposal_id {
                return Err(json::Error::InvalidField {
                    field: "governance_proposals".into(),
                    message:
                        "governance proposal storage key differs from its exact typed fingerprint"
                            .to_owned(),
                }
                .into());
            }
            if proposal
                .kind
                .proposal_operator_v1()
                .is_some_and(|operator| operator != &proposal.proposer)
            {
                return Err(json::Error::InvalidField {
                    field: "governance_proposals".into(),
                    message: "governance proposal operator differs from its retained proposer"
                        .to_owned(),
                }
                .into());
            }
            let governed_subject = proposal.kind.governed_subject_id_v1().map_err(|error| {
                json::Error::InvalidField {
                    field: "governance_proposals".into(),
                    message: format!(
                        "failed to derive governance proposal's governed subject: {error}"
                    ),
                }
            })?;
            let proposal_content_id =
                iroha_data_model::governance::types::ProposalContentId::new(*proposal_id);
            let mut proposal_attempts = parliament_attempts_by_proposal
                .get(&proposal_content_id)
                .cloned()
                .unwrap_or_default();
            proposal_attempts.sort_unstable_by_key(|attempt| attempt.attempt().sequence);
            crate::governance::parliament::validate_parliament_randomness_redraw_lineage_v1(
                proposal_attempts.iter().copied(),
            )
            .map_err(|error| json::Error::InvalidField {
                field: "parliament_attempts".into(),
                message: format!(
                    "governance Parliament randomness-redraw lineage is invalid: {error}"
                ),
            })?;
            for (index, attempt) in proposal_attempts.iter().enumerate() {
                let expected_sequence =
                    u32::try_from(index).map_err(|_| json::Error::InvalidField {
                        field: "parliament_attempts".into(),
                        message:
                            "governance Parliament attempt history exceeds the u32 sequence domain"
                                .to_owned(),
                    })?;
                if attempt.attempt().sequence != expected_sequence {
                    return Err(json::Error::InvalidField {
                    field: "parliament_attempts".into(),
                    message:
                        "governance Parliament attempt history is not an exact contiguous sequence"
                            .to_owned(),
                }.into());
                }
                if attempt.policy_version()
                    != crate::governance::parliament::PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1
                {
                    return Err(json::Error::InvalidField {
                        field: "parliament_attempts".into(),
                        message: "governance Parliament attempt has a non-V1 policy version"
                            .to_owned(),
                    }
                    .into());
                }
                if let Some(certificate) = attempt.certificate() {
                    let certificate_subject = match certificate.expected_head {
                        iroha_data_model::governance::types::GovernanceExpectedHeadV1::Absent(
                            head,
                        ) => head.subject_id,
                        iroha_data_model::governance::types::GovernanceExpectedHeadV1::Present(
                            head,
                        ) => head.subject_id,
                    };
                    if certificate.proposal_content_id != proposal_content_id
                        || certificate.governance_attempt_sequence != expected_sequence
                        || certificate.effect_preimage_hash
                            != proposal.kind.effect_preimage_hash_v1()
                        || certificate_subject != governed_subject
                    {
                        return Err(json::Error::InvalidField {
                        field: "parliament_attempts".into(),
                        message: "Parliament certificate differs from its exact governance proposal effect"
                            .to_owned(),
                    }.into());
                    }
                }
                let is_latest = index + 1 == proposal_attempts.len();
                if !is_latest
                && !matches!(
                    attempt.attempt().status,
                    iroha_data_model::governance::types::GovernanceAttemptStatusV1::Rejected
                        | iroha_data_model::governance::types::GovernanceAttemptStatusV1::Superseded
                        | iroha_data_model::governance::types::GovernanceAttemptStatusV1::ExecutionFailed
                )
            {
                return Err(json::Error::InvalidField {
                    field: "parliament_attempts".into(),
                    message:
                        "a non-latest Parliament attempt is not a retryable terminal predecessor"
                            .to_owned(),
                }.into());
            }
            }
            let latest_attempt = proposal_attempts.last().copied();
            let status_matches_attempt = proposal_status_matches_latest_attempt_v1(
                proposal.status,
                latest_attempt.map(|attempt| attempt.attempt().status),
            ) && latest_attempt.is_none_or(|attempt| {
                proposal.status != GovernanceProposalStatus::Enacted
                    || attempt.certificate().is_some_and(|certificate| {
                        attempt.terminal_height() == Some(certificate.enact_at_height)
                    })
            });
            if !status_matches_attempt {
                return Err(json::Error::InvalidField {
                field: "governance_proposals".into(),
                message:
                    "governance proposal status does not match its exact Parliament attempt outcome"
                        .to_owned(),
            }.into());
            }
        }
        crate::validation_fee::validate_persisted_policy_registry_governance_v1(&world.view())
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(message) => {
                    StateRestoreError::Serialization(json::Error::InvalidField {
                        field: "parameters".into(),
                        message,
                    })
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    StateRestoreError::ExecutionDeferred(reason)
                }
            })?;
        MusubiPersistedState {
            namespace_bindings: &world.musubi_namespace_bindings,
            packages: &world.musubi_packages,
            package_metadata: &world.musubi_package_metadata,
            package_members: &world.musubi_package_members,
            package_invitations: &world.musubi_package_invitations,
            maintainer_directory: &world.musubi_maintainer_directory,
            releases: &world.musubi_releases,
            archives: &world.musubi_archives,
            provider_bundle_attestations: &world.musubi_provider_bundle_attestations,
            archive_locations: &world.musubi_archive_locations,
            archive_availability: &world.musubi_archive_availability,
            archive_reverse_references: &world.musubi_archive_reverse_references,
            resolver_index: &world.musubi_resolver_index,
            resolver_index_checkpoints: &world.musubi_resolver_index_checkpoints,
            public_directory: &world.musubi_public_directory,
            aliases: &world.musubi_aliases,
            alias_history: &world.musubi_alias_history,
            governance_decisions: &world.musubi_governance_decisions,
            resolver_index_revision: world.musubi_resolver_index_revision.view().get().get(),
            replication_shortfall_releases: *world
                .musubi_replication_shortfall_releases
                .view()
                .get(),
        }
        .validate()?;
        musubi_derived::validate_musubi_derived_cuts(&world)?;
        musubi_universal::validate_musubi_universal_projection_cuts(&world, execution_budget)?;
        validate_musubi_governance_provenance(&world)?;
        validate_musubi_live_projections(&world, execution_budget)?;
        world
            .validate_numeric_asset_invariants()
            .map_err(|message| json::Error::InvalidField {
                field: "world.assets".into(),
                message,
            })?;
        world
            .validate_quantity_ledger_invariants()
            .map_err(|error| {
                error.map_rejection(|message| json::Error::InvalidField {
                    field: "world.numeric_ledgers".into(),
                    message,
                })
            })?;
    }
    world.rebuild_domain_owner_index();
    world
        .rebuild_account_identity_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "uaid_accounts".into(),
            message,
        })?;
    world
        .rebuild_account_alias_index()
        .map_err(|message| json::Error::InvalidField {
            field: "account_aliases".into(),
            message,
        })?;
    world
        .rebuild_account_scope_directory()
        .map_err(|message| json::Error::InvalidField {
            field: "account_scope_directory".into(),
            message,
        })?;
    world
        .rebuild_account_rekey_records()
        .map_err(|message| json::Error::InvalidField {
            field: "account_rekey_records".into(),
            message,
        })?;
    crate::smartcontracts::isi::kaigi::rebuild_kaigi_relay_registry(&mut world).map_err(
        |message| json::Error::InvalidField {
            field: "kaigi_relay_registry".into(),
            message,
        },
    )?;
    crate::smartcontracts::isi::kaigi::rebuild_kaigi_account_dependencies(&mut world).map_err(
        |message| json::Error::InvalidField {
            field: "kaigi_account_dependencies".into(),
            message,
        },
    )?;
    world
        .rebuild_asset_definition_alias_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "asset_definition_alias_bindings".into(),
            message,
        })?;
    world
        .rebuild_contract_alias_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "contract_alias_bindings".into(),
            message,
        })?;
    world
        .rebuild_asset_definition_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "asset_definition_domains".into(),
            message,
        })?;
    world
        .rebuild_confidential_policy_transition_index()
        .map_err(|message| json::Error::InvalidField {
            field: "asset_definitions.confidential_policy.pending_transition".into(),
            message,
        })?;
    world
        .rebuild_governance_read_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: if message.starts_with(ELECTION_RESTORE_ERROR_PREFIX_V1) {
                "elections"
            } else {
                "parliament_attempts"
            }
            .into(),
            message,
        })?;
    world.rebuild_nft_owner_index();
    world
        .rebuild_nft_custody_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "nft_custody_records".into(),
            message,
        })?;
    world.rebuild_rwa_indexes();
    world.rebuild_escrow_indexes();
    world
        .rebuild_game_session_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "game_sessions".into(),
            message,
        })?;
    world
        .rebuild_vpn_lease_indexes()
        .map_err(|message| json::Error::InvalidField {
            field: "vpn_leases".into(),
            message,
        })?;
    world.rebuild_repo_agreement_indexes();
    world.rebuild_proof_status_index();
    world
        .validate_identifier_claims()
        .map_err(|message| json::Error::InvalidField {
            field: "identifier_claims".into(),
            message,
        })?;
    Ok(world)
}

#[cfg(test)]
mod asset_transfer_control_persistence_tests {
    use super::*;
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{
            ASSET_TRANSFER_CONTROL_METADATA_KEY, AssetBalancePolicy, AssetDefinition,
            AssetDefinitionId, AssetTransferControlRecord, AssetTransferControlStoreV1,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;
    use iroha_test_samples::ALICE_ID;

    fn account_with_transfer_store(store: AssetTransferControlStoreV1) -> Account {
        let authority = (*ALICE_ID).clone();
        let mut metadata = Metadata::default();
        metadata.insert(
            ASSET_TRANSFER_CONTROL_METADATA_KEY
                .parse()
                .expect("transfer-control metadata key"),
            Json::new(store),
        );
        Account::new(authority.clone())
            .with_metadata(metadata)
            .build(&authority)
    }

    fn world_with_transfer_store(store: AssetTransferControlStoreV1) -> World {
        let authority = (*ALICE_ID).clone();
        let asset_definition_id = transfer_asset_definition_id();
        World::with(
            [],
            [account_with_transfer_store(store)],
            [AssetDefinition::numeric(
                asset_definition_id,
                "rose".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&authority)],
        )
    }

    fn transfer_asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("transfer", "controls").expect("domain id"),
            "rose".parse().expect("asset name"),
        )
    }

    fn active_record() -> AssetTransferControlRecord {
        let mut record = AssetTransferControlRecord::new(transfer_asset_definition_id());
        record.blacklisted = true;
        record
    }

    #[test]
    fn snapshot_transfer_control_store_must_be_nonempty_and_canonical() {
        let record = active_record();
        assert!(
            validate_asset_transfer_control_persistence_v1(&world_with_transfer_store(
                AssetTransferControlStoreV1 {
                    controls: vec![record.clone()],
                },
            ))
            .is_ok()
        );

        for invalid in [
            AssetTransferControlStoreV1::default(),
            AssetTransferControlStoreV1 {
                controls: vec![record.clone(), record],
            },
        ] {
            let error =
                validate_asset_transfer_control_persistence_v1(&world_with_transfer_store(invalid))
                    .expect_err("ambiguous first-release transfer-control snapshot must fail fast");
            assert!(
                error
                    .to_string()
                    .contains("first-release snapshot is incompatible"),
                "unexpected snapshot incompatibility: {error}"
            );
        }
    }

    #[test]
    fn snapshot_transfer_control_store_rejects_missing_asset_definition() {
        let record = active_record();
        let world = World::with(
            [],
            [account_with_transfer_store(AssetTransferControlStoreV1 {
                controls: vec![record],
            })],
            [],
        );

        let error = validate_asset_transfer_control_persistence_v1(&world)
            .expect_err("first-release restore must reject orphaned transfer controls");
        assert!(
            error.to_string().contains("missing asset definition"),
            "unexpected snapshot incompatibility: {error}"
        );
    }
}

struct BuildStateInputs {
    execution_budget: iroha_allocation::AllocationBudget,
    lane_manifests: LaneManifestRegistryHandle,
    canonical_runtime: Cell<SnapshotNexusRuntime>,
    native_execution_tip: Option<native_execution_tip::TipCell>,
    world: World,
    block_hashes: BlockHashes,
    transactions: TransactionsStorage,
    commit_topology: Cell<Vec<PeerId>>,
    prev_commit_topology: Cell<Vec<PeerId>>,
    ivm: IVM,
    nexus: iroha_config::parameters::actual::Nexus,
    chain_id: iroha_model_base::chain::ChainId,
    network_id: iroha_data_model::NetworkId,
    nexus_runtime_restored_from_snapshot: bool,
    kura: Arc<Kura>,
    query_handle: LiveQueryStoreHandle,
    #[cfg(feature = "telemetry")]
    telemetry: StateTelemetry,
}
fn build_state(
    inputs: BuildStateInputs,
    allow_durable_recovery: bool,
    emergency_fast: bool,
) -> Result<Box<State>, MergeLedgerCommitError> {
    let BuildStateInputs {
        execution_budget,
        lane_manifests,
        canonical_runtime,
        native_execution_tip,
        world,
        block_hashes,
        transactions,
        commit_topology,
        prev_commit_topology,
        ivm,
        nexus,
        chain_id,
        network_id,
        nexus_runtime_restored_from_snapshot,
        kura,
        query_handle,
        #[cfg(feature = "telemetry")]
        telemetry,
    } = inputs;
    let native_execution_tip = match native_execution_tip {
        Some(original) => original,
        None => native_execution_tip::empty_cell(&execution_budget)?,
    };
    #[cfg(feature = "telemetry")]
    let telemetry_seed = telemetry.clone();
    validate_no_standalone_governance_state_for_typed_proposals_v1(&world).map_err(|error| {
        MergeLedgerCommitError::ExecutionStatePublication(format!(
            "restored standalone governance state is invalid: {error}"
        ))
    })?;
    let initial_crypto = iroha_config::parameters::actual::Crypto::default();
    let da_receipt_cursors =
        PublicationRwLock::try_new(DaReceiptCursorIndex::default(), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?;
    let da_shard_cursors =
        PublicationRwLock::try_new(DaShardCursorIndex::default(), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?;
    let restored_height = u64::try_from(block_hashes.committed_height()).map_err(|error| {
        MergeLedgerCommitError::ExecutionStatePublication(format!(
            "restored committed height does not fit the Parliament height domain: {error}"
        ))
    })?;
    crate::smartcontracts::isi::sorafs_moderation::validate_persisted_moderation_schema_v1(
        &world.view(),
    )
    .map_err(|error| {
        MergeLedgerCommitError::ExecutionStatePublication(format!(
            "incompatible persisted SoraFS moderation V1 policy/appeal/anchor/case state; regenerate first-release genesis and snapshots: {error}"
        ))
    })?;
    {
        // Preserve the global State view lock order even though restoration is single-threaded.
        let committed_block_hashes = block_hashes.view();
        let world_view = world.view();
        crate::smartcontracts::isi::sorafs_moderation::validate_persisted_moderation_anchor_history_v1(
            &world_view,
            &committed_block_hashes,
        )
        .map_err(|error| {
            MergeLedgerCommitError::ExecutionStatePublication(format!(
                "restored SoraFS moderation sortition anchors are not bound to committed block history: {error}"
            ))
        })?;
    }
    if !emergency_fast {
        validate_tle_ovn_snapshot_network_v1(&world, &network_id)
            .map_err(MergeLedgerCommitError::ExecutionStatePublication)?;
        for (proposal_id, proposal) in world.governance_proposals.view().iter() {
            if let Some(reason) = proposal.first_release_exact_json_u64_invariant_error() {
                return Err(MergeLedgerCommitError::ExecutionStatePublication(format!(
                    "restored governance proposal {} violates the first-release JSON number invariant: {reason}",
                    hex::encode(proposal_id),
                )));
            }
            if proposal.created_height > restored_height {
                return Err(MergeLedgerCommitError::ExecutionStatePublication(format!(
                    "restored governance proposal {} was created at future height {} beyond committed height {restored_height}",
                    hex::encode(proposal_id),
                    proposal.created_height,
                )));
            }
        }
        for (governance_attempt_id, attempt) in world.parliament_attempts.view().iter() {
            attempt
                .validate_restored_height_v1(restored_height)
                .map_err(|error| {
                    MergeLedgerCommitError::ExecutionStatePublication(format!(
                        "restored Parliament attempt {governance_attempt_id:?} has impossible lifecycle state at committed height {restored_height}: {error}"
                    ))
                })?;
        }
    }
    let canonical_query_index_status = {
        (restored_height > 0).then(|| QueryIndexStatus {
            indexed_height: restored_height,
            indexed_block_hash: block_hashes.view().last().copied(),
        })
    };
    let LoadedStateJournals {
        query_index: query_index_journal,
        query_projection_checkpoint: query_projection_checkpoint_journal,
    } = load_state_journals(&kura, canonical_query_index_status, allow_durable_recovery);
    let active_runtime = allow_durable_recovery && !emergency_fast;
    let mut pipeline = default_pipeline();
    pipeline.ivm_execution_max_bytes = execution_budget.limit_bytes();
    let pipeline_parallelism = if active_runtime {
        PipelineParallelism::new(&pipeline)
    } else {
        PipelineParallelism::inert(&pipeline)
    };
    let stateless_cache_cap = pipeline.stateless_cache_cap;
    let pipeline_cache_size = pipeline.cache_size;
    let tiered_backend = Arc::new(PublicationMutex::new(TieredStateBackend::default()));
    let tiered_snapshot_worker = if active_runtime {
        TieredSnapshotWorker::new(
            Arc::clone(&tiered_backend),
            #[cfg(feature = "telemetry")]
            Some(telemetry_seed.clone()),
        )
    } else {
        TieredSnapshotWorker::inert(
            Arc::clone(&tiered_backend),
            #[cfg(feature = "telemetry")]
            None,
        )
    };
    let durable_blocks = kura.exact_durable_blocks_count().map_err(|error| {
        MergeLedgerCommitError::ExecutionStatePublication(format!(
            "failed to read the exact durable Kura boundary: {error}"
        ))
    })?;
    let latest_block_header = if emergency_fast {
        None
    } else {
        NonZeroUsize::new(durable_blocks)
            .map(|height| kura.get_block(height, &execution_budget))
            .transpose()
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    MergeLedgerCommitError::ExecutionDeferred(reason)
                }
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                    MergeLedgerCommitError::ExecutionStatePublication(format!(
                        "cannot read original latest block: {error}"
                    ))
                }
            })?
            .flatten()
            .map(|block| block.header())
    };
    let evidence_preparation_bytes = nexus.storage.consensus_evidence_preparation_bytes;
    let stake_index_bytes = nexus.storage.consensus_stake_index_bytes;
    let mut state = Box::new(State {
        world,
        block_hashes,
        latest_block_header: PublicationRwLock::try_new(latest_block_header, &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,

        transactions,
        commit_topology,
        prev_commit_topology,
        da_commitments: PublicationRwLock::try_new(DaCommitmentStore::default(), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        da_confidential_compute: PublicationRwLock::try_new(
            ConfidentialComputeStore::default(),
            &execution_budget,
        )
        .map_err(StateStorageAdmissionError::World)?,
        da_receipt_cursors,
        da_shard_cursors,
        da_shard_cursor_persistor: DaShardCursorJournalPersistor::new(),
        query_index_journal: parking_lot::RwLock::new(query_index_journal),
        query_index_journal_persistence_lock: parking_lot::Mutex::new(()),
        query_projection_checkpoint_journal: parking_lot::RwLock::new(
            query_projection_checkpoint_journal,
        ),
        query_projection_checkpoint_journal_persistence_lock: parking_lot::Mutex::new(()),
        da_pin_intents: PublicationRwLock::try_new(DaPinStore::default(), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,

        lane_manifests: PublicationRwLock::try_new(lane_manifests, &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        provisional_emergency_lane_manifests_consumed: false,
        lane_privacy_registry: PublicationRwLock::try_new(
            Arc::new(LanePrivacyRegistry::empty()),
            &execution_budget,
        )
        .map_err(StateStorageAdmissionError::World)?,
        lane_compliance: parking_lot::RwLock::new(None),
        da_index_hydration_fence: parking_lot::Mutex::new(()),
        da_indexes_hydrated: PublicationRwLock::try_new(None, &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        ivm,
        kura,
        query_handle,
        oracle: default_oracle(),
        pipeline,
        pipeline_parallelism,
        soracloud_runtime: parking_lot::RwLock::new(None),
        stateless_validation_cache: parking_lot::Mutex::new(StatelessValidationCache::new(
            stateless_cache_cap,
        )),
        trigger_ivm_cache: parking_lot::Mutex::new(IvmCache::with_prepared_contract_cache(
            pipeline_cache_size,
            PreparedContractCache::with_execution_budget(
                pipeline_cache_size,
                execution_budget.clone(),
            ),
        )),
        contract_query_ivm_cache: parking_lot::Mutex::new(IvmCache::with_prepared_contract_cache(
            pipeline_cache_size,
            PreparedContractCache::with_execution_budget(
                pipeline_cache_size,
                execution_budget.clone(),
            ),
        )),
        ivm_execution_budget: execution_budget.clone(),
        pipeline_ivm_prepared_cache: PublicationRwLock::try_new(
            PreparedContractCache::with_execution_budget(
                pipeline_cache_size,
                execution_budget.clone(),
            ),
            &execution_budget,
        )
        .map_err(StateStorageAdmissionError::World)?,
        crypto: PublicationRwLock::try_new(Arc::new(initial_crypto.clone()), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        nexus: PublicationRwLock::try_new(nexus, &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        canonical_runtime,
        native_execution_tip,
        // Decoded claims cannot recreate original pre-tail journal custody.
        native_world_cut: parking_lot::Mutex::new(None),
        nexus_runtime_restored_from_snapshot,
        nexus_storage_budget_last_check_height: AtomicU64::new(0),
        native_evidence_admission: parking_lot::Mutex::new(
            crate::sumeragi::evidence::admission::AdmissionCache::default(),
        ),
        evidence_preparation_budget: iroha_allocation::AllocationBudget::new(
            evidence_preparation_bytes,
        ),
        stake_index_budget: iroha_allocation::AllocationBudget::new(stake_index_bytes),
        tiered_backend: Arc::clone(&tiered_backend),
        tiered_snapshot_worker,
        fraud_monitoring: default_fraud_monitoring_cfg(),
        zk: default_zk(),
        gov: default_governance(),
        content: default_content_cfg(),
        settlement: iroha_config::parameters::actual::Settlement::default(),
        settlement_engine: SettlementEngine::new_roadmap_default(),
        chain_id,
        network_id,
        #[cfg(feature = "telemetry")]
        telemetry,
        lane_lifecycle_lock: PublicationMutex::default(),
        geometry_publication: parking_lot::Mutex::new(None),
        tiered_startup_geometry: None,

        state_commit_lock: Arc::new(PublicationMutex::default()),
        state_write_lock: PublicationMutex::try_new((), &execution_budget)
            .map_err(StateStorageAdmissionError::World)?,
        view_generation: AtomicU64::new(0),
        publication_notify: tokio::sync::Notify::new(),
        view_lock_contention_log: parking_lot::Mutex::new(ViewLockContentionLog::default()),
        native_pending_evidence: parking_lot::Mutex::new(
            crate::sumeragi::evidence::NativeEvidencePool::default(),
        ),
    });
    if !emergency_fast {
        // Restore effective manifests from the caller's frozen startup sources before
        // any State view or derived index can observe the committed runtime catalog.
        let projection = {
            let runtime = state.canonical_runtime.view();
            let world = state.world.view();
            state.project_canonical_runtime(runtime.get(), &world)
        }
        .map_err(|error| MergeLedgerCommitError::ExecutionStatePublication(error.to_string()))?;
        *state.lane_manifests.get_mut() = projection.manifests;
        *state.lane_privacy_registry.get_mut() = projection.privacy;
    }
    crate::sumeragi::evidence::validate_persisted_records(&state).map_err(|error| {
        MergeLedgerCommitError::ExecutionStatePublication(format!(
            "restored native evidence is invalid: {error}"
        ))
    })?;
    crate::validation_fee::validate_persisted_policy_registry_runtime_v1(
        &state.view(),
        restored_height,
    )
    .map_err(|error| match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
            MergeLedgerCommitError::ExecutionStatePublication(format!(
                "restored validation-fee policy registry is invalid: {error}"
            ))
        }
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            MergeLedgerCommitError::ExecutionDeferred(reason)
        }
    })?;
    state
        .world
        .validate_retained_mandatory_sources()
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                MergeLedgerCommitError::ExecutionDeferred(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                MergeLedgerCommitError::ExecutionStatePublication(error)
            }
        })?;
    state
        .finalize_snapshot_derived_state_indexes(emergency_fast)
        .map_err(MergeLedgerCommitError::ExecutionStatePublication)?;
    #[cfg(feature = "sm")]
    if active_runtime {
        Sm2PublicKey::set_default_distid(initial_crypto.sm2_distid_default.clone())
            .expect("sm2_distid_default must be valid");
    }
    #[cfg(feature = "telemetry")]
    if !emergency_fast {
        let view = state.world.governance_proposals.view();
        let records: Vec<_> = view.iter().map(|(id, rec)| (*id, rec.status)).collect();
        telemetry_seed.seed_governance_proposals(records);
        let (status_counts, stage_counts) = state
            .world
            .parliament_attempt_counts
            .view()
            .get()
            .telemetry_counts();
        telemetry_seed.set_parliament_attempt_counts(status_counts, stage_counts);
        let citizens_total = u64::try_from(state.world.citizens.view().iter().count())
            .expect("Parliament citizen count must fit into u64");
        telemetry_seed.record_citizens_total(citizens_total);
    }
    // Native node preparation owns durable replay. Restoring a snapshot does not
    // activate an independent legacy merge-ledger or finality-sidecar recovery path.
    Ok(state)
}
fn default_pipeline() -> iroha_config::parameters::actual::Pipeline {
    iroha_config::parameters::actual::Pipeline {
        dynamic_prepass: iroha_config::parameters::defaults::pipeline::DYNAMIC_PREPASS,
        access_set_cache_enabled:
            iroha_config::parameters::defaults::pipeline::ACCESS_SET_CACHE_ENABLED,
        parallel_overlay: iroha_config::parameters::defaults::pipeline::PARALLEL_OVERLAY,
        workers: iroha_config::parameters::defaults::pipeline::WORKERS,
        stateless_cache_cap: iroha_config::parameters::defaults::pipeline::STATELESS_CACHE_CAP,
        parallel_apply: iroha_config::parameters::defaults::pipeline::PARALLEL_APPLY,
        ready_queue_heap: iroha_config::parameters::defaults::pipeline::READY_QUEUE_HEAP,
        gpu_key_bucket: iroha_config::parameters::defaults::pipeline::GPU_KEY_BUCKET,
        debug_trace_scheduler_inputs:
            iroha_config::parameters::defaults::pipeline::DEBUG_TRACE_SCHEDULER_INPUTS,
        debug_trace_tx_eval: iroha_config::parameters::defaults::pipeline::DEBUG_TRACE_TX_EVAL,
        signature_batch_max_ed25519:
            iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_ED25519,
        signature_batch_max_secp256k1:
            iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_SECP256K1,
        signature_batch_max_pqc:
            iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_PQC,
        signature_batch_max_bls:
            iroha_config::parameters::defaults::pipeline::SIGNATURE_BATCH_MAX_BLS,
        cache_size: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
        ivm_cache_max_decoded_ops:
            iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        ivm_cache_max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
        ivm_execution_max_bytes:
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ivm_prover_threads: iroha_config::parameters::defaults::pipeline::IVM_PROVER_THREADS,
        overlay_max_instructions:
            iroha_config::parameters::defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS,
        overlay_max_bytes: iroha_config::parameters::defaults::pipeline::OVERLAY_MAX_BYTES,
        overlay_chunk_instructions:
            iroha_config::parameters::defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS,
        gas: iroha_config::parameters::actual::Gas {
            tech_account_id: iroha_config::parameters::defaults::pipeline::GAS_TECH_ACCOUNT_ID
                .to_string(),
            accepted_assets: Vec::new(),
            units_per_gas: Vec::new(),
        },
        ivm_max_cycles_upper_bound:
            iroha_config::parameters::defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND,
        ivm_max_decoded_instructions:
            iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS,
        ivm_max_decoded_bytes: iroha_config::parameters::defaults::pipeline::IVM_MAX_DECODED_BYTES,
        quarantine_max_txs_per_block:
            iroha_config::parameters::defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK,
        quarantine_tx_max_cycles:
            iroha_config::parameters::defaults::pipeline::QUARANTINE_TX_MAX_CYCLES,
        query_default_cursor_mode: iroha_config::parameters::actual::QueryCursorMode::Ephemeral,
        query_max_fetch_size: iroha_config::parameters::defaults::pipeline::QUERY_MAX_FETCH_SIZE,
        query_stored_min_gas_units:
            iroha_config::parameters::defaults::pipeline::QUERY_STORED_MIN_GAS_UNITS,
        amx_per_dataspace_budget_ms:
            iroha_config::parameters::defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS,
        amx_group_budget_ms: iroha_config::parameters::defaults::pipeline::AMX_GROUP_BUDGET_MS,
        amx_per_instruction_ns:
            iroha_config::parameters::defaults::pipeline::AMX_PER_INSTRUCTION_NS,
        amx_per_memory_access_ns:
            iroha_config::parameters::defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS,
        amx_per_syscall_ns: iroha_config::parameters::defaults::pipeline::AMX_PER_SYSCALL_NS,
    }
}
pub(super) use super::default_zk_config as default_zk;
#[allow(clippy::too_many_lines)]
fn default_governance() -> iroha_config::parameters::actual::Governance {
    iroha_config::parameters::actual::Governance {
        vk_ballot: None,
        vk_tally: None,
        voting_asset_id: iroha_config::parameters::defaults::governance::voting_asset_id()
            .parse()
            .expect("valid default voting asset id"),
        citizenship_asset_id: iroha_config::parameters::defaults::governance::citizenship_asset_id(
        )
        .parse()
        .expect("valid default citizenship asset id"),
        citizenship_bond_amount:
            iroha_config::parameters::defaults::governance::citizenship_bond_amount(),
        citizenship_escrow_account:
            iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
        min_bond_amount: 150_u64.into(),
        bond_escrow_account: iroha_config::parameters::defaults::governance::bond_escrow_account_id(
        ),
        slash_receiver_account:
            iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
        slash_double_vote_bps:
            iroha_config::parameters::defaults::governance::slash_policy::DOUBLE_VOTE_BPS,
        slash_invalid_proof_bps:
            iroha_config::parameters::defaults::governance::slash_policy::MISCONDUCT_BPS,
        slash_ineligible_proof_bps:
            iroha_config::parameters::defaults::governance::slash_policy::INELIGIBLE_PROOF_BPS,
        alias_teu_minimum: iroha_config::parameters::defaults::governance::alias_teu_minimum(),
        alias_frontier_telemetry:
            iroha_config::parameters::defaults::governance::alias_frontier_telemetry(),
        debug_trace_pipeline: iroha_config::parameters::defaults::governance::DEBUG_TRACE_PIPELINE,
        jdg_signature_schemes:
            iroha_config::parameters::defaults::governance::jdg_signature_schemes()
                .into_iter()
                .map(|scheme| {
                    scheme
                        .parse::<iroha_data_model::jurisdiction::JdgSignatureScheme>()
                        .expect("valid default JDG signature scheme")
                })
                .collect(),
        runtime_upgrade_provenance:
            iroha_config::parameters::actual::RuntimeUpgradeProvenancePolicy::default(),
        viral_incentives: iroha_config::parameters::actual::ViralIncentives::default(),
        sorafs_pin_policy: iroha_config::parameters::actual::SorafsPinPolicyConstraints::default(),
        sorafs_pin_fee_asset_id:
            iroha_config::parameters::defaults::governance::sorafs_pin_fee::asset_id()
                .parse()
                .expect("default SoraFS pin fee asset id"),
        sorafs_pin_fee_treasury_account:
            iroha_config::parameters::defaults::governance::sorafs_pin_fee::treasury_account_id(),
        sorafs_pricing: iroha_data_model::sorafs::pricing::PricingScheduleRecord::launch_default(),
        sorafs_penalty: iroha_config::parameters::actual::SorafsPenaltyPolicy::default(),
        sorafs_telemetry: iroha_config::parameters::actual::SorafsTelemetryPolicy::default(),
        sorafs_provider_owners: std::collections::BTreeMap::new(),
        conviction_step_blocks: 100,
        max_conviction: 6,
        min_enactment_delay: 20,
        window_span: 100,
        max_active_referenda: iroha_config::parameters::defaults::governance::MAX_ACTIVE_REFERENDA,
        max_lock_owners_per_referendum:
            iroha_config::parameters::defaults::governance::MAX_LOCK_OWNERS_PER_REFERENDUM,
        plain_voting_enabled: iroha_config::parameters::defaults::governance::PLAIN_VOTING_ENABLED,
        approval_threshold_q_num: 1,
        approval_threshold_q_den: 2,
        min_turnout: 0,
        parliament_alternate_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_ALTERNATE_SIZE,
        parliament_sortition_pulse_delay_blocks:
            iroha_config::parameters::defaults::governance::PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS,
        parliament_invitation_phase_blocks:
            iroha_config::parameters::defaults::governance::PARLIAMENT_INVITATION_PHASE_BLOCKS,
        parliament_public_finding_phase_blocks:
            iroha_config::parameters::defaults::governance::PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS,
        parliament_timed_ovn: iroha_config::parameters::actual::ParliamentTimedOvn::default(),
        parliament_tle_key_lifecycle:
            iroha_config::parameters::actual::ParliamentTleKeyLifecycle::default(),
        parliament_tle_partial_release_signer_provider_handle: None,
        parliament_tle_partial_release_signer_provider_revision: None,
        parliament_tle_partial_release_signer_provider_policy_digest: None,
        rules_committee_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_RULES_COMMITTEE_SIZE,
        agenda_council_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_AGENDA_COUNCIL_SIZE,
        interest_panel_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_INTEREST_PANEL_SIZE,
        review_panel_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_REVIEW_PANEL_SIZE,
        coordination_council_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_COORDINATION_COUNCIL_SIZE,
        policy_jury_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_POLICY_JURY_SIZE,
        confirmation_jury_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_CONFIRMATION_JURY_SIZE,
        oversight_committee_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE,
        mpc_committee_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_MPC_COMMITTEE_SIZE,
        fma_committee_size:
            iroha_config::parameters::defaults::governance::PARLIAMENT_FMA_COMMITTEE_SIZE,
    }
}
fn reject_unknown(map: &SnapshotJsonMap<'_>, context: &str) -> Result<(), json::Error> {
    let Some(field) = map.first_key() else {
        return Ok(());
    };
    Err(json::Error::InvalidField {
        field: format!("{context}.{field}"),
        message: "unknown field is not permitted in a signed first-release snapshot".to_owned(),
    })
}
/// Decode and validate the World component without granting authenticated State
/// history. This test-only helper returns a World, never an installed native tip.
#[cfg(test)]
pub(in crate::state) fn decode_world_component_for_testing(
    world: &World,
) -> Result<World, StateRestoreError> {
    let encoded = json::to_json(world)?;
    let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
    let operation_index_refusal = std::cell::RefCell::new(None);
    let ivm = IVM::new(0);
    parse_world(
        &iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        SnapshotJsonMap::parse(&encoded, "world")?,
        &IvmSeed {
            operation_index_budget: &operation_index_budget,
            operation_index_refusal: &operation_index_refusal,
            ivm: &ivm,
            _marker: PhantomData,
        },
    )
}

/// Reuse the validated publication fixture for direct State commit controls.
#[cfg(test)]
pub(in crate::state) fn seeded_musubi_publication_world_for_testing() -> World {
    decode_tests::seeded_musubi_publication_snapshot().0
}

#[cfg(test)]
mod decode_tests {
    use super::*;
    include!("deserialize_world_musubi_live_tests.rs");
    use crate::query::store::LiveQueryStore;
    use iroha_crypto::SignatureOf;
    use iroha_data_model::account::AccountDetails;
    use iroha_data_model::musubi::{
        MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiAliasHistoryActionV1,
        MusubiArchiveCommitmentV1, MusubiArchiveLocationIdV1, MusubiArtifactGovernanceStateV1,
        MusubiArtifactTakedownV1, MusubiContentDigestV1, MusubiGovernanceDecisionV1,
        MusubiMaintainerPermissionsV1, MusubiNamespaceBindingDigestV1, MusubiPackageRevisionsV1,
        MusubiPackageScopeV1, MusubiParliamentActionV1, MusubiProviderBundleAttestationDigestV1,
        MusubiProviderBundleAttestationSetDigestV1, MusubiProviderBundleVerificationApprovalV1,
        MusubiProviderBundleVerificationAttestationV1, MusubiProviderBundleVerificationBindingV1,
        MusubiProviderBundleVerificationPayloadV1, MusubiReasonV1, MusubiRecoverPackageOwnersV1,
        MusubiRegistryAdmissionModeV1, MusubiReleaseManifestV1, MusubiReleaseMetadataV1,
        MusubiReleaseRevisionsV1, MusubiReleaseSelectionStateV1, MusubiReleaseYankV1,
        MusubiRetargetAliasV1, MusubiSeedIngressReceiptApprovalV1,
        MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptPayloadV1,
        MusubiSeedIngressReceiptV1, MusubiSetRegistryPolicyActionV1, MusubiStorageAvailabilityV1,
        MusubiTakedownArtifactActionV1, MusubiVerificationLockDigestV1,
    };
    use iroha_data_model::sorafs::pin_registry::{
        ChunkerProfileHandle, ManifestAliasBinding, ManifestRootCid,
        ProviderIngestCompletionSignerPolicyV1, ProviderIngestFinalizedAnchorV1,
    };
    #[test]
    fn restored_proposal_status_must_match_latest_attempt_exactly() {
        use iroha_data_model::governance::types::GovernanceAttemptStatusV1 as Attempt;

        assert!(proposal_status_matches_latest_attempt_v1(
            GovernanceProposalStatus::Rejected,
            Some(Attempt::Rejected),
        ));
        assert!(proposal_status_matches_latest_attempt_v1(
            GovernanceProposalStatus::ExecutionFailed,
            Some(Attempt::ExecutionFailed),
        ));
        assert!(!proposal_status_matches_latest_attempt_v1(
            GovernanceProposalStatus::Proposed,
            Some(Attempt::Rejected),
        ));
        assert!(!proposal_status_matches_latest_attempt_v1(
            GovernanceProposalStatus::Rejected,
            Some(Attempt::ExecutionFailed),
        ));
    }

    fn musubi_account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive deterministic Musubi snapshot account");
        AccountId::new(key_pair.public_key().clone())
    }

    #[test]
    fn restore_rejects_every_standalone_state_alias_for_a_typed_proposal() {
        let kind = ProposalKind::DeployContract(
            iroha_data_model::governance::types::DeployContractProposal {
                proposal_operator: musubi_account(59),
                contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                    .parse()
                    .expect("contract address"),
                code_hash: iroha_data_model::governance::types::ContractCodeHash::new([0x31; 32]),
                abi_hash: iroha_data_model::governance::types::ContractAbiHash::new([0x41; 32]),
                abi_version: iroha_data_model::governance::types::AbiVersion::new(1),
                manifest_provenance: None,
            },
        );
        let proposal_id = kind.fingerprint();
        let typed_world = || {
            let mut world = World::default();
            world.governance_proposals.insert(
                proposal_id,
                GovernanceProposalRecord {
                    proposer: musubi_account(59),
                    kind: kind.clone(),
                    created_height: 1,
                    status: GovernanceProposalStatus::Proposed,
                },
            );
            world
        };
        let lowercase = hex::encode(proposal_id);
        let uppercase = lowercase.to_ascii_uppercase();
        let mixed = lowercase
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index % 2 == 0 {
                    character.to_ascii_uppercase()
                } else {
                    character
                }
            })
            .collect::<String>();
        let referendum_alias = uppercase;
        let mut world = typed_world();
        world.governance_referenda.insert(
            referendum_alias.clone(),
            GovernanceReferendumRecord {
                h_start: 1,
                h_end: 2,
                status: GovernanceReferendumStatus::Proposed,
                mode: GovernanceReferendumMode::Plain,
                plain_context: crate::query::standalone_plain_test_fixture::context(
                    &iroha_config::parameters::actual::Governance::default(),
                    0,
                ),
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        let error = validate_no_standalone_governance_state_for_typed_proposals_v1(&world)
            .expect_err("uppercase restored referendum alias must fail closed");
        assert!(matches!(
            error,
            json::Error::InvalidField { ref field, .. } if field == "governance_referenda"
        ));
        let mut world = typed_world();
        world
            .governance_locks
            .insert(mixed.clone(), GovernanceLocksForReferendum::default());
        let error = validate_no_standalone_governance_state_for_typed_proposals_v1(&world)
            .expect_err("mixed-case restored lock alias must fail closed");
        assert!(matches!(
            error,
            json::Error::InvalidField { ref field, .. } if field == "governance_locks"
        ));
        let lower_prefixed = format!("0x{lowercase}");
        let mut world = typed_world();
        world
            .governance_slashes
            .insert(lower_prefixed.clone(), GovernanceSlashLedger::default());
        let error = validate_no_standalone_governance_state_for_typed_proposals_v1(&world)
            .expect_err("0x-prefixed restored slash alias must fail closed");
        assert!(matches!(
            error,
            json::Error::InvalidField { ref field, .. } if field == "governance_slashes"
        ));
        let upper_prefixed = format!("0X{}", lowercase.to_ascii_uppercase());
        let mut world = typed_world();
        world
            .elections
            .insert(upper_prefixed.clone(), ElectionState::default());
        let error = validate_no_standalone_governance_state_for_typed_proposals_v1(&world)
            .expect_err("0X-prefixed restored election alias must fail closed");
        assert!(matches!(
            error,
            json::Error::InvalidField { ref field, .. } if field == "elections"
        ));
        validate_no_standalone_governance_state_for_typed_proposals_v1(&typed_world())
            .expect("typed proposal without standalone state is valid");
    }

    #[test]
    fn restored_invalid_election_reports_the_elections_field() {
        let mut world = World::default();
        world.elections.insert(
            "invalid-option-count".to_owned(),
            ElectionState {
                options: 1,
                tally: vec![0],
                ..ElectionState::default()
            },
        );
        let encoded = json::to_json(&world).expect("serialize malformed election fixture");
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let error = match parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse election fixture"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        ) {
            Ok(_) => panic!("one-option election must fail restore"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StateRestoreError::Serialization(json::Error::InvalidField { ref field, ref message })
                if field == "elections" && message.contains("below the minimum")
        ));
    }

    fn musubi_package(name: &str) -> MusubiPackageIdV1 {
        MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            name.parse().expect("Musubi package name"),
        )
    }
    #[test]
    fn legacy_musubi_generic_state_rejects_entire_reserved_namespace() {
        for path in [
            "musubi",
            "musubi_package_catalog",
            "musubi_registry",
            "musubi_short_aliases",
            "musubi/releases",
            "musubi.v0.aliases",
            "musubi:registry",
        ] {
            let mut state = Storage::<StatePath, Vec<u8>>::default();
            state.insert(path.parse().expect("valid legacy state path"), vec![1]);
            let error = reject_legacy_musubi_state(&state)
                .expect_err("every reserved legacy Musubi state path must block loading");
            assert!(
                error.to_string().contains(path),
                "rejection must identify the exact legacy path: {error}"
            );
        }
        let mut unrelated = Storage::<StatePath, Vec<u8>>::default();
        unrelated.insert(
            "musubian_contract"
                .parse()
                .expect("valid unrelated state path"),
            vec![1],
        );
        reject_legacy_musubi_state(&unrelated)
            .expect("a non-reserved prefix must not be mistaken for Musubi state");
    }
    fn retain_musubi_consumption_as(
        world: &mut World,
        decision_id: [u8; 32],
        action: MusubiParliamentActionV1,
        enacted_at_height: u64,
        execute_after_height: u64,
        consumed_at_height: u64,
    ) -> iroha_data_model::musubi::MusubiGovernanceActionDigestV1 {
        let action_digest = action.action_digest();
        let kind = ProposalKind::MusubiRegistryGovernance(action);
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x5E; 32])),
        );
        let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
            &kind,
            vec![musubi_account(61), musubi_account(62), musubi_account(63)],
            &network_id,
            enacted_at_height,
        );
        let attempt_id = attempt.attempt().id;
        world.governance_proposals.insert(
            decision_id,
            GovernanceProposalRecord {
                proposer: musubi_account(60),
                kind,
                created_height: 1,
                status: GovernanceProposalStatus::Enacted,
            },
        );
        world.parliament_attempts.insert(attempt_id, attempt);
        let consumption = MusubiGovernanceDecisionConsumptionV1 {
            decision: MusubiGovernanceDecisionV1 {
                decision_id,
                action_digest,
                enacted_at_height,
                execute_after_height,
            },
            minimum_enactment_delay: execute_after_height
                .checked_sub(enacted_at_height)
                .expect("execution boundary follows enactment height"),
            consumed_at_height,
        };
        consumption.validate().expect("valid decision consumption");
        world
            .musubi_governance_decisions
            .insert(decision_id, consumption);
        action_digest
    }
    fn retain_musubi_consumption(
        world: &mut World,
        action: MusubiParliamentActionV1,
        enacted_at_height: u64,
        execute_after_height: u64,
        consumed_at_height: u64,
    ) -> iroha_data_model::musubi::MusubiGovernanceActionDigestV1 {
        let decision_id = ProposalKind::MusubiRegistryGovernance(action.clone()).fingerprint();
        retain_musubi_consumption_as(
            world,
            decision_id,
            action,
            enacted_at_height,
            execute_after_height,
            consumed_at_height,
        )
    }
    fn musubi_policy_successor(
        current: &MusubiRegistryPolicyV1,
        mode: MusubiRegistryAdmissionModeV1,
    ) -> MusubiRegistryPolicyV1 {
        let mut successor = current.clone();
        successor.revision = current.revision.checked_add(1).expect("policy revision");
        successor.mode = mode;
        successor.allowlisted_dataspaces.clear();
        successor
            .validate_successor(current)
            .expect("canonical policy successor");
        successor
    }
    fn seed_current_musubi_package(
        world: &mut World,
        package: &MusubiPackageIdV1,
        owner: &AccountId,
        governance_revision: u64,
        accepted_at_height: u64,
    ) -> MusubiPackageMemberV1 {
        let record = MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: "sora".parse().expect("namespace"),
            claimed_namespace_binding: MusubiNamespaceBindingDigestV1::new([1; 32]),
            owners: vec![owner.clone()],
            member_accounts: vec![owner.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: governance_revision,
                metadata: 1,
                archive_locations: 1,
            },
        };
        record.validate().expect("valid package fixture");
        world.musubi_packages.insert(package.clone(), record);
        let member = MusubiPackageMemberV1 {
            package: package.clone(),
            account: owner.clone(),
            role: MusubiPackageRoleV1::Owner,
            accepted_at_height,
            governance_revision,
        };
        member.validate().expect("valid member fixture");
        world
            .musubi_package_members
            .insert(member.key(), member.clone());
        member
    }
    fn musubi_release_record(
        release: MusubiReleaseIdV1,
        artifact_governance: MusubiArtifactGovernanceStateV1,
        artifact_governance_revision: u64,
    ) -> MusubiReleaseRecordV1 {
        let manifest = MusubiReleaseManifestV1 {
            release: release.clone(),
            edition: iroha_data_model::musubi::MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([0xA1; 32]).expect("nonzero ABI hash"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([0xA2; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            archive_id: ArchiveId::new([0xA3; 32]),
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0xA4; 32]),
        };
        let publisher = musubi_account(61);
        let record = MusubiReleaseRecordV1 {
            release_digest: manifest.release_digest(),
            yank: MusubiReleaseYankV1 {
                release,
                yanked: false,
                reason: "initial publication".parse().expect("bounded reason"),
                changed_by: publisher.clone(),
                changed_at_height: 1,
                revision: 1,
            },
            artifact_governance,
            revisions: MusubiReleaseRevisionsV1 {
                yank: 1,
                artifact_governance: artifact_governance_revision,
            },
            manifest,
            published_by: publisher,
            published_at_height: 1,
        };
        record.validate().expect("valid release fixture");
        record
    }
    fn validate_musubi_persisted_snapshot(world: &World) -> Result<(), json::Error> {
        MusubiPersistedState {
            namespace_bindings: &world.musubi_namespace_bindings,
            packages: &world.musubi_packages,
            package_metadata: &world.musubi_package_metadata,
            package_members: &world.musubi_package_members,
            package_invitations: &world.musubi_package_invitations,
            maintainer_directory: &world.musubi_maintainer_directory,
            releases: &world.musubi_releases,
            archives: &world.musubi_archives,
            provider_bundle_attestations: &world.musubi_provider_bundle_attestations,
            archive_locations: &world.musubi_archive_locations,
            archive_availability: &world.musubi_archive_availability,
            archive_reverse_references: &world.musubi_archive_reverse_references,
            resolver_index: &world.musubi_resolver_index,
            resolver_index_checkpoints: &world.musubi_resolver_index_checkpoints,
            public_directory: &world.musubi_public_directory,
            aliases: &world.musubi_aliases,
            alias_history: &world.musubi_alias_history,
            governance_decisions: &world.musubi_governance_decisions,
            resolver_index_revision: world.musubi_resolver_index_revision.view().get().get(),
            replication_shortfall_releases: *world
                .musubi_replication_shortfall_releases
                .view()
                .get(),
        }
        .validate()
    }
    fn validate_musubi_publication_snapshot(world: &World) -> Result<(), json::Error> {
        validate_musubi_location_reverse_indices(
            &world.musubi_archives,
            &world.musubi_archive_locations,
            &world.pin_manifests,
            &world.replication_orders,
            &world.musubi_locations_by_pin,
            &world.musubi_locations_by_replication_order,
            &world.musubi_locations_by_provider,
        )?;
        validate_musubi_persisted_snapshot(world)?;
        validate_musubi_live_projections(
            world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn seeded_musubi_publication_snapshot()
    -> (World, MusubiReleaseIdV1, ArchiveId, MusubiPackageSelectorV1) {
        let mut world = World::default();
        let package = musubi_package("atomic-publication");
        let namespace: MusubiNamespaceV1 = "sora".parse().expect("namespace");
        let binding = MusubiNamespaceBindingV1 {
            namespace: namespace.clone(),
            home_dataspace: package.home_dataspace,
            scope: package.scope.clone(),
            generation: 1,
        };
        let publisher_keypair = KeyPair::try_from_seed(vec![61; 32], Algorithm::Ed25519)
            .expect("derive deterministic publisher key");
        let publisher = AccountId::new(publisher_keypair.public_key().clone());
        let package_record = MusubiPackageRecordV1 {
            package: package.clone(),
            claimed_namespace: namespace.clone(),
            claimed_namespace_binding: binding.digest(),
            owners: vec![publisher.clone()],
            member_accounts: vec![publisher.clone()],
            claimed_at_height: 1,
            revisions: MusubiPackageRevisionsV1 {
                governance: 1,
                metadata: 1,
                archive_locations: 1,
            },
        };
        package_record.validate().expect("valid package record");
        let member = MusubiPackageMemberV1 {
            package: package.clone(),
            account: publisher.clone(),
            role: MusubiPackageRoleV1::Owner,
            accepted_at_height: 1,
            governance_revision: 1,
        };
        member.validate().expect("valid package owner");
        let metadata = MusubiPackageMetadataRecordV1 {
            package: package.clone(),
            metadata: MusubiReleaseMetadataV1::default(),
            revision: 1,
            changed_by: publisher.clone(),
            changed_at_height: 1,
        };
        metadata.validate().expect("valid package metadata");
        let commitment = MusubiArchiveCommitmentV1 {
            root_cid: ManifestRootCid::from_blake3_digest([0x11; 32]).expect("archive root CID"),
            chunker: ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".to_owned(),
                name: "sf1".to_owned(),
                semver: "1.0.0".to_owned(),
                multihash_code: 0x1f,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([0x12; 32]),
            por_root: MusubiContentDigestV1::new([0x13; 32]),
            content_length: 1,
            car_digest: MusubiContentDigestV1::new([0x14; 32]),
            car_size: 1,
            bundle_digest: MusubiContentDigestV1::new([0x15; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x16; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x17; 32]),
            file_count: 1,
            chunk_count: 1,
        };
        let archive_id = commitment.archive_id();
        let release =
            MusubiReleaseIdV1::new(package.clone(), "1.0.0".parse().expect("release version"));
        let manifest = MusubiReleaseManifestV1 {
            release: release.clone(),
            edition: iroha_data_model::musubi::MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([0x18; 32]).expect("ABI binding"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([0x19; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            archive_id,
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0x1A; 32]),
        };
        manifest.validate().expect("valid release manifest");
        let broker_keypair = KeyPair::try_from_seed(vec![62; 32], Algorithm::Ed25519)
            .expect("derive deterministic ingress broker key");
        let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding: MusubiSeedIngressReceiptBindingV1 {
                network_id: iroha_data_model::NetworkId::from_genesis_hash(
                    HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x1B; 32])),
                ),
                publisher: publisher.clone(),
                ingress_broker: AccountId::new(broker_keypair.public_key().clone()),
                seed_provider: ProviderId::new([0x1C; 32]),
                semantic_release_manifest_digest: manifest.semantic_digest(),
                archive_id,
                car_body_digest: commitment.car_digest,
                car_body_length: commitment.car_size,
                nonce: [0x1D; 32],
            },
            issued_at_ms: 1,
            expires_at_ms: 2,
        };
        let receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_keypair.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_keypair.private_key(),
                    receipt_payload.signing_hash(),
                )
                .expect("sign ingress receipt"),
            }],
            payload: receipt_payload,
        };
        let archive = MusubiArchiveRecordV1 {
            archive_id,
            commitment: commitment.clone(),
            staging_receipt: receipt,
            registered_by: publisher.clone(),
            registered_at_height: 1,
            location_revision: 1,
            location_ids: Vec::new(),
        };
        archive.validate().expect("valid archive record");
        let availability = MusubiArchiveAvailabilityV1 {
            archive_id,
            availability: MusubiStorageAvailabilityV1::Unavailable,
            healthy_replicas: 0,
            active_locations: 0,
            finalized_height: 1,
            finalized_block_hash: [0x1E; 32],
            index_revision: 1,
        };
        availability.validate().expect("valid archive availability");
        let yank = MusubiReleaseYankV1 {
            release: release.clone(),
            yanked: false,
            reason: "initial publication".parse().expect("bounded reason"),
            changed_by: publisher.clone(),
            changed_at_height: 2,
            revision: 1,
        };
        let release_record = MusubiReleaseRecordV1 {
            release_digest: manifest.release_digest(),
            manifest: manifest.clone(),
            published_by: publisher,
            published_at_height: 2,
            yank: yank.clone(),
            artifact_governance: MusubiArtifactGovernanceStateV1::Available,
            revisions: MusubiReleaseRevisionsV1 {
                yank: 1,
                artifact_governance: 1,
            },
        };
        release_record.validate().expect("valid release record");
        let resolver_row = MusubiResolverReleaseRowV1 {
            release: release.clone(),
            release_digest: release_record.release_digest,
            archive_id,
            source_digest: commitment.source_tree_digest,
            interface_digest: manifest.interface_digest,
            abi: manifest.abi,
            dependencies: Vec::new(),
            selection: MusubiReleaseSelectionStateV1 {
                yank,
                storage: availability,
                governance: MusubiArtifactGovernanceStateV1::Available,
            },
            index_revision: 2,
        };
        resolver_row.validate().expect("valid resolver row");
        let selector = MusubiPackageSelectorV1 {
            namespace,
            name: package.name.clone(),
        };
        let directory = MusubiOrderedPackageEntryV1 {
            selector: selector.clone(),
            package: package.clone(),
            latest_selectable: None,
            metadata_revision: 1,
            index_revision: 2,
        };
        directory.validate().expect("valid public directory entry");
        world
            .musubi_namespace_bindings
            .insert(binding.namespace.clone(), binding);
        world
            .musubi_package_members
            .insert(member.key(), member.clone());
        world.musubi_maintainer_directory.insert(
            MusubiMaintainerDirectoryKeyV1::accepted(package.clone(), member.account.clone()),
            MusubiMaintainerDirectoryEntryV1::Accepted(member),
        );
        world
            .musubi_package_metadata
            .insert(package.clone(), metadata);
        world.musubi_packages.insert(package, package_record);
        world.musubi_archives.insert(archive_id, archive);
        world
            .musubi_archive_availability
            .insert(archive_id, availability);
        world.musubi_archive_reverse_references.insert(
            archive_id,
            MusubiArchiveReverseReferencesV1 {
                archive_id,
                releases: vec![release.clone()],
            },
        );
        world
            .musubi_releases
            .insert(release.clone(), release_record);
        world
            .musubi_resolver_index
            .insert(release.clone(), resolver_row);
        world
            .musubi_public_directory
            .insert(selector.clone(), directory);
        world.musubi_resolver_index_revision =
            Cell::new(MusubiResolverIndexRevisionV1::new(2).expect("resolver revision"));
        world.musubi_replication_shortfall_releases = crate::state::scalar_cell_custody::fixture(1);
        (world, release, archive_id, selector)
    }
    include!("deserialize_world_musubi_source_fixture.rs");
    #[test]
    fn musubi_publication_snapshot_validates_replication_shortfall_aggregate() {
        let (baseline, _, _, _) = seeded_musubi_publication_snapshot();
        validate_musubi_publication_snapshot(&baseline)
            .expect("one release on an unavailable archive has shortfall count one");
        let (mut mismatched, _, _, _) = seeded_musubi_publication_snapshot();
        mismatched.musubi_replication_shortfall_releases =
            crate::state::scalar_cell_custody::fixture(0);
        let error = validate_musubi_publication_snapshot(&mismatched)
            .expect_err("a stale persisted shortfall aggregate must fail closed");
        assert!(
            error
                .to_string()
                .contains("musubi_replication_shortfall_releases"),
            "unexpected shortfall mismatch diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_secondary_projections_reject_current_and_predecessor_mutations() {
        let (baseline, _, _, _) = seeded_musubi_publication_snapshot();
        musubi_derived::validate_musubi_derived_cuts(&baseline)
            .expect("the retained current and predecessor projections are exact");
        for mutation in 0..3 {
            let (world, _, archive_id, _) = seeded_musubi_publication_snapshot();
            let directory_row = world
                .musubi_maintainer_directory
                .view()
                .first_key_value()
                .map(|(key, value)| (key.clone(), value.clone()))
                .expect("seeded owner directory row");
            let reference_row = world
                .musubi_archive_reverse_references
                .view()
                .get(&archive_id)
                .cloned()
                .expect("seeded archive reverse-reference row");
            let field = match mutation {
                0 => {
                    let mut block = world.musubi_maintainer_directory.block();
                    block.remove(directory_row.0.clone());
                    block.commit();
                    "musubi_maintainer_directory"
                }
                1 => {
                    let mut block = world.musubi_archive_reverse_references.block();
                    block.remove(archive_id);
                    block.commit();
                    "musubi_archive_reverse_references"
                }
                2 => {
                    let mut block = world.musubi_replication_shortfall_releases.block();
                    *block.get_mut() = 0;
                    block.commit();
                    "musubi_replication_shortfall_releases"
                }
                _ => unreachable!(),
            };
            let error = musubi_derived::validate_musubi_derived_cuts(&world)
                .expect_err("a missing or stale current projection must be rejected");
            assert!(
                error.to_string().contains(field) && error.to_string().contains("current"),
                "unexpected current-cut diagnostic: {error}"
            );
            match mutation {
                0 => {
                    let mut block = world.musubi_maintainer_directory.block();
                    block.insert(directory_row.0, directory_row.1);
                    block.commit();
                }
                1 => {
                    let mut block = world.musubi_archive_reverse_references.block();
                    block.insert(archive_id, reference_row);
                    block.commit();
                }
                2 => {
                    let mut block = world.musubi_replication_shortfall_releases.block();
                    *block.get_mut() = 1;
                    block.commit();
                }
                _ => unreachable!(),
            }
            let error = musubi_derived::validate_musubi_derived_cuts(&world)
                .expect_err("repairing the current cut must not conceal a bad predecessor");
            assert!(
                error.to_string().contains(field) && error.to_string().contains("predecessor"),
                "unexpected predecessor-cut diagnostic: {error}"
            );
        }
    }
    #[test]
    fn musubi_live_availability_rejects_current_and_predecessor_mutations() {
        let (world, _, archive_id, _) = seeded_musubi_publication_snapshot();
        validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect("both retained availability cuts match their SoraFS evidence");
        let original = world
            .musubi_archive_availability
            .view()
            .get(&archive_id)
            .cloned()
            .expect("seeded availability row");
        let mut stale = original.clone();
        stale.active_locations = 1;
        stale
            .validate()
            .expect("stale row remains independently canonical");
        let mut block = world.musubi_archive_availability.block();
        block.insert(archive_id, stale);
        block.commit();
        let error = validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect_err("current availability cannot invent an active location");
        assert!(
            error.to_string().contains("musubi_archive_availability")
                && error.to_string().contains("current"),
            "unexpected current-cut diagnostic: {error}"
        );
        let mut block = world.musubi_archive_availability.block();
        block.insert(archive_id, original);
        block.commit();
        let error = validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect_err("repairing current availability cannot hide the stale predecessor");
        assert!(
            error.to_string().contains("musubi_archive_availability")
                && error.to_string().contains("predecessor"),
            "unexpected predecessor-cut diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_live_availability_rejects_orphan_rows() {
        let (mut world, _, archive_id, _) = seeded_musubi_publication_snapshot();
        let mut orphan = *world
            .musubi_archive_availability
            .view()
            .get(&archive_id)
            .expect("seeded availability row");
        orphan.archive_id = ArchiveId::new([0xD1; 32]);
        orphan
            .validate()
            .expect("orphan row is independently valid");
        world
            .musubi_archive_availability
            .insert(orphan.archive_id, orphan);
        let error = validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect_err("a valid availability row cannot name an absent archive");
        assert!(
            error.to_string().contains("musubi_archive_availability")
                && error.to_string().contains("current"),
            "unexpected orphan diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_publication_preflight_rejects_current_and_replacement_availability() {
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let (world, _, archive_id, _) = seeded_musubi_publication_snapshot();
        let original = *world
            .musubi_archive_availability
            .view()
            .get(&archive_id)
            .expect("seeded availability row");
        let mut stale = original;
        stale.active_locations = 1;
        stale.validate().expect("stale row is independently valid");
        {
            let mut block = world.block();
            block
                .musubi_archive_availability
                .insert(archive_id, original);
            crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
                &mut block,
                &iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                2,
                &nexus,
                &BTreeMap::new(),
                None,
                None,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("an exact touched availability row remains publishable");
            block.musubi_archive_availability.insert(archive_id, stale);
            let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
                &mut block,
                &iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                2,
                &nexus,
                &BTreeMap::new(),
                None,
                None,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection) else {
                panic!("a stale current availability row must fail before publication");
            };
            assert!(
                error.contains("musubi_archive_availability"),
                "unexpected current-cut diagnostic: {error}"
            );
        }
        assert_eq!(
            world.musubi_archive_availability.view().get(&archive_id),
            Some(&original),
            "failed preparation cannot publish the invalid row"
        );
        let mut first = world.musubi_archive_availability.block();
        first.insert(archive_id, stale);
        first.commit();
        let mut second = world.musubi_archive_availability.block();
        second.insert(archive_id, original);
        second.commit();
        let mut replacement = world.block_and_revert();
        assert_eq!(
            replacement.musubi_archive_availability.get(&archive_id),
            Some(&stale),
            "replacement starts from the rollback-visible predecessor"
        );
        let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
            &mut replacement,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            2,
            &nexus,
            &BTreeMap::new(),
            None,
            None,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection) else {
            panic!("a stale rollback cut must fail before replacement publication");
        };
        assert!(
            error.contains("musubi_archive_availability"),
            "unexpected rollback-cut diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_publication_preflight_rechecks_changed_archive_evidence() {
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let (world, _, archive_id, _) = seeded_musubi_publication_snapshot();
        let mut changed = world
            .musubi_archives
            .view()
            .get(&archive_id)
            .cloned()
            .expect("seeded archive row");
        changed
            .location_ids
            .push(MusubiArchiveLocationIdV1::new([0x44; 32]));
        changed
            .validate()
            .expect("a stale directory remains intrinsically canonical");
        let mut block = world.block();
        block.musubi_archives.insert(archive_id, changed);
        let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
            &mut block,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            2,
            &nexus,
            &BTreeMap::new(),
            None,
            None,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection) else {
            panic!("changed archive evidence must revalidate availability before publication");
        };
        assert!(
            error.contains("musubi_archives"),
            "unexpected changed-source diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_live_attestation_cut_rejects_missing_current_and_predecessor_evidence() {
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        let key = seed_provider_attested_location(&mut world, &release, archive_id);
        validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect("the attested location is valid on both retained cuts");
        let record = world
            .musubi_provider_bundle_attestations
            .view()
            .get(&key)
            .cloned()
            .expect("seeded exact provider attestation");
        let mut removal = world.musubi_provider_bundle_attestations.block();
        removal.remove(key);
        removal.commit();
        let error = validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect_err("current location must retain its exact attestation");
        assert!(
            error
                .to_string()
                .contains("missing exact provider attestation")
                && error.to_string().contains("current"),
            "unexpected current-cut diagnostic: {error}"
        );
        let mut repair = world.musubi_provider_bundle_attestations.block();
        repair.insert(key, record);
        repair.commit();
        let error = validate_musubi_live_projections(
            &world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
        .map_err(expect_completed_restore_rejection)
        .expect_err("repairing current evidence cannot hide a missing predecessor row");
        assert!(
            error
                .to_string()
                .contains("missing exact provider attestation")
                && error.to_string().contains("predecessor"),
            "unexpected predecessor-cut diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_publication_preflight_rejects_removed_provider_attestation() {
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        let key = seed_provider_attested_location(&mut world, &release, archive_id);
        let mut block = world.block();
        block.musubi_provider_bundle_attestations.remove(key);
        let Err(error) = crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
            &mut block,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            2,
            &nexus,
            &BTreeMap::new(),
            None,
            None,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection) else {
            panic!("missing provider evidence must fail before World publication");
        };
        assert!(
            error.contains("missing exact provider attestation"),
            "unexpected publication diagnostic: {error}"
        );
        drop(block);
        assert!(
            world
                .musubi_provider_bundle_attestations
                .view()
                .get(&key)
                .is_some(),
            "failed preparation cannot publish attestation deletion"
        );
    }
    #[test]
    fn musubi_persisted_state_rejects_missing_provider_attestation_record() {
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        let attestation_key = seed_provider_attested_location(&mut world, &release, archive_id);
        validate_musubi_persisted_snapshot(&world)
            .expect("an archive location with its exact attestation record is valid");
        {
            let mut mutation = world.musubi_provider_bundle_attestations.block();
            mutation.remove(attestation_key);
            mutation.commit();
        }
        let error = validate_musubi_persisted_snapshot(&world)
            .expect_err("a location must not outlive its exact provider attestation record");
        assert!(
            error
                .to_string()
                .contains("missing exact provider attestation"),
            "unexpected missing-attestation diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_persisted_state_rejects_corrupt_provider_attestation_record() {
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        let attestation_key = seed_provider_attested_location(&mut world, &release, archive_id);
        let mut corrupt_record = world
            .musubi_provider_bundle_attestations
            .view()
            .get(&attestation_key)
            .cloned()
            .expect("seeded provider attestation record");
        corrupt_record.attestation_digest =
            MusubiProviderBundleAttestationDigestV1::new([0xFF; 32]);
        world
            .musubi_provider_bundle_attestations
            .insert(attestation_key, corrupt_record);
        let error = validate_musubi_persisted_snapshot(&world)
            .expect_err("a corrupt provider attestation record must fail closed");
        assert!(
            error
                .to_string()
                .contains("musubi_provider_bundle_attestations"),
            "unexpected corrupt-attestation diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_persisted_state_rejects_corrupt_provider_attestation_set_digest() {
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        seed_provider_attested_location(&mut world, &release, archive_id);
        let (location_key, mut location) = world
            .musubi_archive_locations
            .view()
            .iter()
            .next()
            .map(|(key, location)| (*key, location.clone()))
            .expect("seeded archive location");
        location.provider_attestation_set_digest =
            MusubiProviderBundleAttestationSetDigestV1::new([0xFE; 32]);
        world
            .musubi_archive_locations
            .insert(location_key, location);
        let error = validate_musubi_persisted_snapshot(&world)
            .expect_err("a corrupt provider-attestation aggregate must fail closed");
        assert!(
            error
                .to_string()
                .contains("provider-attestation set digest is not exact"),
            "unexpected corrupt-attestation-set diagnostic: {error}"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn musubi_publication_snapshot_rejects_every_one_sided_projection_cut() {
        let (baseline, _, _, _) = seeded_musubi_publication_snapshot();
        validate_musubi_publication_snapshot(&baseline)
            .expect("complete home and universal publication projections are valid");
        let (mut universal_only, release, archive_id, _) = seeded_musubi_publication_snapshot();
        {
            let mut mutation = universal_only.musubi_releases.block();
            mutation.remove(release.clone());
            mutation.commit();
        }
        universal_only.musubi_archive_reverse_references.insert(
            archive_id,
            MusubiArchiveReverseReferencesV1 {
                archive_id,
                releases: Vec::new(),
            },
        );
        universal_only.musubi_replication_shortfall_releases =
            crate::state::scalar_cell_custody::fixture(0);
        let error = validate_musubi_publication_snapshot(&universal_only)
            .expect_err("a universal resolver row cannot survive without its home release");
        assert!(
            error
                .to_string()
                .contains("resolver row references a missing release"),
            "unexpected universal-only diagnostic: {error}"
        );
        let (mut home_only, release, archive_id, selector) = seeded_musubi_publication_snapshot();
        home_only.musubi_archive_reverse_references.insert(
            archive_id,
            MusubiArchiveReverseReferencesV1 {
                archive_id,
                releases: Vec::new(),
            },
        );
        {
            let mut mutation = home_only.musubi_resolver_index.block();
            mutation.remove(release.clone());
            mutation.commit();
        }
        {
            let mut mutation = home_only.musubi_public_directory.block();
            mutation.remove(selector.clone());
            mutation.commit();
        }
        let error = validate_musubi_publication_snapshot(&home_only)
            .expect_err("a home release cannot survive without universal projections");
        assert!(
            error
                .to_string()
                .contains("archive reverse references are not the exact release set"),
            "unexpected home-only diagnostic: {error}"
        );
        let (missing_resolver, release, _, selector) = seeded_musubi_publication_snapshot();
        {
            let mut mutation = missing_resolver.musubi_resolver_index.block();
            mutation.remove(release);
            mutation.commit();
        }
        {
            let mut mutation = missing_resolver.musubi_public_directory.block();
            mutation.remove(selector);
            mutation.commit();
        }
        let error = validate_musubi_publication_snapshot(&missing_resolver)
            .expect_err("a reverse reference cannot survive without its resolver row");
        assert!(
            error
                .to_string()
                .contains("release is missing its exact resolver row"),
            "unexpected missing-resolver diagnostic: {error}"
        );
        let (missing_directory, _, _, selector) = seeded_musubi_publication_snapshot();
        {
            let mut mutation = missing_directory.musubi_public_directory.block();
            mutation.remove(selector);
            mutation.commit();
        }
        let error = validate_musubi_publication_snapshot(&missing_directory)
            .expect_err("a resolver row cannot survive without its directory projection");
        assert!(
            error
                .to_string()
                .contains("package is missing its canonical public-directory entry"),
            "unexpected missing-directory diagnostic: {error}"
        );
        let (mut replayed, release, archive_id, selector) = seeded_musubi_publication_snapshot();
        let replayed_release = replayed
            .musubi_releases
            .view()
            .get(&release)
            .cloned()
            .expect("seeded release");
        let replayed_references = replayed
            .musubi_archive_reverse_references
            .view()
            .get(&archive_id)
            .cloned()
            .expect("seeded reverse references");
        let replayed_resolver = replayed
            .musubi_resolver_index
            .view()
            .get(&release)
            .cloned()
            .expect("seeded resolver row");
        let replayed_directory = replayed
            .musubi_public_directory
            .view()
            .get(&selector)
            .cloned()
            .expect("seeded public directory");
        assert_eq!(
            replayed
                .musubi_releases
                .insert(release.clone(), replayed_release.clone()),
            Some(replayed_release)
        );
        assert_eq!(
            replayed
                .musubi_archive_reverse_references
                .insert(archive_id, replayed_references.clone()),
            Some(replayed_references)
        );
        assert_eq!(
            replayed
                .musubi_resolver_index
                .insert(release, replayed_resolver.clone()),
            Some(replayed_resolver)
        );
        assert_eq!(
            replayed
                .musubi_public_directory
                .insert(selector, replayed_directory.clone()),
            Some(replayed_directory)
        );
        validate_musubi_publication_snapshot(&replayed)
            .expect("an exact projection replay preserves the complete snapshot");
    }
    // Keep the exact-source projection checks together with their complete
    // assertion matrix, outside the snapshot decoder implementation.
    mod musubi_universal_tests {
        use super::*;
        include!("deserialize_world_musubi_universal_tests.rs");
    }
    #[test]
    fn take_parameters_cell_accepts_canonical_mv_envelope() {
        let expected = Parameters::default();
        let blocks = norito::json::to_value(&expected).expect("serialize parameters");
        let mut canonical_map = json::native::Map::new();
        canonical_map.insert("revert".to_owned(), json::Value::Null);
        canonical_map.insert("blocks".to_owned(), blocks);
        let canonical = json::Value::Object(canonical_map);
        let mut map = json::native::Map::new();
        map.insert("parameters".to_owned(), canonical);
        let mut map = SnapshotJsonMap::from_owned(map);
        let parsed = take_parameters_cell(&mut map, "parameters")
            .expect("canonical parameters MV envelope must be accepted");
        assert_eq!(parsed.view().get(), &expected);
    }
    #[test]
    fn borrowed_snapshot_map_rejects_duplicates_and_noncanonical_order() {
        let canonical = SnapshotJsonMap::parse(r#"{"first":0,"second":1}"#, "fixture")
            .expect("borrowed fixture map");
        canonical
            .require_source_order(&["first", "second"], "fixture")
            .expect("declared schema order must match");
        assert!(
            canonical
                .require_source_order(&["second", "first"], "fixture")
                .is_err()
        );
        assert!(
            SnapshotJsonMap::parse(r#"{"first":0,"first":1}"#, "fixture").is_err(),
            "duplicate signed snapshot fields must fail closed"
        );
    }
    include!("private_settlement_snapshot_predecessor_tests.rs");

    #[test]
    fn private_settlement_snapshot_roundtrip_validates_governed_pool_projection() {
        let fixture = crate::private_settlement::sidecar_store::tests::sidecar_fixture();
        let route = fixture.pool_governance.body.route;
        let pool_id = fixture.pool_governance.body.pool_id;
        let restricted_asset_canary = fixture.pool_governance.body.asset_definition_id.to_string();
        let restricted_salt_canary = fixture.pool_governance.body.asset_binding_salt;
        let governance =
            PrivateSettlementPoolGovernanceProjectionV1::from_restricted(&fixture.pool_governance)
                .expect("restricted governance projects only after validation");
        let mut world = World::default();
        let plan = plan_private_settlement_pool_bootstrap_v1(
            &world.private_settlement_governance.view(),
            &world.private_settlement_pools.view(),
            &world.private_settlement_roots.view(),
            governance,
            &[iroha_data_model::privacy::PrivacyCommitmentV1::new(
                [0xE1; 32],
            )],
            5,
        )
        .expect("governed pool bootstrap validates")
        .expect("new governed pool produces writes");
        world
            .private_settlement_governance
            .insert(plan.key, plan.governance);
        world.private_settlement_pools.insert(plan.key, plan.pool);
        world
            .private_settlement_roots
            .insert(plan.root_key, plan.root_provenance);

        let encoded = json::to_json(&world).expect("serialize governed settlement pool");
        assert!(
            !encoded.contains("asset_definition_id")
                && !encoded.contains("asset_binding_salt")
                && !encoded.contains(&restricted_asset_canary)
                && !encoded.contains(&hex::encode(restricted_salt_canary))
                && !encoded.contains(&hex::encode_upper(restricted_salt_canary))
                && !encoded
                    .as_bytes()
                    .windows(restricted_salt_canary.len())
                    .any(|window| window == restricted_salt_canary),
            "canonical World snapshot must never contain restricted pool asset/salt canaries"
        );
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let restored = parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse governed pool World"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .expect("restore governed pool World");
        assert_eq!(
            restored
                .view()
                .private_settlement_pool_head_v1(route, pool_id),
            Some((plan.root_key.epoch, plan.root_key.root))
        );

        {
            let mut roots = world.private_settlement_roots.block();
            roots.remove(plan.root_key);
            roots.commit();
        }
        let corrupt = json::to_json(&world).expect("serialize corrupt governed pool projection");
        let error = match parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&corrupt, "world").expect("parse corrupt World"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        {
            Ok(_) => panic!("missing governed pool root must fail restore"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("private-settlement pool transition is invalid"),
            "unexpected private-settlement restore error: {error}"
        );
    }

    #[test]
    fn private_settlement_finalized_snapshot_roundtrip_restores_all_eight_maps() {
        let world = crate::private_settlement::global_state::tests::finalized_world_fixture();
        let receipt = {
            let receipts = world.private_settlement_receipts.view();
            receipts
                .iter()
                .next()
                .map(|(_, receipt)| receipt.clone())
                .expect("finalized fixture receipt")
        };
        let abort = {
            let aborts = world.private_settlement_aborts.view();
            aborts
                .iter()
                .next()
                .map(|(_, abort)| abort.clone())
                .expect("finalized fixture abort")
        };
        let encoded = json::to_json(&world).expect("serialize finalized settlement World");
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let restored = parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse finalized settlement World"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .expect("restore every private-settlement map");

        assert_eq!(restored.private_settlement_governance.view().len(), 2);
        assert_eq!(restored.private_settlement_pools.view().len(), 2);
        assert_eq!(restored.private_settlement_roots.view().len(), 4);
        assert_eq!(restored.private_settlement_nullifiers.view().len(), 4);
        assert_eq!(restored.private_settlement_outputs.view().len(), 6);
        assert_eq!(restored.private_settlement_recipient_index.view().len(), 6);
        assert_eq!(restored.private_settlement_staged_locks.view().len(), 0);
        assert_eq!(restored.private_settlement_receipts.view().len(), 1);
        assert_eq!(restored.private_settlement_aborts.view().len(), 1);
        assert_eq!(
            restored
                .view()
                .private_settlement_receipt_v1(&receipt.manifest.bundle_id),
            Some(&receipt)
        );
        assert_eq!(
            restored
                .view()
                .private_settlement_abort_v1(&abort.bundle_id),
            Some(&abort)
        );
        assert_eq!(
            json::to_json(&restored).expect("re-encode restored settlement World"),
            encoded,
            "canonical restart must preserve every public settlement byte"
        );
        assert!(
            !encoded.contains("private_settlement_recipient_index"),
            "the deterministically rebuilt recipient index must not alter snapshot schema"
        );
    }

    #[test]
    fn private_settlement_prepared_snapshot_roundtrip_restores_exact_lock_rows() {
        let world = crate::private_settlement::global_state::tests::prepared_world_fixture();
        let (bundle_id, barrier, row_count) = {
            let locks = world.private_settlement_staged_locks.view();
            let (bundle_id, barrier) = locks
                .iter()
                .find_map(|(key, record)| match (key, record) {
                    (
                        PrivateSettlementStagedLockKeyV1::Bundle(bundle_id),
                        PrivateSettlementStagedLockRecordV1::Bundle { barrier, .. },
                    ) => Some((*bundle_id, barrier.clone())),
                    _ => None,
                })
                .expect("prepared fixture bundle lock");
            (bundle_id, barrier, locks.len())
        };
        let encoded = json::to_json(&world).expect("serialize prepared settlement World");
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let restored = parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse prepared settlement World"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .expect("restore prepared settlement lock map");
        assert_eq!(
            restored.private_settlement_staged_locks.view().len(),
            row_count
        );
        assert_eq!(
            restored
                .view()
                .private_settlement_prepare_barrier_v1(&bundle_id),
            Some(&barrier)
        );
        assert_eq!(
            json::to_json(&restored).expect("re-encode prepared settlement World"),
            encoded,
            "prepared restart must preserve every staged-lock byte"
        );
    }

    #[test]
    fn private_settlement_snapshot_rejects_recipient_reuse_before_index_rebuild() {
        let mut world = crate::private_settlement::global_state::tests::finalized_world_fixture();
        let (first_recipient, second_key, mut second_record) = {
            let outputs = world.private_settlement_outputs.view();
            let mut entries = outputs.iter();
            let (_, first) = entries.next().expect("first finalized output");
            let (second_key, second) = entries.next().expect("second finalized output");
            (
                first.encrypted_output.recipient,
                *second_key,
                second.clone(),
            )
        };
        second_record.encrypted_output.recipient = first_recipient;
        world
            .private_settlement_outputs
            .insert(second_key, second_record);
        let encoded = json::to_json(&world).expect("serialize adversarial settlement World");
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let error = match parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse adversarial World"),
            &IvmSeed {
                operation_index_budget: &operation_index_budget,
                operation_index_refusal: &operation_index_refusal,
                ivm: &ivm,
                _marker: PhantomData,
            },
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        {
            Ok(_) => panic!("duplicate recipient output must fail before rebuilding the index"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("private-settlement state conflict"),
            "unexpected duplicate-recipient restore error: {error}"
        );
    }

    #[test]
    fn restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal() {
        use iroha_data_model::{
            isi::InstructionBox,
            prelude::{Level, Log},
        };
        use iroha_executor_data_model::isi::multisig::MultisigProposalState;
        let signer =
            iroha_crypto::KeyPair::from_seed(vec![77; 32], iroha_crypto::Algorithm::Ed25519);
        let account = iroha_data_model::account::AccountId::new(signer.public_key().clone());
        let instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "restored approved body".into(),
        ))];
        let hash = iroha_crypto::HashOf::new(&instructions);
        let key: iroha_model_base::state_path::StatePath = format!(
            "multisig/proposal/{}/{hash}",
            iroha_crypto::HashOf::new(&account)
        )
        .parse()
        .unwrap();
        let proposal = MultisigProposalState::new(
            account.clone(),
            hash,
            instructions,
            1,
            10_000,
            std::collections::BTreeSet::new(),
            None,
        );
        let mut world = World::with(
            [],
            [iroha_data_model::account::Account::new(account.clone()).build(&account)],
            [],
        );
        let original = norito::to_bytes(&proposal).unwrap();
        world
            .smart_contract_state_mut_for_testing()
            .insert(key.clone(), original.clone());
        let encoded = json::to_json(&world).unwrap();
        let ivm = IVM::new(0);
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let seed = IvmSeed {
            operation_index_budget: &operation_index_budget,
            operation_index_refusal: &operation_index_refusal,
            ivm: &ivm,
            _marker: PhantomData,
        };
        let budget = iroha_allocation::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        );
        const CEILING: usize = 64 * 1024 * 1024;
        let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
        let prefix_allocation = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, usize::MAX),
            || {
                decode_world_fields(&budget, fields, &seed)
                    .expect("fund the entire original World decoder before proposal validation");
                let norito::Error::TotalAllocationExceeded { attempted, .. } =
                    norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
                else {
                    panic!("cumulative decode usage probe");
                };
                usize::try_from(attempted).unwrap() - CEILING - 1
            },
        );
        let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                prefix_allocation,
                usize::MAX,
            ),
            || {
                let decoded = decode_world_fields(&budget, fields, &seed)
                    .expect("World fields finish within their measured budget");
                assert!(matches!(
                    crate::smartcontracts::isi::multisig::validate_persisted_proposals(
                        &decoded.view()
                    ),
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ));
            },
        );
        let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                prefix_allocation,
                usize::MAX,
            ),
            || parse_world(&budget, fields, &seed),
        )
        .err()
        .expect("unfinished proposal validation cannot publish a restored World");
        assert!(
            matches!(error, StateRestoreError::ExecutionDeferred(_)),
            "{error:?}"
        );
        let restored = parse_world(
            &budget,
            SnapshotJsonMap::parse(&encoded, "world").unwrap(),
            &seed,
        )
        .expect("retry identical serialized World with available decoder capacity");
        assert_eq!(
            restored.smart_contract_state.view().get(&key),
            Some(&original)
        );
        for rebound in [false, true] {
            let mut altered = proposal.clone();
            if rebound {
                altered.multisig_account_id = iroha_data_model::account::AccountId::new(
                    iroha_crypto::KeyPair::from_seed(
                        vec![78; 32],
                        iroha_crypto::Algorithm::Ed25519,
                    )
                    .public_key()
                    .clone(),
                );
            } else {
                altered.instructions = Vec::new();
            }
            world
                .smart_contract_state_mut_for_testing()
                .insert(key.clone(), norito::to_bytes(&altered).unwrap());
            let encoded = json::to_json(&world).unwrap();
            let error = parse_world(
                &budget,
                SnapshotJsonMap::parse(&encoded, "world").unwrap(),
                &seed,
            )
            .err()
            .expect("an inconsistent retained row is a completed restore rejection");
            assert!(
                matches!(&error, StateRestoreError::Serialization(json::Error::InvalidField { field, .. })
                    if field == "world.smart_contract_state.multisig/proposal"),
                "the exact retained proposal validation boundary rejects restoration: {error:?}"
            );
        }
    }
    #[test]
    fn first_release_world_decoder_requires_every_canonical_field() {
        let encoded = json::to_json(&World::default()).expect("serialize default World");
        let operation_index_budget = crate::state::kagemusha_operation_indexes::default_budget();
        let operation_index_refusal = std::cell::RefCell::new(None);
        let ivm = IVM::new(0);
        let seed = IvmSeed {
            operation_index_budget: &operation_index_budget,
            operation_index_refusal: &operation_index_refusal,
            ivm: &ivm,
            _marker: PhantomData,
        };

        assert!(
            !encoded.contains("\"account_aliases_by_account\"")
                && !encoded.contains("\"account_scope_directory\""),
            "derived account indexes must remain outside the canonical snapshot"
        );
        assert!(
            encoded.contains("\"manifest_aliases\""),
            "authoritative SoraFS alias records must remain in the canonical snapshot"
        );
        parse_world(
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            SnapshotJsonMap::parse(&encoded, "world").expect("parse default World"),
            &seed,
        )
        .map_err(crate::state::deserialize::snapshot_format_error_for_test)
        .expect("canonical World must decode while rebuilding skipped account indexes");

        for required in ["account_aliases", "private_dataspaces"] {
            let mut map = SnapshotJsonMap::parse(&encoded, "world").expect("parse default World");
            map.remove(required)
                .expect("canonical World contains required field");
            let error = match parse_world(
                &iroha_allocation::AllocationBudget::new(
                    iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                ),
                map,
                &seed,
            )
            .map_err(crate::state::deserialize::snapshot_format_error_for_test)
            {
                Ok(_) => panic!("a first-release snapshot cannot default a missing World field"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(required),
                "unexpected missing-field diagnostic: {error}"
            );
        }

        let encoded_prefix = encoded
            .strip_suffix('}')
            .expect("canonical World snapshot is a JSON object");
        for retired_field in [
            "council",
            "parliament_bodies",
            "lane_relay_emergency_validators",
        ] {
            let injected = format!("{encoded_prefix},\"{retired_field}\":[]}}");
            let error = SnapshotJsonMap::parse(&injected, "world")
                .and_then(|map| {
                    parse_world(
                        &iroha_allocation::AllocationBudget::new(
                            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
                        ),
                        map,
                        &seed,
                    )
                    .map_err(crate::state::deserialize::snapshot_format_error_for_test)
                })
                .err()
                .expect("retired caller-selected council state must fail closed");
            assert!(
                error.to_string().contains(retired_field)
                    && error.to_string().contains("unknown field"),
                "unexpected retired-field diagnostic: {error}"
            );
        }
    }
    #[test]
    fn canonical_state_snapshot_persists_manifest_aliases_and_rebuilds_account_indexes() {
        let mut world = World::default();
        let account_id = AccountId::new(crate::state::checked_keypair().public_key().clone());
        let alias_domain =
            AccountAliasDomain::new("parliament".parse().expect("account alias domain"));
        let account_alias = AccountAlias::new(
            "member".parse().expect("account alias label"),
            Some(alias_domain.clone()),
            DataSpaceId::UNIVERSAL,
        );
        let account_details = AccountDetails::new(
            Metadata::default(),
            Some(account_alias.clone()),
            None,
            Vec::new(),
        );
        world
            .accounts
            .insert(account_id.clone(), AccountValue::new(account_details));
        world
            .account_aliases
            .insert(account_alias.clone(), account_id.clone());
        world.account_rekey_records.insert(
            account_alias.clone(),
            AccountRekeyRecord::new(account_alias.clone(), account_id.clone()),
        );

        let manifest_binding = ManifestAliasBinding {
            name: "parliament".to_owned(),
            namespace: "sora".to_owned(),
            proof: vec![0xA5; 32],
        };
        let manifest_alias_id = ManifestAliasId::from(&manifest_binding);
        let manifest_alias_record = ManifestAliasRecord::new(
            manifest_binding,
            ManifestDigest::new([0xB6; 32]),
            account_id.clone(),
            7,
            19,
        );
        world
            .manifest_aliases
            .insert(manifest_alias_id.clone(), manifest_alias_record.clone());

        let kura = Kura::blank_kura_for_testing();
        let state = State::new_for_testing(world, Arc::clone(&kura), LiveQueryStore::start_test());
        let encoded = json::to_json(&state).expect("serialize populated State");
        assert!(!encoded.contains("\"account_aliases_by_account\""));
        assert!(!encoded.contains("\"account_scope_directory\""));
        let snapshot = json::to_value(&state).expect("serialize populated State snapshot");
        let restored = KuraSeed {
            operation_index_budget: crate::state::kagemusha_operation_indexes::default_budget(),
            execution_budget: iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            lane_manifests: state.lane_manifests.read().clone(),
            kura,
            query_handle: LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            telemetry: crate::telemetry::StateTelemetry::default(),
        }
        .into_state_from_json(snapshot)
        .expect("restore populated canonical State");

        assert_eq!(
            restored
                .world
                .manifest_aliases
                .view()
                .get(&manifest_alias_id),
            Some(&manifest_alias_record),
            "authoritative manifest alias metadata must survive restart"
        );
        assert_eq!(
            restored
                .world
                .account_aliases_by_account
                .view()
                .get(&account_id),
            Some(&BTreeSet::from([account_alias.clone()])),
            "the reverse alias index must be rebuilt from authoritative bindings"
        );
        let restored_scope = restored
            .world
            .account_scope_directory
            .view()
            .get(&account_id)
            .cloned()
            .expect("the account scope directory must be rebuilt");
        assert!(
            restored_scope.iter().any(|(dataspace, domains)| {
                *dataspace == DataSpaceId::UNIVERSAL && domains.contains(&alias_domain)
            }),
            "the rebuilt account scope must retain the authoritative alias domain"
        );
    }
    #[test]
    fn borrowed_snapshot_field_errors_retain_the_schema_field() {
        let error = match (SnapshotJsonField::Borrowed { raw: "[]" })
            .decode_canonical::<Cell<Vec<PeerId>>>("commit_topology")
        {
            Ok(_) => panic!("an array must not decode as an MV topology cell"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            json::Error::InvalidField { field, message }
                if field == "commit_topology" && message.contains("expected object start")
        ));
    }
    #[test]
    fn snapshot_record_order_must_be_strict_and_duplicate_free() {
        validate_canonical_snapshot_record_order(&[1_u8, 2, 3], "fixture", |value| *value)
            .expect("strict order is canonical");
        assert!(
            validate_canonical_snapshot_record_order(&[2_u8, 1], "fixture", |value| *value)
                .is_err()
        );
        assert!(
            validate_canonical_snapshot_record_order(&[1_u8, 1], "fixture", |value| *value)
                .is_err()
        );
    }
    #[test]
    fn snapshot_norito_records_require_exact_canonical_bytes() {
        SNAPSHOT_NORITO_CANONICAL_PASSES.with(|passes| passes.set(0));
        let encoded = 7_u64.encode();
        let record = SnapshotNoritoBlob {
            encoded_hex: hex::encode(&encoded),
        };
        assert_eq!(
            decode_snapshot_records::<u64>(vec![record], "fixture")
                .expect("canonical Norito record"),
            [7]
        );
        let mut trailing = encoded;
        trailing.push(0);
        let error = decode_snapshot_records::<u64>(
            vec![SnapshotNoritoBlob {
                encoded_hex: hex::encode(trailing),
            }],
            "fixture",
        )
        .expect_err("trailing or alternate Norito bytes must fail closed");
        assert!(error.to_string().contains("fixture"));
        SNAPSHOT_NORITO_CANONICAL_PASSES.with(|passes| assert_eq!(passes.get(), 1));
    }
    #[test]
    fn take_parameters_cell_rejects_legacy_blocks_envelope() {
        let expected = Parameters::default();
        let blocks = norito::json::to_value(&expected).expect("serialize parameters");
        let mut legacy_map = json::native::Map::new();
        legacy_map.insert("blocks".to_owned(), blocks);
        let mut map = json::native::Map::new();
        map.insert("parameters".to_owned(), json::Value::Object(legacy_map));
        let mut map = SnapshotJsonMap::from_owned(map);
        let error = take_parameters_cell(&mut map, "parameters")
            .err()
            .expect("legacy blocks-only parameters envelope must be rejected");
        assert!(
            error.to_string().contains("parameters"),
            "unexpected diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_provider_attestation_snapshot_store_roundtrips_and_is_required() {
        assert!(
            World::default()
                .musubi_provider_bundle_attestations
                .view()
                .is_empty(),
            "a new first-release world starts with an empty attestation registry"
        );
        let (mut world, release, archive_id, _) = seeded_musubi_publication_snapshot();
        let attestation_key = seed_provider_attested_location(&mut world, &release, archive_id);
        let expected = world
            .musubi_provider_bundle_attestations
            .view()
            .get(&attestation_key)
            .cloned()
            .expect("seeded provider attestation record");
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_provider_bundle_attestations".to_owned(),
            json::to_value(&world.musubi_provider_bundle_attestations)
                .expect("serialize provider attestation snapshot store"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let parsed: Storage<
            MusubiProviderBundleAttestationKeyV1,
            MusubiProviderBundleAttestationRecordV1,
        > = take_required(&mut map, "musubi_provider_bundle_attestations")
            .expect("decode provider attestation snapshot store");
        assert_eq!(parsed.view().get(&attestation_key), Some(&expected));
        assert!(map.is_empty());
        let error = take_required::<
            Storage<MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1>,
        >(
            &mut SnapshotJsonMap::from_owned(json::native::Map::new()),
            "musubi_provider_bundle_attestations",
        )
        .err()
        .expect("missing provider attestation snapshot store must fail");
        assert!(
            error
                .to_string()
                .contains("musubi_provider_bundle_attestations"),
            "unexpected missing-field error: {error}"
        );
    }
    #[test]
    fn musubi_maintainer_directory_snapshot_store_roundtrips_and_is_required() {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            iroha_data_model::musubi::MusubiPackageScopeV1::DataspaceRoot,
            "snapshot-package".parse().expect("package name"),
        );
        let owner = musubi_account(41);
        let invited = musubi_account(42);
        let accepted = MusubiPackageMemberV1 {
            package: package.clone(),
            account: owner.clone(),
            role: iroha_data_model::musubi::MusubiPackageRoleV1::Owner,
            accepted_at_height: 5,
            governance_revision: 1,
        };
        let invitation = MusubiMaintainerInvitationV1 {
            invite_id: MusubiInviteIdV1::new([0x2A; 32]),
            package,
            invited_by: owner,
            invited_account: invited,
            role: iroha_data_model::musubi::MusubiPackageRoleV1::Maintainer(
                iroha_data_model::musubi::MusubiMaintainerPermissionsV1 {
                    publish: true,
                    yank: false,
                    metadata: true,
                    archive_locations: false,
                },
            ),
            expected_governance_revision: 1,
            expires_at_height: 50,
            state: iroha_data_model::musubi::MusubiInvitationStateV1::Pending,
        };
        let accepted_entry = MusubiMaintainerDirectoryEntryV1::Accepted(accepted);
        let invitation_entry = MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation);
        let mut expected = Storage::default();
        expected.insert(accepted_entry.key(), accepted_entry.clone());
        expected.insert(invitation_entry.key(), invitation_entry.clone());
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_maintainer_directory".to_owned(),
            json::to_value(&expected).expect("serialize maintainer directory snapshot store"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let parsed: Storage<MusubiMaintainerDirectoryKeyV1, MusubiMaintainerDirectoryEntryV1> =
            take_required(&mut map, "musubi_maintainer_directory")
                .expect("decode maintainer directory snapshot store");
        assert_eq!(
            parsed.view().get(&accepted_entry.key()),
            Some(&accepted_entry)
        );
        assert_eq!(
            parsed.view().get(&invitation_entry.key()),
            Some(&invitation_entry)
        );
        assert!(map.is_empty());
        let error = take_required::<
            Storage<MusubiMaintainerDirectoryKeyV1, MusubiMaintainerDirectoryEntryV1>,
        >(
            &mut SnapshotJsonMap::from_owned(json::native::Map::new()),
            "musubi_maintainer_directory",
        )
        .err()
        .expect("missing maintainer directory snapshot store must fail");
        assert!(
            error.to_string().contains("musubi_maintainer_directory"),
            "unexpected missing-field error: {error}"
        );
    }
    #[test]
    fn take_musubi_namespace_bindings_rejects_missing_malformed_and_key_mismatch() {
        let namespace: MusubiNamespaceV1 = "universal".parse().expect("namespace");
        let binding = MusubiNamespaceBindingV1 {
            namespace: namespace.clone(),
            home_dataspace: DataSpaceId::UNIVERSAL,
            scope: MusubiPackageScopeV1::DataspaceRoot,
            generation: 1,
        };
        let mut bindings = Storage::default();
        bindings.insert(namespace.clone(), binding.clone());
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_namespace_bindings".to_owned(),
            json::to_value(&bindings).expect("serialize bindings"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let parsed =
            take_musubi_namespace_bindings(&mut map).expect("canonical namespace binding map");
        assert_eq!(parsed.view().get(&namespace), Some(&binding));
        let error = take_musubi_namespace_bindings(&mut SnapshotJsonMap::from_owned(
            json::native::Map::new(),
        ))
        .err()
        .expect("missing namespace binding map must fail");
        assert!(
            error.to_string().contains("musubi_namespace_bindings"),
            "unexpected missing-field error: {error}"
        );
        let mut malformed = Storage::default();
        malformed.insert(
            namespace.clone(),
            MusubiNamespaceBindingV1 {
                generation: 0,
                ..binding.clone()
            },
        );
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_namespace_bindings".to_owned(),
            json::to_value(&malformed).expect("serialize malformed binding"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let error = take_musubi_namespace_bindings(&mut map)
            .err()
            .expect("malformed namespace binding must fail");
        assert!(
            error.to_string().contains("musubi_namespace_bindings"),
            "unexpected malformed-binding error: {error}"
        );
        let mismatched_namespace: MusubiNamespaceV1 =
            "other.universal".parse().expect("mismatched namespace");
        let mut mismatched = Storage::default();
        mismatched.insert(mismatched_namespace, binding);
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_namespace_bindings".to_owned(),
            json::to_value(&mismatched).expect("serialize mismatched binding"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let error = take_musubi_namespace_bindings(&mut map)
            .err()
            .expect("namespace key/value mismatch must fail");
        assert!(
            error
                .to_string()
                .contains("does not match embedded namespace"),
            "unexpected key-mismatch error: {error}"
        );
    }
    #[test]
    fn take_musubi_domain_generations_requires_canonical_persisted_values() {
        let domain = DomainId::try_new("packages", "universal").expect("domain id");
        let error = take_musubi_domain_ownership_generations(&mut SnapshotJsonMap::from_owned(
            json::native::Map::new(),
        ))
        .err()
        .expect("missing generation map must fail");
        assert!(
            error
                .to_string()
                .contains("musubi_domain_ownership_generations"),
            "unexpected missing-field error: {error}"
        );
        let empty: Storage<DomainId, u64> = Storage::default();
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_domain_ownership_generations".to_owned(),
            json::to_value(&empty).expect("serialize empty generation map"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        assert!(
            take_musubi_domain_ownership_generations(&mut map)
                .expect("empty required map represents all generation-one domains")
                .view()
                .is_empty()
        );
        for generation in [0, 1] {
            let mut generations = Storage::default();
            generations.insert(domain.clone(), generation);
            let mut map = json::native::Map::new();
            map.insert(
                "musubi_domain_ownership_generations".to_owned(),
                json::to_value(&generations).expect("serialize invalid generation map"),
            );
            let mut map = SnapshotJsonMap::from_owned(map);
            let error = take_musubi_domain_ownership_generations(&mut map)
                .err()
                .unwrap_or_else(|| panic!("persisted generation {generation} must fail"));
            assert!(
                error.to_string().contains("noncanonical generation"),
                "unexpected generation {generation} error: {error}"
            );
        }
        let mut generations = Storage::default();
        generations.insert(domain.clone(), 4);
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_domain_ownership_generations".to_owned(),
            json::to_value(&generations).expect("serialize canonical generation map"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let parsed = take_musubi_domain_ownership_generations(&mut map)
            .expect("persisted generation four is canonical");
        assert_eq!(parsed.view().get(&domain), Some(&4));
    }
    #[test]
    fn take_musubi_policy_revision_and_shortfall_fail_closed() {
        let policy = MusubiRegistryPolicyV1::default();
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_registry_policy".to_owned(),
            json::to_value(&Cell::new(policy.clone())).expect("serialize policy"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        assert_eq!(
            take_musubi_registry_policy(&mut map)
                .expect("canonical policy")
                .view()
                .get(),
            &policy
        );
        let mut invalid_policy = policy;
        invalid_policy.revision = 0;
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_registry_policy".to_owned(),
            json::to_value(&Cell::new(invalid_policy)).expect("serialize invalid policy"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let error = take_musubi_registry_policy(&mut map)
            .err()
            .expect("invalid policy must fail");
        assert!(
            error.to_string().contains("musubi_registry_policy"),
            "unexpected policy error: {error}"
        );
        assert!(
            take_musubi_registry_policy(
                &mut SnapshotJsonMap::from_owned(json::native::Map::new(),)
            )
            .is_err(),
            "missing policy must fail"
        );
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_resolver_index_revision".to_owned(),
            json::to_value(&Cell::new(MusubiResolverIndexRevisionV1::default()))
                .expect("serialize resolver revision"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        assert_eq!(
            take_musubi_resolver_index_revision(&mut map)
                .expect("canonical resolver revision")
                .view()
                .get()
                .get(),
            1
        );
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_resolver_index_revision".to_owned(),
            json::to_value(&Cell::new(MusubiResolverIndexRevisionV1(0)))
                .expect("serialize zero resolver revision"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let error = take_musubi_resolver_index_revision(&mut map)
            .err()
            .expect("zero resolver revision must fail");
        assert!(
            error.to_string().contains("musubi_resolver_index_revision"),
            "unexpected resolver revision error: {error}"
        );
        assert!(
            take_musubi_resolver_index_revision(&mut SnapshotJsonMap::from_owned(
                json::native::Map::new(),
            ))
            .is_err(),
            "missing resolver revision must fail"
        );
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_replication_shortfall_releases".to_owned(),
            json::to_value(&Cell::new(7_u64)).expect("serialize shortfall count"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        assert_eq!(
            *take_musubi_replication_shortfall_releases(
                &mut map,
                &crate::state::scalar_cell_custody::default_budget()
            )
            .expect("canonical shortfall count")
            .view()
            .get(),
            7
        );
        let error = take_musubi_replication_shortfall_releases(
            &mut SnapshotJsonMap::from_owned(json::native::Map::new()),
            &crate::state::scalar_cell_custody::default_budget(),
        )
        .err()
        .expect("missing shortfall count must fail cleanly");
        assert!(
            error
                .to_string()
                .contains("musubi_replication_shortfall_releases"),
            "unexpected missing-shortfall error: {error}"
        );
    }
    #[test]
    fn funded_scalar_restore_preserves_both_cuts_and_refuses_local_capacity_separately() {
        let raw = r#"{"musubi_replication_shortfall_releases":{"revert":{"value":6},"blocks":9}}"#;
        let demand = mv::cell::CellInitialization::<u64>::allocation_layouts()
            .into_iter()
            .map(|layout| layout.size())
            .sum::<usize>();
        let pool = iroha_allocation::AllocationBudget::new(demand - 1);
        let mut map = SnapshotJsonMap::parse(raw, "world").unwrap();
        let error = take_musubi_replication_shortfall_releases(&mut map, &pool)
            .err()
            .unwrap();
        assert!(matches!(error, StateRestoreError::Admission(_)));
        assert_eq!(pool.reserved_bytes(), 0);
        // Logical refusal did not consume the original encoded field.
        pool.set_limit_bytes(demand);
        let value = take_musubi_replication_shortfall_releases(&mut map, &pool).unwrap();
        assert_eq!(*value.view().get(), 9);
        assert_eq!(*value.predecessor_view().get(), Some(6));
        assert_eq!(pool.reserved_bytes(), demand);
        for raw in [
            r#"{"musubi_replication_shortfall_releases":{"blocks":9,"revert":{"value":6}}}"#,
            r#"{"musubi_replication_shortfall_releases":{"revert":{"value":6},"blocks":9,"extra":0}}"#,
            r#"{"musubi_replication_shortfall_releases":{"revert":{"value":6},"blocks":9,"blocks":9}}"#,
        ] {
            let budget = iroha_allocation::AllocationBudget::new(demand);
            let mut map = match SnapshotJsonMap::parse(raw, "world") {
                Ok(map) => map,
                Err(error) => {
                    // The canonical JSON scanner rejects nested duplicate keys
                    // before a field decoder can acquire any funded shells.
                    assert!(raw.contains("\"blocks\":9,\"blocks\":9"));
                    assert!(error.to_string().contains("duplicate field `blocks`"));
                    assert_eq!(budget.reserved_bytes(), 0);
                    continue;
                }
            };
            let error = take_musubi_replication_shortfall_releases(&mut map, &budget)
                .err()
                .unwrap();
            assert!(
                matches!(error, StateRestoreError::Serialization(_)),
                "exact signed field identity remains mandatory"
            );
            assert_eq!(
                budget.reserved_bytes(),
                0,
                "failed parsing abandons only unused physical shells"
            );
        }
    }

    #[test]
    fn musubi_resolver_checkpoint_keys_use_canonical_nonzero_decimal() {
        use norito::json::JsonKeyCodec;
        let revision = MusubiResolverIndexRevisionV1::new(42).expect("revision forty-two");
        let mut encoded = String::new();
        revision.encode_json_key(&mut encoded);
        assert_eq!(encoded, "\"42\"");
        assert_eq!(
            MusubiResolverIndexRevisionV1::decode_json_key("42").expect("canonical revision key"),
            revision
        );
        for invalid in ["0", "00", "01", "+1", " 1", "1 "] {
            assert!(
                MusubiResolverIndexRevisionV1::decode_json_key(invalid).is_err(),
                "noncanonical revision key must fail: {invalid:?}"
            );
        }
    }
    #[test]
    fn musubi_resolver_checkpoints_are_required_and_canonically_anchored() {
        let revision = MusubiResolverIndexRevisionV1::new(1).expect("revision one");
        let checkpoint = MusubiRegistrySnapshotV1 {
            finalized_height: 1,
            finalized_block_hash: [0xA1; 32],
            index_revision: 1,
        };
        let mut checkpoints = Storage::default();
        checkpoints.insert(revision, checkpoint.clone());
        let mut map = json::native::Map::new();
        map.insert(
            "musubi_resolver_index_checkpoints".to_owned(),
            json::to_value(&checkpoints).expect("serialize resolver checkpoints"),
        );
        let mut map = SnapshotJsonMap::from_owned(map);
        let decoded = take_musubi_resolver_index_checkpoints(&mut map)
            .expect("checkpoint store is required and decodable");
        validate_musubi_resolver_checkpoint_structure(&decoded, 1)
            .expect("canonical sparse checkpoint structure");
        assert!(
            take_musubi_resolver_index_checkpoints(&mut SnapshotJsonMap::from_owned(
                json::native::Map::new(),
            ))
            .is_err(),
            "the clean schema must reject snapshots without checkpoint history"
        );
        let mut mismatched = Storage::default();
        mismatched.insert(
            MusubiResolverIndexRevisionV1::new(2).expect("revision two"),
            checkpoint,
        );
        assert!(
            validate_musubi_resolver_checkpoint_structure(&mismatched, 2).is_err(),
            "checkpoint keys must match embedded revisions"
        );
        let mut world = World::default();
        world.musubi_resolver_index_checkpoints = decoded;
        let canonical_hash =
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA1; Hash::LENGTH]));
        validate_musubi_resolver_checkpoint_anchors(&world, std::slice::from_ref(&canonical_hash))
            .expect("checkpoint binds its canonical finalized block");
        let fabricated_hash =
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xB2; Hash::LENGTH]));
        assert!(
            validate_musubi_resolver_checkpoint_anchors(
                &world,
                std::slice::from_ref(&fabricated_hash)
            )
            .is_err(),
            "a fabricated checkpoint tuple must fail restoration"
        );
    }
    #[test]
    fn musubi_governance_requires_exact_fingerprint_and_execution_boundary() {
        let genesis = MusubiRegistryPolicyV1::default();
        let successor = musubi_policy_successor(&genesis, MusubiRegistryAdmissionModeV1::Closed);
        let action = MusubiParliamentActionV1::SetRegistryPolicy(MusubiSetRegistryPolicyActionV1 {
            policy: successor.clone(),
            expected_revision: genesis.revision,
        });
        let decision_id = ProposalKind::MusubiRegistryGovernance(action.clone()).fingerprint();
        let mut world = World::default();
        world.musubi_registry_policy = Cell::new(successor.clone());
        retain_musubi_consumption(&mut world, action.clone(), 110, 120, 120);
        validate_musubi_governance_provenance(&world)
            .expect("execution exactly at the boundary must pass");
        let mut consumption = world
            .musubi_governance_decisions
            .view()
            .get(&decision_id)
            .copied()
            .expect("retained consumption");
        consumption.consumed_at_height = 119;
        world
            .musubi_governance_decisions
            .insert(decision_id, consumption);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("pre-boundary consumption must fail");
        assert!(error.to_string().contains("consumed before"), "{error}");
        let wrong_id = if decision_id == [0xA5; 32] {
            [0x5A; 32]
        } else {
            [0xA5; 32]
        };
        let mut mismatched = World::default();
        mismatched.musubi_registry_policy = Cell::new(successor);
        retain_musubi_consumption_as(&mut mismatched, wrong_id, action, 110, 120, 120);
        let error = validate_musubi_governance_provenance(&mismatched)
            .expect_err("proposal fingerprint mismatch must fail");
        assert!(error.to_string().contains("fingerprint"), "{error}");
    }
    #[test]
    fn musubi_owner_recovery_current_projection_is_exact() {
        let mut world = World::default();
        let package = musubi_package("current-recovery");
        let owner = musubi_account(71);
        let member = seed_current_musubi_package(&mut world, &package, &owner, 2, 120);
        let action = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
            package: package.clone(),
            owners: vec![owner.clone()],
            expected_revision: 1,
        });
        retain_musubi_consumption(&mut world, action, 110, 120, 120);
        validate_musubi_governance_provenance(&world).expect("exact current recovery projection");
        let canonical_package = world
            .musubi_packages
            .view()
            .get(&package)
            .cloned()
            .expect("package");
        let mut wrong_package = canonical_package.clone();
        let unrelated = musubi_account(72);
        wrong_package.owners = vec![unrelated.clone()];
        wrong_package.member_accounts = vec![unrelated];
        wrong_package
            .validate()
            .expect("structurally valid package");
        world.musubi_packages.insert(package.clone(), wrong_package);
        assert!(
            validate_musubi_governance_provenance(&world)
                .expect_err("wrong owner set")
                .to_string()
                .contains("owner-recovery projection")
        );
        world
            .musubi_packages
            .insert(package.clone(), canonical_package);
        let key = member.key();
        {
            let mut members = world.musubi_package_members.block();
            members.remove(key.clone());
            members.commit();
        }
        assert!(
            validate_musubi_governance_provenance(&world)
                .expect_err("missing recovered owner member")
                .to_string()
                .contains("exact member projection")
        );
        world
            .musubi_package_members
            .insert(key.clone(), member.clone());
        let mut wrong_member = member.clone();
        wrong_member.role = MusubiPackageRoleV1::Maintainer(MusubiMaintainerPermissionsV1 {
            publish: true,
            yank: false,
            metadata: false,
            archive_locations: false,
        });
        world
            .musubi_package_members
            .insert(key.clone(), wrong_member);
        assert!(
            validate_musubi_governance_provenance(&world)
                .expect_err("wrong recovered owner role")
                .to_string()
                .contains("owner-recovery projection")
        );
        let mut wrong_member = member.clone();
        wrong_member.governance_revision = 1;
        world
            .musubi_package_members
            .insert(key.clone(), wrong_member);
        assert!(
            validate_musubi_governance_provenance(&world)
                .expect_err("wrong recovered owner revision")
                .to_string()
                .contains("owner-recovery projection")
        );
        let mut wrong_member = member;
        wrong_member.accepted_at_height = 121;
        world.musubi_package_members.insert(key, wrong_member);
        assert!(
            validate_musubi_governance_provenance(&world)
                .expect_err("wrong recovered owner acceptance height")
                .to_string()
                .contains("consumption height")
        );
    }
    #[test]
    fn musubi_owner_recovery_rejects_duplicate_result_revision_but_accepts_later_state() {
        let mut world = World::default();
        let package = musubi_package("recovery-history");
        let current_owner = musubi_account(80);
        seed_current_musubi_package(&mut world, &package, &current_owner, 3, 130);
        let first = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
            package: package.clone(),
            owners: vec![musubi_account(81)],
            expected_revision: 1,
        });
        retain_musubi_consumption(&mut world, first, 110, 120, 120);
        validate_musubi_governance_provenance(&world)
            .expect("later current revision need not reproduce historical owners");
        let duplicate =
            MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
                package,
                owners: vec![musubi_account(82)],
                expected_revision: 1,
            });
        retain_musubi_consumption(&mut world, duplicate, 111, 121, 121);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("two recoveries cannot claim the same result revision");
        assert!(error.to_string().contains("result revision"), "{error}");
    }
    #[test]
    fn musubi_policy_consumption_heights_are_nondecreasing() {
        let genesis = MusubiRegistryPolicyV1::default();
        let second = musubi_policy_successor(&genesis, MusubiRegistryAdmissionModeV1::Closed);
        let third = musubi_policy_successor(&second, MusubiRegistryAdmissionModeV1::Open);
        let first_action =
            MusubiParliamentActionV1::SetRegistryPolicy(MusubiSetRegistryPolicyActionV1 {
                policy: second.clone(),
                expected_revision: genesis.revision,
            });
        let first_id = ProposalKind::MusubiRegistryGovernance(first_action.clone()).fingerprint();
        let second_action =
            MusubiParliamentActionV1::SetRegistryPolicy(MusubiSetRegistryPolicyActionV1 {
                policy: third.clone(),
                expected_revision: second.revision,
            });
        let mut world = World::default();
        world.musubi_registry_policy = Cell::new(third);
        retain_musubi_consumption(&mut world, first_action, 110, 120, 121);
        retain_musubi_consumption(&mut world, second_action, 111, 121, 121);
        validate_musubi_governance_provenance(&world)
            .expect("equal same-block consumption heights are nondecreasing");
        let mut first = world
            .musubi_governance_decisions
            .view()
            .get(&first_id)
            .copied()
            .expect("first policy consumption");
        first.consumed_at_height = 122;
        first.validate().expect("still individually valid");
        world.musubi_governance_decisions.insert(first_id, first);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("policy revision history cannot move backward in height");
        assert!(error.to_string().contains("consumption heights"), "{error}");
    }
    #[test]
    fn musubi_owner_recovery_consumption_heights_are_nondecreasing() {
        let mut world = World::default();
        let package = musubi_package("recovery-height-history");
        let current_owner = musubi_account(90);
        seed_current_musubi_package(&mut world, &package, &current_owner, 3, 121);
        let first = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
            package: package.clone(),
            owners: vec![musubi_account(91)],
            expected_revision: 1,
        });
        retain_musubi_consumption(&mut world, first, 110, 120, 122);
        let second = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
            package,
            owners: vec![current_owner],
            expected_revision: 2,
        });
        retain_musubi_consumption(&mut world, second, 111, 121, 121);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("owner-recovery history cannot move backward in execution height");
        assert!(error.to_string().contains("consumption heights"), "{error}");
    }
    #[test]
    fn alias_retarget_history_binds_exact_decision_consumption_height() {
        const CONSUMED_AT: u64 = 130;
        let mut world = World::default();
        let alias: MusubiAliasNameV1 = "stable".parse().expect("alias");
        let previous_target = musubi_package("previous");
        let target = musubi_package("replacement");
        let action = MusubiParliamentActionV1::RetargetAlias(MusubiRetargetAliasV1 {
            alias: alias.clone(),
            target: target.clone(),
            expected_revision: 1,
        });
        let action_digest = retain_musubi_consumption(&mut world, action, 110, 120, CONSUMED_AT);
        let mut history = MusubiAliasHistoryEntryV1 {
            alias,
            revision: 2,
            action: MusubiAliasHistoryActionV1::ParliamentRetarget,
            previous_target: Some(previous_target),
            target,
            governance_action: Some(action_digest),
            finalized_height: CONSUMED_AT,
        };
        history.validate().expect("valid alias history fixture");
        let key = history.key();
        world
            .musubi_alias_history
            .insert(key.clone(), history.clone());
        validate_musubi_governance_provenance(&world)
            .expect("exact consumption-height binding must pass");
        history.finalized_height = CONSUMED_AT + 1;
        history
            .validate()
            .expect("height mismatch remains structurally valid");
        world.musubi_alias_history.insert(key, history);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("a different finalized height must fail closed");
        assert!(
            error.to_string().contains("decision consumption height"),
            "unexpected alias-height diagnostic: {error}"
        );
    }
    #[test]
    fn artifact_takedown_binds_exact_decision_consumption_height() {
        const CONSUMED_AT: u64 = 130;
        let mut world = World::default();
        let release = MusubiReleaseIdV1::new(
            musubi_package("withdrawn"),
            "1.2.3".parse().expect("release version"),
        );
        let reason: MusubiReasonV1 = "security response".parse().expect("bounded reason");
        let action = MusubiParliamentActionV1::TakedownArtifact(MusubiTakedownArtifactActionV1 {
            release: release.clone(),
            reason: reason.clone(),
            expected_artifact_governance_revision: 1,
        });
        let action_digest = retain_musubi_consumption(&mut world, action, 110, 120, CONSUMED_AT);
        let record = musubi_release_record(
            release.clone(),
            MusubiArtifactGovernanceStateV1::TakenDown(MusubiArtifactTakedownV1 {
                action_digest,
                reason,
                applied_at_height: CONSUMED_AT,
            }),
            2,
        );
        world
            .musubi_releases
            .insert(release.clone(), record.clone());
        validate_musubi_governance_provenance(&world)
            .expect("exact consumption-height binding must pass");
        let mut mismatched = record;
        let MusubiArtifactGovernanceStateV1::TakenDown(takedown) =
            &mut mismatched.artifact_governance
        else {
            unreachable!("takedown fixture")
        };
        takedown.applied_at_height = CONSUMED_AT + 1;
        mismatched
            .validate()
            .expect("height mismatch remains structurally valid");
        world.musubi_releases.insert(release, mismatched);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("a different takedown height must fail closed");
        assert!(
            error.to_string().contains("decision consumption height"),
            "unexpected takedown-height diagnostic: {error}"
        );
    }
    #[test]
    fn musubi_governance_provenance_reconstructs_policy_and_requires_proposals() {
        let mut world = World::default();
        validate_musubi_governance_provenance(&world)
            .expect("genesis Musubi policy has an empty decision history");
        let mut unexplained_policy = MusubiRegistryPolicyV1::default();
        unexplained_policy.revision += 1;
        unexplained_policy.mode = iroha_data_model::musubi::MusubiRegistryAdmissionModeV1::Closed;
        world.musubi_registry_policy = Cell::new(unexplained_policy);
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("policy state without retained decisions must fail closed");
        assert!(
            error.to_string().contains("exact result"),
            "unexpected unexplained-policy diagnostic: {error}"
        );
        let mut world = World::default();
        let mut successor = MusubiRegistryPolicyV1::default();
        successor.revision += 1;
        successor.mode = iroha_data_model::musubi::MusubiRegistryAdmissionModeV1::Closed;
        let action = iroha_data_model::musubi::MusubiParliamentActionV1::SetRegistryPolicy(
            iroha_data_model::musubi::MusubiSetRegistryPolicyActionV1 {
                policy: successor,
                expected_revision: 1,
            },
        );
        let decision_id = [0x31; 32];
        world.musubi_governance_decisions.insert(
            decision_id,
            MusubiGovernanceDecisionConsumptionV1 {
                decision: MusubiGovernanceDecisionV1 {
                    decision_id,
                    action_digest: action.action_digest(),
                    enacted_at_height: 10,
                    execute_after_height: 20,
                },
                minimum_enactment_delay: 10,
                consumed_at_height: 20,
            },
        );
        let error = validate_musubi_governance_provenance(&world)
            .expect_err("consumed decision without its proposal must fail closed");
        assert!(
            error
                .to_string()
                .contains("no retained governance proposal"),
            "unexpected missing-proposal diagnostic: {error}"
        );
    }
}
