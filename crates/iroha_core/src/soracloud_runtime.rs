//! Shared Soracloud runtime snapshot types and execution traits.
use crate::{
    smartcontracts::isi::staking::validator_election_eligible_at_height, state::WorldReadOnly,
};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::nexus::staking::PublicLaneValidatorStatus;
#[cfg(test)]
use iroha_data_model::soracloud::{
    SoraModelProvenanceKindV1, SoraModelProvenanceRefV1, SoraUploadedModelBundleV1,
};
use iroha_data_model::{
    account::AccountId,
    isi::InstructionBox,
    soracloud::{
        SoraAgentRuntimeStatusV1, SoraArtifactKindV1, SoraCertifiedResponsePolicyV1,
        SoraConfigExportV1, SoraContainerRuntimeV1, SoraDeploymentBundleV1, SoraInrouGuestIsaV1,
        SoraInrouReplicaHostAvailabilityV1, SoraInrouReplicaPlacementV1,
        SoraInrouServicePlacementRecordV1, SoraLeaseVolumeKindV1, SoraOrderedMailboxResultV1,
        SoraRuntimeDeterministicValidatorHostV1, SoraRuntimeReceiptV1,
        SoraServiceDeploymentStateV1, SoraServiceExecutionPlaneV1, SoraServiceHandlerClassV1,
        SoraServiceHandlerV1, SoraServiceHealthStatusV1, SoraServiceLeaseStatusV1,
        SoraServiceMailboxMessageV1, SoraServiceRuntimeStateV1, SoraStateEncryptionV1,
        SoraStateMutationOperationV1,
    },
    sorafs::pin_registry::StorageClass,
};
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
/// Return the greatest globally allocated Soracloud sequence.
///
/// The persisted transactional watermark makes allocation O(1) and permits independently pruned
/// history stores without reusing sequence numbers.
#[must_use]
pub fn latest_soracloud_sequence(world: &impl WorldReadOnly) -> u64 {
    world.soracloud_sequence_watermark()
}
/// Return the next authoritative Soracloud sequence visible from committed world state.
#[must_use]
pub fn authoritative_soracloud_sequence(world: &impl WorldReadOnly) -> u64 {
    latest_soracloud_sequence(world).saturating_add(1)
}

#[cfg(test)]
/// Validate the exact writer-produced finalization projections for an uploaded-model bundle.
///
/// A registered bundle is final only once one unambiguous `UserUpload` weight projection
/// and its matching artifact projection exist. The projection records must preserve the
/// immutable provenance fields written by finalization, and their registration sequences must be
/// the exact consecutive pair allocated by that atomic instruction. Service revision metadata is
/// deliberately excluded from the equality check because later promotion updates the weight
/// projection without rewriting its immutable artifact.
///
/// # Errors
///
/// Returns a deterministic error when either projection is missing, ambiguous, invalid,
/// mis-keyed, non-consecutive, or does not exactly bind the uploaded bundle and its counterpart.
pub fn validate_finalized_soracloud_uploaded_model_release(
    world: &impl WorldReadOnly,
    bundle: &SoraUploadedModelBundleV1,
) -> Result<(), String> {
    let service_name = bundle.service_name.as_ref();
    let source_matches = |source: Option<&SoraModelProvenanceRefV1>| {
        source.is_some_and(|source| {
            source.kind == SoraModelProvenanceKindV1::UserUpload && source.id == bundle.model_id
        })
    };
    let mut matching_weights = world.soracloud_model_weight_versions().iter().filter(
        |((stored_service, _stored_model, stored_version), weight)| {
            stored_service == service_name
                && (stored_version == &bundle.weight_version
                    || weight.weight_version == bundle.weight_version)
                && source_matches(weight.source_provenance.as_ref())
        },
    );
    let Some((weight_key, weight)) = matching_weights.next() else {
        return Err(format!(
            "uploaded model `{}` version `{}` for service `{}` has not been finalized with an exact UserUpload weight projection",
            bundle.model_id, bundle.weight_version, bundle.service_name
        ));
    };
    if matching_weights.next().is_some() {
        return Err(format!(
            "uploaded model `{}` version `{}` for service `{}` has ambiguous UserUpload weight projections",
            bundle.model_id, bundle.weight_version, bundle.service_name
        ));
    }
    weight.validate().map_err(|error| {
        format!(
            "uploaded model `{}` version `{}` has an invalid finalization weight projection: {error}",
            bundle.model_id, bundle.weight_version
        )
    })?;
    let expected_weight_key = (
        service_name.to_owned(),
        weight.model_name.clone(),
        bundle.weight_version.clone(),
    );
    if weight_key != &expected_weight_key
        || weight.service_name != bundle.service_name
        || weight.weight_version != bundle.weight_version
        || !weight.training_job_id.is_empty()
    {
        return Err(format!(
            "uploaded model `{}` version `{}` finalization weight projection does not exactly bind its UserUpload source",
            bundle.model_id, bundle.weight_version
        ));
    }

    let mut matching_artifacts = world.soracloud_model_artifacts().iter().filter(
        |((stored_service, _stored_artifact), artifact)| {
            stored_service == service_name
                && (artifact.weight_version.as_deref() == Some(bundle.weight_version.as_str())
                    || artifact.consumed_by_version.as_deref()
                        == Some(bundle.weight_version.as_str()))
                && source_matches(artifact.source_provenance.as_ref())
        },
    );
    let Some((artifact_key, artifact)) = matching_artifacts.next() else {
        return Err(format!(
            "uploaded model `{}` version `{}` for service `{}` has not been finalized with an exact UserUpload artifact projection",
            bundle.model_id, bundle.weight_version, bundle.service_name
        ));
    };
    if matching_artifacts.next().is_some() {
        return Err(format!(
            "uploaded model `{}` version `{}` for service `{}` has ambiguous UserUpload artifact projections",
            bundle.model_id, bundle.weight_version, bundle.service_name
        ));
    }
    artifact.validate().map_err(|error| {
        format!(
            "uploaded model `{}` version `{}` has an invalid finalization artifact projection: {error}",
            bundle.model_id, bundle.weight_version
        )
    })?;
    let expected_artifact_key = (service_name.to_owned(), artifact.artifact_id.clone());
    if artifact_key != &expected_artifact_key
        || artifact.service_name != bundle.service_name
        || artifact.model_name != weight.model_name
        || artifact.training_job_id != artifact.artifact_id
        || artifact.weight_version.as_deref() != Some(bundle.weight_version.as_str())
        || artifact.consumed_by_version.as_deref() != Some(bundle.weight_version.as_str())
        || artifact.source_provenance != weight.source_provenance
        || artifact.weight_artifact_hash != weight.weight_artifact_hash
        || artifact.dataset_ref != weight.dataset_ref
        || artifact.training_config_hash != weight.training_config_hash
        || artifact.reproducibility_hash != weight.reproducibility_hash
        || artifact.provenance_attestation_hash != weight.provenance_attestation_hash
        || artifact.chunk_manifest_root != Some(bundle.chunk_manifest_root)
    {
        return Err(format!(
            "uploaded model `{}` version `{}` finalization artifact does not exactly match its UserUpload weight projection",
            bundle.model_id, bundle.weight_version
        ));
    }
    let expected_artifact_sequence =
        weight.registered_sequence.checked_add(1).ok_or_else(|| {
            format!(
                "uploaded model `{}` version `{}` finalization weight sequence overflows",
                bundle.model_id, bundle.weight_version
            )
        })?;
    if artifact.registered_sequence != expected_artifact_sequence {
        return Err(format!(
            "uploaded model `{}` version `{}` finalization weight and artifact sequences must be consecutive",
            bundle.model_id, bundle.weight_version
        ));
    }
    Ok(())
}

#[cfg(test)]
/// Return whether an account has an exact validator tenure active at one consensus height.
///
/// Soracloud adverts are only eligibility claims; validator lifecycle state remains the
/// authoritative admission gate for both placement and request serving.
#[must_use]
pub fn soracloud_validator_is_active(
    world: &impl WorldReadOnly,
    validator_account_id: &AccountId,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> bool {
    world.public_lane_validators().iter().any(|(key, record)| {
        &key.1 == validator_account_id
            && crate::state::public_lane_validator_record_matches_key(key, record)
            && validator_election_eligible_at_height(record, current_height)
            && lane_is_active_for_authority(key.0)
    })
}
/// Return whether an account has one exact height-active validator tenure bound to a peer.
///
/// The validator account and consensus peer can use different key roles. Their authoritative
/// association is the active public-lane validator record, so a stale advert becomes ineligible
/// immediately when that record changes.
#[must_use]
pub fn soracloud_validator_has_active_peer_binding(
    world: &impl WorldReadOnly,
    validator_account_id: &AccountId,
    peer_id: &str,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> bool {
    let Ok(canonical_peer_id) = peer_id.parse::<PeerId>() else {
        return false;
    };
    if canonical_peer_id.to_string() != peer_id {
        return false;
    }
    world.public_lane_validators().iter().any(|(key, record)| {
        &key.1 == validator_account_id
            && crate::state::public_lane_validator_record_matches_key(key, record)
            && validator_election_eligible_at_height(record, current_height)
            && record.peer_id == canonical_peer_id
            && lane_is_active_for_authority(key.0)
    })
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxDestinationFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxDestinationFingerprintV1 {
    service_name: Name,
    service_version: String,
    handler_name: Name,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxExecutorPreimageV1")]
#[derive(Encode)]
struct OrderedMailboxExecutorPreimageV1 {
    domain: String,
    beacon_height: u64,
    beacon_round: u64,
    beacon_pulse_id: [u8; 32],
    beacon_seed: [u8; 32],
    destination: OrderedMailboxDestinationFingerprintV1,
    host: SoraRuntimeDeterministicValidatorHostV1,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxPayloadFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxPayloadFingerprintV1 {
    payload_bytes: u64,
    payload_commitment: Hash,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxMutationFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxMutationFingerprintV1 {
    schema_version: u16,
    binding_name: Name,
    state_key: String,
    operation: SoraStateMutationOperationV1,
    encryption: SoraStateEncryptionV1,
    value_payload: Option<OrderedMailboxPayloadFingerprintV1>,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxMessageFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxMessageFingerprintV1 {
    schema_version: u16,
    message_id: Hash,
    from_service: Name,
    from_service_version: String,
    from_handler: Name,
    to_service: Name,
    to_service_version: String,
    to_handler: Name,
    payload_commitment: Hash,
    delivery_delay_blocks: u32,
    enqueue_sequence: u64,
    enqueue_height: u64,
    available_after_height: u64,
    expires_at_height: u64,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxReceiptFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxReceiptFingerprintV1 {
    mailbox_message_id: Option<Hash>,
    service_name: Name,
    service_version: String,
    handler_name: Name,
    handler_class: SoraServiceHandlerClassV1,
    request_commitment: Hash,
    certified_by: SoraCertifiedResponsePolicyV1,
    execution_host: Option<SoraRuntimeDeterministicValidatorHostV1>,
    journal_artifact_hash: Option<Hash>,
    checkpoint_artifact_hash: Option<Hash>,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxReceiptIdentityPreimageV1")]
#[derive(Encode)]
struct OrderedMailboxReceiptIdentityPreimageV1 {
    domain: String,
    schema_version: u16,
    mailbox_message_id: Hash,
    service_name: Name,
    service_version: String,
    handler_name: Name,
    handler_class: SoraServiceHandlerClassV1,
    request_commitment: Hash,
    result_commitment: Hash,
    certified_by: SoraCertifiedResponsePolicyV1,
    execution_host: Option<SoraRuntimeDeterministicValidatorHostV1>,
    journal_artifact_hash: Option<Hash>,
    checkpoint_artifact_hash: Option<Hash>,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxRuntimeStateFingerprintV1")]
#[derive(Encode)]
struct OrderedMailboxRuntimeStateFingerprintV1 {
    schema_version: u16,
    service_name: Name,
    active_service_version: String,
    health_status: SoraServiceHealthStatusV1,
    load_factor_bps: u16,
    materialized_bundle_hash: Hash,
}

#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::OrderedMailboxResultPreimageV1")]
#[derive(Encode)]
struct OrderedMailboxResultPreimageV1 {
    domain: String,
    receipt: OrderedMailboxReceiptFingerprintV1,
    state_mutations: Vec<OrderedMailboxMutationFingerprintV1>,
    outbound_mailbox_messages: Vec<OrderedMailboxMessageFingerprintV1>,
    response_commitment: Hash,
    runtime_execution_commitment: Hash,
    content_type: Option<String>,
    runtime_state: Option<OrderedMailboxRuntimeStateFingerprintV1>,
}

/// Select the exact height-active public-lane validator responsible for one mailbox message.
///
/// Selection is a deterministic rendezvous over the first finalized threshold-beacon pulse after
/// enqueue, the immutable destination, and each unique exact active validator identity. The
/// current height advances through the ranked candidates after a fixed grace, providing bounded
/// deterministic failover without caller-controlled entropy.
#[must_use]
pub fn resolve_ordered_mailbox_executor(
    world: &impl WorldReadOnly,
    message: &SoraServiceMailboxMessageV1,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> Option<SoraRuntimeDeterministicValidatorHostV1> {
    const EXECUTOR_FAILOVER_GRACE_BLOCKS: u64 = 10;
    let pulse = world
        .global_beacon_pulses()
        .iter()
        .map(|(_pulse_id, pulse)| *pulse)
        .filter(|pulse| pulse.height > message.enqueue_height)
        .min_by_key(|pulse| (pulse.height, pulse.round, pulse.pulse_id))?;
    let mut unique_hosts =
        BTreeMap::<(AccountId, String), SoraRuntimeDeterministicValidatorHostV1>::new();
    for (key, record) in world.public_lane_validators().iter() {
        if !crate::state::public_lane_validator_record_matches_key(key, record)
            || !validator_election_eligible_at_height(record, current_height)
            || !lane_is_active_for_authority(key.0)
        {
            continue;
        }
        let peer_id = record.peer_id.to_string();
        let host = SoraRuntimeDeterministicValidatorHostV1 {
            lane_id: key.0,
            validator_account_id: key.1.clone(),
            peer_id: peer_id.clone(),
        };
        unique_hosts
            .entry((key.1.clone(), peer_id))
            .and_modify(|existing| {
                if host.lane_id < existing.lane_id {
                    *existing = host.clone();
                }
            })
            .or_insert(host);
    }
    let mut ranked = unique_hosts
        .into_values()
        .map(|host| {
            let score = Hash::new(Encode::encode(&OrderedMailboxExecutorPreimageV1 {
                domain: "soracloud:ordered-mailbox-executor:v1".to_owned(),
                beacon_height: pulse.height,
                beacon_round: pulse.round,
                beacon_pulse_id: pulse.pulse_id,
                beacon_seed: pulse.seed,
                destination: OrderedMailboxDestinationFingerprintV1 {
                    service_name: message.to_service.clone(),
                    service_version: message.to_service_version.clone(),
                    handler_name: message.to_handler.clone(),
                },
                host: host.clone(),
            }));
            (score, host)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.validator_account_id.cmp(&right.validator_account_id))
            .then_with(|| left.peer_id.cmp(&right.peer_id))
            .then_with(|| left.lane_id.cmp(&right.lane_id))
    });
    let failover_started_at = message.available_after_height.max(pulse.height);
    let elapsed = current_height.saturating_sub(failover_started_at);
    let rank = usize::try_from(elapsed / EXECUTOR_FAILOVER_GRACE_BLOCKS).unwrap_or(usize::MAX);
    let selected_rank = rank.min(ranked.len().saturating_sub(1));
    ranked
        .into_iter()
        .nth(selected_rank)
        .map(|(_score, host)| host)
}
/// Compute the canonical commitment to every authoritative effect of an ordered mailbox result.
///
/// Observation height/sequence are optimistic-concurrency preconditions, not result identity.
/// The ledger-assigned receipt sequence is likewise deliberately excluded.
#[must_use]
pub fn ordered_mailbox_result_commitment(result: &SoraOrderedMailboxResultV1) -> Hash {
    let mutation_fingerprints = result
        .state_mutations
        .iter()
        .map(|mutation| OrderedMailboxMutationFingerprintV1 {
            schema_version: mutation.schema_version,
            binding_name: mutation.binding_name.clone(),
            state_key: mutation.state_key.clone(),
            operation: mutation.operation,
            encryption: mutation.encryption,
            value_payload: mutation.value_payload.as_ref().map(|payload| {
                OrderedMailboxPayloadFingerprintV1 {
                    payload_bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
                    payload_commitment: Hash::new(payload),
                }
            }),
        })
        .collect::<Vec<_>>();
    let outbound_fingerprints = result
        .outbound_mailbox_messages
        .iter()
        .map(|message| OrderedMailboxMessageFingerprintV1 {
            schema_version: message.schema_version,
            message_id: message.message_id,
            from_service: message.from_service.clone(),
            from_service_version: message.from_service_version.clone(),
            from_handler: message.from_handler.clone(),
            to_service: message.to_service.clone(),
            to_service_version: message.to_service_version.clone(),
            to_handler: message.to_handler.clone(),
            payload_commitment: message.payload_commitment,
            delivery_delay_blocks: message.delivery_delay_blocks,
            enqueue_sequence: message.enqueue_sequence,
            enqueue_height: message.enqueue_height,
            available_after_height: message.available_after_height,
            expires_at_height: message.expires_at_height,
        })
        .collect::<Vec<_>>();
    let receipt = &result.runtime_receipt;
    let runtime_state_fingerprint =
        result
            .runtime_state
            .as_ref()
            .map(|state| OrderedMailboxRuntimeStateFingerprintV1 {
                schema_version: state.schema_version,
                service_name: state.service_name.clone(),
                active_service_version: state.active_service_version.clone(),
                health_status: state.health_status,
                load_factor_bps: state.load_factor_bps,
                materialized_bundle_hash: state.materialized_bundle_hash,
            });
    Hash::new(Encode::encode(&OrderedMailboxResultPreimageV1 {
        domain: "soracloud:ordered-mailbox-result:v1".to_owned(),
        receipt: OrderedMailboxReceiptFingerprintV1 {
            mailbox_message_id: receipt.mailbox_message_id,
            service_name: receipt.service_name.clone(),
            service_version: receipt.service_version.clone(),
            handler_name: receipt.handler_name.clone(),
            handler_class: receipt.handler_class,
            request_commitment: receipt.request_commitment,
            certified_by: receipt.certified_by,
            execution_host: receipt.execution_host.clone(),
            journal_artifact_hash: receipt.journal_artifact_hash,
            checkpoint_artifact_hash: receipt.checkpoint_artifact_hash,
        },
        state_mutations: mutation_fingerprints,
        outbound_mailbox_messages: outbound_fingerprints,
        response_commitment: result.response_commitment,
        runtime_execution_commitment: result.runtime_execution_commitment,
        content_type: result.content_type.clone(),
        runtime_state: runtime_state_fingerprint,
    }))
}
/// Derive the sequence-independent identifier for an ordered mailbox receipt.
///
/// The identifier binds every immutable receipt field while excluding only the identifier itself
/// and the ledger-assigned emission sequence. Binding the full retained receipt directly keeps
/// snapshot validation self-contained after the ordered-result preimage has been discarded.
#[must_use]
pub fn ordered_mailbox_runtime_receipt_id(receipt: &SoraRuntimeReceiptV1) -> Option<Hash> {
    let message_id = receipt.mailbox_message_id?;
    Some(Hash::new(Encode::encode(
        &OrderedMailboxReceiptIdentityPreimageV1 {
            domain: "soracloud:ordered-mailbox-receipt:v1".to_owned(),
            schema_version: receipt.schema_version,
            mailbox_message_id: message_id,
            service_name: receipt.service_name.clone(),
            service_version: receipt.service_version.clone(),
            handler_name: receipt.handler_name.clone(),
            handler_class: receipt.handler_class,
            request_commitment: receipt.request_commitment,
            result_commitment: receipt.result_commitment,
            certified_by: receipt.certified_by,
            execution_host: receipt.execution_host.clone(),
            journal_artifact_hash: receipt.journal_artifact_hash,
            checkpoint_artifact_hash: receipt.checkpoint_artifact_hash,
        },
    )))
}

/// Derive the sequence-independent identifier from a validated ordered mailbox result.
#[must_use]
pub fn ordered_mailbox_receipt_id(result: &SoraOrderedMailboxResultV1) -> Hash {
    ordered_mailbox_runtime_receipt_id(&result.runtime_receipt)
        .expect("a validated ordered mailbox result must reference its source message")
}

/// Validate the exact authoritative lease-volume economics for one admitted service bundle.
///
/// Deployment state is the source used for prepaid storage accounting, so accepting missing,
/// extra, or altered rows would let routing and placement observe economics that differ from the
/// admitted manifest. This cross-record invariant deliberately has no compatibility fallback.
pub fn validate_soracloud_deployment_lease_volume_bindings(
    deployment: &SoraServiceDeploymentStateV1,
    bundle: &SoraDeploymentBundleV1,
) -> Result<(), String> {
    if deployment.service_name != bundle.service.service_name {
        return Err(format!(
            "deployment service `{}` does not match admitted bundle service `{}`",
            deployment.service_name, bundle.service.service_name
        ));
    }
    let mut declared_names = BTreeSet::new();
    for binding in &bundle.service.lease_volumes {
        if !declared_names.insert(binding.volume_name.clone()) {
            return Err(format!(
                "service `{}` admitted bundle contains duplicate lease-volume binding `{}`",
                deployment.service_name, binding.volume_name
            ));
        }
    }
    let mut authoritative_names = BTreeSet::new();
    for state in &deployment.lease_volume_states {
        if !authoritative_names.insert(state.volume_name.clone()) {
            return Err(format!(
                "service `{}` contains duplicate authoritative lease-volume state `{}`",
                deployment.service_name, state.volume_name
            ));
        }
    }
    if declared_names != authoritative_names {
        let missing = declared_names
            .difference(&authoritative_names)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let unexpected = authoritative_names
            .difference(&declared_names)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        return Err(format!(
            "service `{}` requires exact 1:1 admitted-to-authoritative lease-volume state; missing {missing:?}, unexpected {unexpected:?}",
            deployment.service_name
        ));
    }
    for binding in &bundle.service.lease_volumes {
        let Some(state) = deployment
            .lease_volume_states
            .iter()
            .find(|state| state.volume_name == binding.volume_name)
        else {
            return Err(format!(
                "service `{}` is missing authoritative lease-volume state for admitted binding `{}`",
                deployment.service_name, binding.volume_name
            ));
        };
        if state.authoritative_generation != 1 {
            return Err(format!(
                "service `{}` authoritative lease-volume state `{}` field `authoritative_generation` must equal 1 in the first-release protocol",
                deployment.service_name, binding.volume_name
            ));
        }
        for (field, matches) in [
            ("kind", state.kind == binding.kind),
            (
                "storage_class",
                state.storage_class == binding.storage_class,
            ),
            ("mount_path", state.mount_path == binding.mount_path),
            (
                "max_total_bytes",
                state.max_total_bytes == binding.max_total_bytes.get(),
            ),
        ] {
            if !matches {
                return Err(format!(
                    "service `{}` authoritative lease-volume state `{}` field `{field}` does not exactly match its admitted binding",
                    deployment.service_name, binding.volume_name
                ));
            }
        }
    }
    Ok(())
}

/// Validate the immutable identity shared by every admitted revision of one service.
///
/// A revision changes implementation, not execution, routing, or durable-state identity. Retained
/// revisions are rollback targets, so this invariant applies to upgrades, rollback, and restored
/// state alike.
/// The first release deliberately has no compatibility fallback for older revision shapes.
pub fn validate_soracloud_service_revision_identity(
    current: &SoraDeploymentBundleV1,
    candidate: &SoraDeploymentBundleV1,
) -> Result<(), String> {
    if candidate.service.service_name != current.service.service_name {
        return Err(format!(
            "service revision identity mismatch: candidate service `{}` does not match current service `{}`",
            candidate.service.service_name, current.service.service_name
        ));
    }
    if candidate.service.execution_plane != current.service.execution_plane {
        return Err(
            "service revision cannot change execution_plane; deploy a distinct service identity"
                .to_owned(),
        );
    }
    if candidate.container.runtime != current.container.runtime {
        return Err(
            "service revision cannot change container runtime; deploy a distinct service identity"
                .to_owned(),
        );
    }
    if candidate.service.route != current.service.route {
        return Err(
            "service revision cannot change route identity; deploy a distinct service identity"
                .to_owned(),
        );
    }
    if candidate.service.lease_volumes != current.service.lease_volumes {
        return Err(
            "service revision cannot change lease-volume identity or economics; deploy a distinct service identity"
                .to_owned(),
        );
    }
    if candidate.service.state_bindings != current.service.state_bindings {
        return Err(
            "service revision cannot change durable state-binding contracts; deploy a distinct service identity"
                .to_owned(),
        );
    }
    if current.container.runtime == SoraContainerRuntimeV1::Inrou {
        if candidate.service.replicas != current.service.replicas {
            return Err(
                "Inrou service revision cannot change replica count during the hosted-service lease; deploy a distinct service identity"
                    .to_owned(),
            );
        }
        if candidate.service.placement_targets != current.service.placement_targets {
            return Err(
                "Inrou service revision cannot change the exact placement-target allowlist during the hosted-service lease; deploy a distinct service identity"
                    .to_owned(),
            );
        }
        if candidate.container.inrou != current.container.inrou {
            return Err(
                "Inrou service revision cannot change the guest-platform manifest during the hosted-service lease; deploy a distinct service identity"
                    .to_owned(),
            );
        }
    }
    Ok(())
}
/// Resolve one authoritative Inrou placement record through its exact active deployment binding.
///
/// Missing or retained non-current state resolves to `None`. An active rollout, malformed record,
/// or cross-keyed authoritative state is an error so callers fail closed and reconciliation can
/// repair the row. First-release Inrou admits exactly one active revision.
pub fn resolve_active_inrou_placement_record(
    world: &impl WorldReadOnly,
    service_name: &str,
    service_version: &str,
    current_height: u64,
) -> Result<Option<SoraInrouServicePlacementRecordV1>, String> {
    let service_name_id = service_name.parse::<Name>().map_err(|error| {
        format!(
            "Inrou placement storage key contains invalid service name `{service_name}`: {error}"
        )
    })?;
    let key = (service_name.to_owned(), service_version.to_owned());
    let Some(record) = world
        .soracloud_inrou_service_placements()
        .get(&key)
        .cloned()
    else {
        return Ok(None);
    };
    record.validate().map_err(|error| {
        format!(
            "Inrou placement for service `{service_name}` revision `{service_version}` is malformed: {error}"
        )
    })?;
    if record.service_name != service_name_id || record.service_version != service_version {
        return Err(format!(
            "Inrou placement storage key `{service_name}`/`{service_version}` does not match embedded service `{}` revision `{}`",
            record.service_name, record.service_version
        ));
    }

    let Some(deployment) = world.soracloud_service_deployments().get(&service_name_id) else {
        return Ok(None);
    };
    deployment.validate().map_err(|error| {
        format!(
            "Inrou placement for service `{service_name}` revision `{service_version}` references a malformed deployment: {error}"
        )
    })?;
    if deployment.service_name != service_name_id {
        return Err(format!(
            "Inrou placement for service `{service_name}` revision `{service_version}` references a deployment whose embedded service is `{}`",
            deployment.service_name
        ));
    }
    if deployment.active_rollout.is_some() {
        return Err(format!(
            "service `{service_name}` carries an unsupported active Inrou canary; first-release host-local lease disks require one active revision"
        ));
    }
    if deployment.current_service_version != service_version {
        return Ok(None);
    }

    let Some(bundle) = world.soracloud_service_revisions().get(&key) else {
        return Err(format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` has no admitted deployment bundle"
        ));
    };
    bundle.validate_for_admission().map_err(|error| {
        format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` references a malformed deployment bundle: {error}"
        )
    })?;
    if bundle.service.service_name != service_name_id
        || bundle.service.service_version != service_version
    {
        return Err(format!(
            "Inrou revision storage key `{service_name}`/`{service_version}` does not match embedded service `{}` revision `{}`",
            bundle.service.service_name, bundle.service.service_version
        ));
    }
    if bundle.container.runtime != SoraContainerRuntimeV1::Inrou
        || bundle.service.execution_plane != SoraServiceExecutionPlaneV1::HttpService
    {
        return Err(format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` is not bound to an Inrou HTTP-service bundle"
        ));
    }
    validate_soracloud_deployment_lease_volume_bindings(deployment, bundle).map_err(|error| {
        format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` has noncanonical lease-volume economics: {error}"
        )
    })?;
    if !deployment
        .hosted_service_lease_active_at(current_height)
        .map_err(|error| {
            format!(
                "Inrou placement lifecycle for service `{service_name}` revision `{service_version}` could not be calculated: {error}"
            )
        })?
    {
        return Ok(None);
    }
    if deployment.lease_volume_states.iter().any(|volume| {
        current_height < volume.lease_started_height
            || current_height >= volume.lease_expires_height
    }) {
        return Ok(None);
    }
    if record.desired_replica_count != bundle.service.replicas.get() {
        return Err(format!(
            "Inrou placement for service `{service_name}` revision `{service_version}` declares {} replicas but the admitted bundle declares {}",
            record.desired_replica_count,
            bundle.service.replicas.get()
        ));
    }
    if deployment.current_service_manifest_hash != bundle.service_manifest_hash()
        || deployment.current_container_manifest_hash != bundle.container_manifest_hash()
    {
        return Err(format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` does not match the deployment's admitted manifest hashes"
        ));
    }
    Ok(Some(record))
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ActiveInrouReservationUsage {
    hosted_replicas: u32,
    cpu_millis: u64,
    memory_bytes: u64,
    storage_bytes: u64,
}
fn inrou_bundle_per_replica_storage_bytes(bundle: &SoraDeploymentBundleV1) -> Option<u64> {
    bundle
        .service
        .lease_volumes
        .iter()
        .filter(|volume| volume.kind.is_per_replica())
        .try_fold(
            bundle.container.resources.ephemeral_storage_bytes.get(),
            |total, volume| total.checked_add(volume.max_total_bytes.get()),
        )
}
fn active_inrou_reservation_usage_by_validator(
    world: &impl WorldReadOnly,
    current_height: u64,
) -> Result<BTreeMap<AccountId, ActiveInrouReservationUsage>, String> {
    let mut usage_by_validator = BTreeMap::new();
    for ((service_name, service_version), _record) in
        world.soracloud_inrou_service_placements().iter()
    {
        let Some(record) = resolve_active_inrou_placement_record(
            world,
            service_name,
            service_version,
            current_height,
        )?
        else {
            continue;
        };
        let bundle = world
            .soracloud_service_revisions()
            .get(&(
                service_name.as_str().to_owned(),
                service_version.as_str().to_owned(),
            ))
            .ok_or_else(|| {
                format!(
                    "active Inrou placement for service `{service_name}` revision `{service_version}` lost its admitted deployment bundle"
                )
            })?;
        let cpu_millis = bundle
            .container
            .resources
            .checked_inrou_host_cpu_millis()
            .ok_or_else(|| {
                format!(
                    "active Inrou per-replica physical CPU reservation overflows for service `{service_name}` revision `{service_version}`"
                )
            })?;
        let memory_bytes = bundle
            .container
            .resources
            .checked_inrou_host_memory_bytes()
            .ok_or_else(|| {
                format!(
                    "active Inrou per-replica physical memory reservation overflows for service `{service_name}` revision `{service_version}`"
                )
            })?;
        let storage_bytes = inrou_bundle_per_replica_storage_bytes(bundle).ok_or_else(|| {
            format!(
                "active Inrou per-replica storage reservation overflows for service `{service_name}` revision `{service_version}`"
            )
        })?;
        for assignment in record.placements {
            let validator_account_id = assignment.validator_account_id;
            let usage = usage_by_validator
                .entry(validator_account_id.clone())
                .or_insert_with(ActiveInrouReservationUsage::default);
            usage.hosted_replicas = usage.hosted_replicas.checked_add(1).ok_or_else(|| {
                format!(
                    "active Inrou replica reservations overflow for validator `{validator_account_id}`"
                )
            })?;
            usage.cpu_millis = usage.cpu_millis.checked_add(cpu_millis).ok_or_else(|| {
                format!(
                    "active Inrou CPU reservations overflow for validator `{validator_account_id}`"
                )
            })?;
            usage.memory_bytes = usage.memory_bytes.checked_add(memory_bytes).ok_or_else(|| {
                format!(
                    "active Inrou memory reservations overflow for validator `{validator_account_id}`"
                )
            })?;
            usage.storage_bytes = usage.storage_bytes.checked_add(storage_bytes).ok_or_else(|| {
                format!(
                    "active Inrou storage reservations overflow for validator `{validator_account_id}`"
                )
            })?;
        }
    }
    Ok(usage_by_validator)
}
fn inrou_replica_assignment_has_active_capability(
    world: &impl WorldReadOnly,
    bundle: &SoraDeploymentBundleV1,
    assignment: &SoraInrouReplicaPlacementV1,
    now_ms: u64,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> bool {
    if !assignment.host_availability.is_available()
        || !bundle.service.placement_targets.iter().any(|target| {
            target.validator_account_id == assignment.validator_account_id
                && target.peer_id == assignment.peer_id
        })
    {
        return false;
    }
    let Some(capability) = world
        .soracloud_inrou_host_capabilities()
        .get(&assignment.validator_account_id)
    else {
        return false;
    };
    let Some(required_cpu_millis) = bundle.container.resources.checked_inrou_host_cpu_millis()
    else {
        return false;
    };
    let Some(required_memory_bytes) = bundle.container.resources.checked_inrou_host_memory_bytes()
    else {
        return false;
    };
    let Some(required_storage_bytes) = inrou_bundle_per_replica_storage_bytes(bundle) else {
        return false;
    };
    capability.validate().is_ok()
        && capability.validator_account_id == assignment.validator_account_id
        && capability.peer_id == assignment.peer_id
        && capability.can_host_replicas_at(now_ms)
        && capability
            .supported_guest_isas
            .contains(&assignment.selected_guest_isa)
        && bundle.container.inrou.as_ref().is_some_and(|inrou| {
            inrou
                .guest_images
                .get(&assignment.selected_guest_isa)
                .is_some_and(|image| image.published_artifact == capability.trusted_guest_artifact)
        })
        && u64::from(capability.max_cpu_millis) >= required_cpu_millis
        && capability.max_memory_bytes >= required_memory_bytes
        && capability.max_storage_bytes >= required_storage_bytes
        && soracloud_validator_has_active_peer_binding(
            world,
            &assignment.validator_account_id,
            &assignment.peer_id,
            current_height,
            lane_is_active_for_authority,
        )
}
/// Resolve all exact active replica assignments for an active Inrou placement record.
///
/// This is also the validator ledger-mutation authorization boundary. Returned assignments must
/// be marked available, remain on the admitted validator/peer allowlist, and fit the host's exact
/// aggregate physical reservation including fixed VMM overhead.
pub fn resolve_active_inrou_replica_assignments(
    world: &impl WorldReadOnly,
    service_name: &str,
    service_version: &str,
    now_ms: u64,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> Result<Vec<SoraInrouReplicaPlacementV1>, String> {
    let Some(record) = resolve_active_inrou_placement_record(
        world,
        service_name,
        service_version,
        current_height,
    )?
    else {
        return Ok(Vec::new());
    };
    let Some(bundle) = world
        .soracloud_service_revisions()
        .get(&(service_name.to_owned(), service_version.to_owned()))
    else {
        return Err(format!(
            "active Inrou placement for service `{service_name}` revision `{service_version}` lost its admitted deployment bundle"
        ));
    };
    let reserved_usage = active_inrou_reservation_usage_by_validator(world, current_height)?;
    Ok(record
        .placements
        .into_iter()
        .filter(|assignment| {
            let aggregate_capacity_matches = world
                .soracloud_inrou_host_capabilities()
                .get(&assignment.validator_account_id)
                .zip(reserved_usage.get(&assignment.validator_account_id))
                .is_some_and(|(capability, usage)| {
                    usage.hosted_replicas <= u32::from(capability.max_hosted_replica_capacity)
                        && usage.cpu_millis <= u64::from(capability.max_cpu_millis)
                        && usage.memory_bytes <= capability.max_memory_bytes
                        && usage.storage_bytes <= capability.max_storage_bytes
                });
            inrou_replica_assignment_has_active_capability(
                world,
                bundle,
                assignment,
                now_ms,
                current_height,
                &lane_is_active_for_authority,
            ) && aggregate_capacity_matches
        })
        .collect())
}
/// Resolve one exact active replica-slot assignment for an active Inrou placement record.
pub fn resolve_active_inrou_replica_assignment(
    world: &impl WorldReadOnly,
    service_name: &str,
    service_version: &str,
    replica_slot: u16,
    now_ms: u64,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(LaneId) -> bool,
) -> Result<Option<SoraInrouReplicaPlacementV1>, String> {
    Ok(resolve_active_inrou_replica_assignments(
        world,
        service_name,
        service_version,
        now_ms,
        current_height,
        lane_is_active_for_authority,
    )?
    .into_iter()
    .find(|assignment| assignment.replica_slot == replica_slot))
}
/// Distinguishes the local runtime role of a materialized service revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(tag = "revision_role", content = "value")]
#[norito(deny_unknown_fields)]
pub enum SoracloudRuntimeRevisionRole {
    /// The currently active deployment revision.
    Active,
    /// A canary candidate revision that must be materialized during rollout.
    CanaryCandidate,
}
/// Node-local mailbox materialization metadata for a handler.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeMailboxPlan {
    /// Stable handler identifier.
    pub handler_name: String,
    /// Stable logical queue name.
    pub queue_name: String,
    /// Maximum retained pending messages.
    pub max_pending_messages: u32,
    /// Maximum message size.
    pub max_message_bytes: u64,
    /// Retention bound in consensus blocks.
    pub retention_blocks: u32,
}
/// Node-local hydration/materialization metadata for a referenced artifact.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeArtifactPlan {
    /// Artifact class.
    pub kind: SoraArtifactKindV1,
    /// Content-addressed artifact digest.
    pub artifact_hash: String,
    /// Logical artifact path inside the service revision.
    pub artifact_path: String,
    /// Optional consuming handler.
    #[norito(required)]
    pub handler_name: Option<String>,
    /// Local cache path where the runtime manager expects the artifact.
    pub local_cache_path: String,
    /// Whether the artifact is already present in the node-local cache.
    pub available_locally: bool,
}
/// Node-local materialization plan for one active service revision.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeServicePlan {
    /// Service identifier.
    pub service_name: String,
    /// Materialized revision/version.
    pub service_version: String,
    /// Whether this revision is the active one or a rollout candidate.
    pub role: SoracloudRuntimeRevisionRole,
    /// Requested traffic percentage for this revision.
    pub traffic_percent: u8,
    /// Runtime target.
    pub runtime: SoraContainerRuntimeV1,
    /// Execution plane selected for this revision.
    pub execution_plane: SoraServiceExecutionPlaneV1,
    /// Bundle digest.
    pub bundle_hash: String,
    /// Bundle path declared by the container manifest.
    pub bundle_path: String,
    /// Entrypoint declared by the container manifest.
    pub entrypoint: String,
    /// Explicit Inrou VM metadata projected for hosted HTTP microVMs.
    #[norito(required)]
    pub inrou: Option<SoracloudRuntimeInrouPlan>,
    /// Node-local cache path for the executable bundle.
    pub bundle_cache_path: String,
    /// Whether the bundle is already present locally.
    pub bundle_available_locally: bool,
    /// Current deployment process generation when known for this revision.
    #[norito(required)]
    pub process_generation: Option<u64>,
    /// Desired replica count declared by the admitted service manifest.
    pub desired_replica_count: u16,
    /// Replica slots this runtime host is projecting locally for the revision.
    pub local_replica_slots: Vec<u16>,
    /// Replica-local runtime topology currently projected on this host for the revision.
    pub local_replicas: Vec<SoracloudRuntimeReplicaPlan>,
    /// Current runtime health projection.
    pub health_status: SoraServiceHealthStatusV1,
    /// Current runtime load projection.
    pub load_factor_bps: u16,
    /// Pending mailbox messages currently stored in authoritative state.
    pub authoritative_pending_mailbox_messages: u32,
    /// Active rollout handle when this revision is part of a canary rollout.
    #[norito(required)]
    pub rollout_handle: Option<String>,
    /// Monotonic generation of committed service config updates.
    pub config_generation: u64,
    /// Monotonic generation of committed service secret updates.
    pub secret_generation: u64,
    /// Hosted-service quota class when the service uses the HTTP plane.
    #[norito(required)]
    pub quota_class: Option<String>,
    /// Effective hosted-service lease status at the observed block height.
    #[norito(required)]
    pub service_lease_status: Option<SoraServiceLeaseStatusV1>,
    /// Canonical block height when hosted-service routing/materialization expires.
    #[norito(required)]
    pub lease_expires_height: Option<u64>,
    /// Remaining prepaid runtime balance estimated at snapshot build time.
    #[norito(required)]
    pub remaining_runtime_balance: Option<Quantity>,
    /// Number of committed service config entries projected into runtime materialization.
    pub config_entry_count: u32,
    /// Number of committed service secret entries projected into runtime materialization.
    pub secret_entry_count: u32,
    /// Explicit config exports declared by the admitted container manifest.
    pub config_exports: Vec<SoraConfigExportV1>,
    /// Whether ordinary handlers on this revision can read authoritative config payloads.
    pub supports_host_read_config: bool,
    /// Whether ordinary handlers on this revision can read authoritative secret envelopes.
    pub supports_host_read_secret_envelope: bool,
    /// Local directory where the revision plan is materialized.
    pub materialization_dir: String,
    /// Local directory containing canonical JSON config files for this revision.
    pub config_materialization_dir: String,
    /// Effective launch environment after applying explicit config env exports.
    pub effective_env: BTreeMap<String, String>,
    /// Local file containing the effective launch environment projection.
    pub effective_env_materialization_path: String,
    /// Local directory containing explicit config file exports for this revision.
    pub config_exports_materialization_dir: String,
    /// Local directory containing committed secret-envelope files for this revision.
    pub secret_envelopes_materialization_dir: String,
    /// Lease-backed mutable storage materialized for this revision.
    pub lease_volumes: Vec<SoracloudRuntimeLeaseVolumePlan>,
    /// Declared replicated handler mailboxes.
    pub mailboxes: Vec<SoracloudRuntimeMailboxPlan>,
    /// Referenced artifacts that still need local hydration.
    pub artifacts: Vec<SoracloudRuntimeArtifactPlan>,
}
/// Node-local materialization plan for one Inrou microVM guest.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeInrouPlan {
    /// Guest ISA profile selected locally for this replica.
    pub selected_guest_isa: SoraInrouGuestIsaV1,
    /// Kernel image path for the selected guest ISA inside the hydrated Soracloud bundle.
    pub kernel_image_path: String,
    /// Immutable base root filesystem image path for the selected guest ISA.
    pub rootfs_image_path: String,
    /// Optional initrd image path for the selected guest ISA.
    #[norito(required)]
    pub initrd_image_path: Option<String>,
    /// Logical volume identifier used as the authoritative mutable root disk.
    pub root_volume_name: String,
}
/// Node-local materialization plan for one lease-backed service volume.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeLeaseVolumePlan {
    /// Logical volume identifier.
    pub volume_name: String,
    /// Soracloud lease-backed volume kind.
    pub kind: SoraLeaseVolumeKindV1,
    /// Requested Sorafs storage class.
    pub storage_class: StorageClass,
    /// Admission-validated exact guest mount path for this volume.
    pub mount_path: String,
    /// Maximum logical bytes retained for this volume.
    pub max_total_bytes: u64,
    /// Canonical block height that identifies the active economic lease incarnation.
    pub lease_started_height: u64,
    /// Canonical block height when the authoritative volume lease expires.
    pub lease_expires_height: u64,
    /// Monotonic generation of the authoritative lease binding.
    pub authoritative_generation: u64,
    /// Node-local materialization directory used by the current host.
    ///
    /// Every lease disk uses a per-revision/per-replica namespace. Inrou V1 has no shared mutable
    /// filesystem or multi-attach volume path.
    pub local_materialization_dir: String,
}
/// Node-local runtime topology projected for one hosted-HTTP replica slot.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeReplicaPlan {
    /// One-based replica slot within the revision.
    pub replica_slot: u16,
    /// Canonical block height identifying this economic lease incarnation.
    pub lease_started_height: u64,
    /// Transaction-bound incarnation of this slot's host assignment within the active service lease.
    pub placement_incarnation: String,
    /// Whether the sticky assigned host remains eligible to serve this lease incarnation.
    pub host_availability: SoraInrouReplicaHostAvailabilityV1,
    /// Canonical validator account assigned to this replica incarnation.
    pub validator_account_id: String,
    /// Canonical peer identifier assigned to this replica incarnation.
    pub peer_id: String,
    /// Local directory where this replica slot is materialized.
    pub materialization_dir: String,
    /// Current runtime health projection for this replica slot.
    pub health_status: SoraServiceHealthStatusV1,
    /// Loopback listener currently exposed by this replica, when healthy.
    #[norito(required)]
    pub listen_base_url: Option<String>,
    /// Local process identifier when the replica is running.
    #[norito(required)]
    pub pid: Option<u32>,
    /// Human-readable startup or healthcheck failure detail for the replica, when present.
    #[norito(required)]
    pub last_error: Option<String>,
}
/// Node-local materialization plan for an active agent apartment.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeApartmentPlan {
    /// Apartment identifier.
    pub apartment_name: String,
    /// Canonical manifest hash.
    pub manifest_hash: String,
    /// Current runtime status.
    pub status: SoraAgentRuntimeStatusV1,
    /// Current process generation.
    pub process_generation: u64,
    /// Consensus height when the lease expires.
    pub lease_expires_height: u64,
    /// Audit sequence of the most recent observed activity.
    pub last_active_sequence: u64,
    /// Node-local directory where the apartment plan is materialized.
    pub materialization_dir: String,
    /// Number of pending wallet approvals.
    pub pending_wallet_request_count: u32,
    /// Number of queued mailbox messages.
    pub pending_mailbox_message_count: u32,
    /// Remaining autonomy budget.
    pub autonomy_budget_remaining_units: u64,
    /// Number of explicitly approved autonomy artifacts.
    pub approved_artifact_count: u32,
    /// Number of recorded autonomy runs.
    pub autonomy_run_count: u32,
    /// Number of revoked policy capabilities.
    pub revoked_policy_capability_count: u32,
}
/// Schema version for persisted hosted-HTTP runtime state snapshots.
pub const SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1: u16 = 1;
/// Canonical runtime-state filename written beside hosted-HTTP service materializations.
pub const SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_FILE_V1: &str = "hosted_http_runtime.json";
/// Node-local state projected for one hosted-HTTP replica materialized by the local runtime manager.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudHostedHttpReplicaRuntimeStateV1 {
    /// One-based replica slot for the revision-local materialization.
    pub replica_slot: u16,
    /// Exact placement incarnation observed for this local runtime state.
    pub placement_incarnation: String,
    /// Projected health state of the replica runtime.
    pub health_status: SoraServiceHealthStatusV1,
    /// Base URL for the loopback listener exposed by the replica process, when present.
    #[norito(required)]
    pub listen_base_url: Option<String>,
    /// Child process identifier while the replica is running.
    #[norito(required)]
    pub pid: Option<u32>,
    /// Human-readable startup or healthcheck failure detail for this replica, when present.
    #[norito(required)]
    pub last_error: Option<String>,
    /// Timestamp when the replica state was last refreshed.
    pub updated_at_ms: u64,
}
/// Node-local state projected for a supervised hosted-HTTP Soracloud service revision.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudHostedHttpRuntimeStateV1 {
    /// Schema version for this runtime-state document.
    pub schema_version: u16,
    /// Service identifier.
    pub service_name: String,
    /// Materialized revision/version.
    pub service_version: String,
    /// Process generation currently hosted by the local runtime-manager.
    pub process_generation: u64,
    /// Projected health state of the child process.
    pub health_status: SoraServiceHealthStatusV1,
    /// Base URL for the loopback listener exposed by the child process.
    #[norito(required)]
    pub listen_base_url: Option<String>,
    /// Child process identifier while the process is running.
    #[norito(required)]
    pub pid: Option<u32>,
    /// Total authoritative egress bytes accounted by the local supervisor.
    pub accounted_egress_bytes: u64,
    /// Healthy and unhealthy replica listeners currently materialized on this host for the revision.
    pub replicas: Vec<SoracloudHostedHttpReplicaRuntimeStateV1>,
    /// Human-readable startup or healthcheck failure detail, when present.
    #[norito(required)]
    pub last_error: Option<String>,
    /// Timestamp when the state file was last refreshed.
    pub updated_at_ms: u64,
}
/// Schema version for [`SoracloudRuntimeSnapshot`].
pub const SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1: u16 = 1;
/// Persisted snapshot of node-local Soracloud runtime materialization state.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudRuntimeSnapshot {
    /// Schema version for the local runtime snapshot format.
    pub schema_version: u16,
    /// Height of the authoritative state view used to build this snapshot.
    pub observed_height: u64,
    /// Latest committed block hash at snapshot time, when present.
    #[norito(required)]
    pub observed_block_hash: Option<String>,
    /// Peer identity of the runtime host that produced this snapshot, when known.
    #[norito(required)]
    pub local_peer_id: Option<String>,
    /// Materialized active service revisions grouped by service name then version.
    pub services: BTreeMap<String, BTreeMap<String, SoracloudRuntimeServicePlan>>,
    /// Materialized active agent apartments keyed by apartment name.
    pub apartments: BTreeMap<String, SoracloudRuntimeApartmentPlan>,
}
impl Default for SoracloudRuntimeSnapshot {
    fn default() -> Self {
        Self {
            schema_version: SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1,
            observed_height: 0,
            observed_block_hash: None,
            local_peer_id: None,
            services: BTreeMap::new(),
            apartments: BTreeMap::new(),
        }
    }
}
/// Read-only Soracloud runtime handle exposed to Torii and other consumers.
pub trait SoracloudRuntimeReadHandle: Send + Sync {
    /// Return the latest node-local runtime materialization snapshot.
    fn snapshot(&self) -> SoracloudRuntimeSnapshot;
    /// Return the local runtime-manager state directory.
    fn state_dir(&self) -> PathBuf;
    /// Return the local peer id, when the runtime knows its host identity.
    fn local_peer_id(&self) -> Option<String> {
        None
    }
}
/// Coarse execution failure category for embedded Soracloud runtime requests.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudRuntimeExecutionErrorKind")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SoracloudRuntimeExecutionErrorKind {
    /// The runtime cannot execute the request in the current node process.
    Unavailable,
    /// Authoritative state makes this exact request permanently unrecoverable.
    Conflict,
    /// The request is structurally invalid for the configured runtime surface.
    InvalidRequest,
    /// The runtime hit an internal execution failure.
    Internal,
}
/// Structured error returned by the shared Soracloud runtime execution trait.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudRuntimeExecutionError")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SoracloudRuntimeExecutionError {
    /// High-level error category.
    pub kind: SoracloudRuntimeExecutionErrorKind,
    /// Human-readable detail preserved for logging and deterministic receipts.
    pub message: String,
}
impl SoracloudRuntimeExecutionError {
    /// Construct a new structured runtime execution error.
    #[must_use]
    pub fn new(kind: SoracloudRuntimeExecutionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for SoracloudRuntimeExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category = match self.kind {
            SoracloudRuntimeExecutionErrorKind::Unavailable => "unavailable",
            SoracloudRuntimeExecutionErrorKind::Conflict => "conflict",
            SoracloudRuntimeExecutionErrorKind::InvalidRequest => "invalid request",
            SoracloudRuntimeExecutionErrorKind::Internal => "internal",
        };
        write!(
            formatter,
            "Soracloud runtime {category} error: {}",
            self.message
        )
    }
}
impl std::error::Error for SoracloudRuntimeExecutionError {}
/// Deterministic local read class for the Soracloud fast path.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudLocalReadKind")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SoracloudLocalReadKind {
    /// Static asset read bound to committed artifacts.
    Asset,
    /// Read-only query bound to the committed state snapshot.
    Query,
}
/// Shared request envelope for deterministic local Soracloud reads.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudLocalReadRequest")]
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct SoracloudLocalReadRequest {
    /// Authoritative height used for the local read snapshot.
    pub observed_height: u64,
    /// Latest committed block hash visible to the caller.
    pub observed_block_hash: Option<Hash>,
    /// Service targeted by the read.
    pub service_name: String,
    /// Active service version used for the read.
    pub service_version: String,
    /// Handler servicing the request.
    pub handler_name: String,
    /// Handler class for the request.
    pub handler_class: SoracloudLocalReadKind,
    /// HTTP method or logical read method used to invoke the handler.
    pub request_method: String,
    /// Full request path as received by Torii.
    pub request_path: String,
    /// Request path relative to the matched handler route.
    pub handler_path: String,
    /// Optional raw query string without the leading `?`.
    pub request_query: Option<String>,
    /// Canonicalized end-to-end application headers made visible after Torii removes platform and
    /// hop-by-hop metadata.
    pub request_headers: BTreeMap<String, String>,
    /// Opaque request payload bytes supplied to the handler.
    pub request_body: Vec<u8>,
    /// Deterministic commitment over the request envelope.
    pub request_commitment: Hash,
}
impl std::fmt::Debug for SoracloudLocalReadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoracloudLocalReadRequest")
            .field("observed_height", &self.observed_height)
            .field(
                "has_observed_block_hash",
                &self.observed_block_hash.is_some(),
            )
            .field("service_name", &self.service_name)
            .field("service_version", &self.service_version)
            .field("handler_name", &self.handler_name)
            .field("handler_class", &self.handler_class)
            .field("request_method", &self.request_method)
            .field("request_path_len", &self.request_path.len())
            .field("handler_path_len", &self.handler_path.len())
            .field("has_request_query", &self.request_query.is_some())
            .field("request_header_count", &self.request_headers.len())
            .field("request_body_len", &self.request_body.len())
            .field("request_commitment", &self.request_commitment)
            .finish_non_exhaustive()
    }
}
/// Committed artifact/state binding attached to a certified local read response.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudLocalReadBinding")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct SoracloudLocalReadBinding {
    /// Binding name when the response is derived from authoritative service state.
    #[norito(required)]
    pub binding_name: Option<String>,
    /// State key when the response is derived from a specific state entry.
    #[norito(required)]
    pub state_key: Option<String>,
    /// Commitment for the bound state entry, when applicable.
    #[norito(required)]
    pub payload_commitment: Option<Hash>,
    /// Bound artifact digest when the response is served from hydrated local content.
    #[norito(required)]
    pub artifact_hash: Option<Hash>,
}
/// Shared response envelope for deterministic local Soracloud reads.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::soracloud_runtime::SoracloudLocalReadResponse")]
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct SoracloudLocalReadResponse {
    /// Raw response bytes emitted by the runtime.
    pub response_bytes: Vec<u8>,
    /// MIME type of the response payload, when known.
    pub content_type: Option<String>,
    /// Optional content encoding metadata for the response.
    pub content_encoding: Option<String>,
    /// Optional cache-control metadata for the response.
    pub cache_control: Option<String>,
    /// Committed bindings that certify the response payload.
    pub bindings: Vec<SoracloudLocalReadBinding>,
    /// Commitment over the response envelope.
    pub result_commitment: Hash,
    /// Certification mode selected for this read.
    pub certified_by: SoraCertifiedResponsePolicyV1,
    /// Optional receipt emitted for audit-style certifications.
    pub runtime_receipt: Option<SoraRuntimeReceiptV1>,
}
impl std::fmt::Debug for SoracloudLocalReadResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoracloudLocalReadResponse")
            .field("response_bytes_len", &self.response_bytes.len())
            .field("has_content_type", &self.content_type.is_some())
            .field("has_content_encoding", &self.content_encoding.is_some())
            .field("has_cache_control", &self.cache_control.is_some())
            .field("binding_count", &self.bindings.len())
            .field("result_commitment", &self.result_commitment)
            .field("certified_by", &self.certified_by)
            .field("has_runtime_receipt", &self.runtime_receipt.is_some())
            .finish_non_exhaustive()
    }
}
/// Deterministic state mutation produced by ordered Soracloud execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoracloudDeterministicStateMutation {
    /// Binding mutated by the runtime.
    pub binding_name: String,
    /// Canonical key scoped under the binding prefix.
    pub state_key: String,
    /// Mutation mode to apply.
    pub operation: SoraStateMutationOperationV1,
    /// Encryption contract enforced by the binding.
    pub encryption: SoraStateEncryptionV1,
    /// Declared payload size when the mutation upserts content.
    pub payload_bytes: Option<u64>,
    /// Full payload bytes when the mutation upserts content.
    pub payload: Option<Vec<u8>>,
    /// Deterministic commitment over the opaque payload.
    pub payload_commitment: Option<Hash>,
}
/// Shared request envelope for ordered Soracloud mailbox execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoracloudOrderedMailboxExecutionRequest {
    /// Authoritative height pinned for the execution.
    pub observed_height: u64,
    /// Latest committed block hash visible to the executor.
    pub observed_block_hash: Option<Hash>,
    /// Authoritative Soracloud sequence observed by the VM as read-only execution context.
    pub observed_sequence: u64,
    /// Current deployment state for the target service.
    pub deployment: SoraServiceDeploymentStateV1,
    /// Admitted active bundle for the target service revision.
    pub bundle: SoraDeploymentBundleV1,
    /// Resolved target handler when it exists in the active bundle.
    pub handler: Option<SoraServiceHandlerV1>,
    /// Mailbox message being delivered through replicated progression.
    pub mailbox_message: SoraServiceMailboxMessageV1,
    /// Latest runtime state observed for the target service.
    pub runtime_state: Option<SoraServiceRuntimeStateV1>,
    /// Outstanding mailbox message count before this execution is applied.
    pub authoritative_pending_mailbox_messages: u32,
}
/// Deterministic result of ordered Soracloud mailbox execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoracloudOrderedMailboxExecutionResult {
    /// Deterministic state mutations to apply to authoritative service state.
    pub state_mutations: Vec<SoracloudDeterministicStateMutation>,
    /// Cross-service messages emitted by the execution.
    pub outbound_mailbox_messages: Vec<SoraServiceMailboxMessageV1>,
    /// Optional response payload returned by the executed handler.
    pub response_bytes: Vec<u8>,
    /// MIME type associated with `response_bytes`, when known.
    pub content_type: Option<String>,
    /// Runtime-state observation to persist after execution.
    pub runtime_state: Option<SoraServiceRuntimeStateV1>,
    /// Deterministic runtime receipt for the execution.
    pub runtime_receipt: SoraRuntimeReceiptV1,
}
/// Shared request envelope for deterministic apartment execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoracloudApartmentExecutionRequest {
    /// Authoritative height pinned for the apartment execution.
    pub observed_height: u64,
    /// Latest committed block hash visible to the runtime.
    pub observed_block_hash: Option<Hash>,
    /// Apartment targeted by the runtime.
    pub apartment_name: String,
    /// Expected apartment process generation.
    pub process_generation: u64,
    /// Logical apartment operation to execute.
    pub operation: String,
    /// Deterministic commitment over the apartment request.
    pub request_commitment: Hash,
}
/// Shared result for deterministic apartment execution.
#[allow(missing_copy_implementations)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoracloudApartmentExecutionResult {
    /// Latest apartment status reported by the runtime.
    pub status: SoraAgentRuntimeStatusV1,
    /// Optional committed checkpoint hash materialized by the operation.
    pub checkpoint_artifact_hash: Option<Hash>,
    /// Optional committed journal hash materialized by the operation.
    pub journal_artifact_hash: Option<Hash>,
    /// Deterministic commitment over the apartment result.
    pub result_commitment: Hash,
}
/// Shared execution interface for the embedded Soracloud runtime.
pub trait SoracloudRuntime: SoracloudRuntimeReadHandle {
    /// Execute a deterministic local read against the committed runtime snapshot.
    fn execute_local_read(
        &self,
        request: SoracloudLocalReadRequest,
    ) -> Result<SoracloudLocalReadResponse, SoracloudRuntimeExecutionError>;
    /// Execute an ordered mailbox handler against a pinned committed snapshot.
    ///
    /// This is a node-local proposal step. Production consensus persists the returned effects only
    /// through an explicit `ApplySoracloudOrderedMailboxResult` instruction that revalidates the
    /// snapshot preconditions and executor identity.
    fn execute_ordered_mailbox(
        &self,
        request: SoracloudOrderedMailboxExecutionRequest,
    ) -> Result<SoracloudOrderedMailboxExecutionResult, SoracloudRuntimeExecutionError>;
    /// Execute deterministic apartment work owned by the embedded runtime manager.
    fn execute_apartment(
        &self,
        request: SoracloudApartmentExecutionRequest,
    ) -> Result<SoracloudApartmentExecutionResult, SoracloudRuntimeExecutionError>;
}
/// Shared node-local Soracloud runtime trait object.
///
/// Production replicated execution never invokes this handle implicitly.
pub type SharedSoracloudRuntime = Arc<dyn SoracloudRuntime>;
impl SoracloudLocalReadKind {
    /// Return the Soracloud handler class represented by this local read kind.
    #[must_use]
    pub fn handler_class(self) -> SoraServiceHandlerClassV1 {
        match self {
            Self::Asset => SoraServiceHandlerClassV1::Asset,
            Self::Query => SoraServiceHandlerClassV1::Query,
        }
    }
}
impl SoracloudRuntimeExecutionErrorKind {
    /// Stable label used when hashing synthetic failure receipts.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::InvalidRequest => "invalid_request",
            Self::Internal => "internal",
        }
    }
}
#[cfg(test)]
#[test]
fn soracloud_runtime_conflict_has_stable_label() {
    assert_eq!(
        SoracloudRuntimeExecutionErrorKind::Conflict.label(),
        "conflict"
    );
}
impl SoracloudDeterministicStateMutation {}
impl From<SoracloudLocalReadKind> for SoraServiceHandlerClassV1 {
    fn from(value: SoracloudLocalReadKind) -> Self {
        value.handler_class()
    }
}
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
/// Bounded runtime write-back instruction set used for internal Soracloud integration points.
pub enum SoracloudRuntimeInstruction {
    /// Persist an updated runtime-state snapshot.
    SetRuntimeState(iroha_data_model::isi::soracloud::SetSoracloudRuntimeState),
    /// Persist an outbound cross-service mailbox message.
    RecordMailboxMessage(iroha_data_model::isi::soracloud::RecordSoracloudMailboxMessage),
    /// Persist an authoritative runtime receipt.
    RecordRuntimeReceipt(iroha_data_model::isi::soracloud::RecordSoracloudRuntimeReceipt),
}
impl SoracloudRuntimeInstruction {
    /// Convert the bounded runtime write-back into a regular instruction box.
    #[must_use]
    pub fn into_instruction_box(self) -> InstructionBox {
        match self {
            Self::SetRuntimeState(isi) => InstructionBox::from(isi),
            Self::RecordMailboxMessage(isi) => InstructionBox::from(isi),
            Self::RecordRuntimeReceipt(isi) => InstructionBox::from(isi),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::World;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        block::BlockHeader,
        consensus::{
            FinalizedGlobalThresholdBeaconPulseV1, GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            GlobalThresholdBeaconChainAnchorV1,
        },
        nexus::staking::PublicLaneValidatorRecord,
        soracloud::{
            SORA_APP_INFRA_AUDIT_EVENT_VERSION_V1, SORA_DEPLOYMENT_BUNDLE_VERSION_V1,
            SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1, SORA_INROU_MANIFEST_VERSION_V1,
            SORA_INROU_SERVICE_PLACEMENT_RECORD_VERSION_V1,
            SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1, SORA_SERVICE_LEASE_STATE_VERSION_V1,
            SORA_SERVICE_LEASE_VOLUME_STATE_VERSION_V1, SoraAppInfraActionV1,
            SoraAppInfraAuditEventV1, SoraDeploymentBundleV1, SoraInrouGuestImageV1,
            SoraInrouHostCapabilityRecordV1, SoraInrouManifestV1, SoraInrouPlacementTargetV1,
            SoraLeaseVolumeBindingV1, SoraNetworkPolicyV1, SoraPublishedInrouGuestImageArtifactV1,
            SoraServiceDeploymentStateV1, SoraServiceLeaseClockV1, SoraServiceLeaseStateV1,
            SoraServiceLeaseVolumeStateV1, SoraServiceMailboxMessageV1,
            derive_soracloud_mailbox_message_id_v1,
        },
        sorafs::pin_registry::StorageClass,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::peer::PeerId;
    use std::num::{NonZeroU16, NonZeroU64};
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("Soracloud runtime fixture key generation should succeed")
    }
    fn checked_account_id() -> AccountId {
        AccountId::new(checked_keypair().public_key().clone())
    }
    fn checked_peer_id() -> PeerId {
        PeerId::from(checked_keypair().public_key().clone())
    }
    fn seed_ordered_mailbox_validator_world() -> World {
        let mut world = World::new();
        let validator = checked_account_id();
        let peer_id = checked_peer_id();
        world.public_lane_validators_mut_for_testing().insert(
            (LaneId::SINGLE, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id,
                stake_account: validator,
                total_stake: Quantity::from(1_000_u32),
                self_stake: Quantity::from(1_000_u32),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        let pulse = FinalizedGlobalThresholdBeaconPulseV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: iroha_data_model::NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x11; 32])),
            ),
            session_id: [0x22; 32],
            roster_hash: [0x33; 32],
            transcript_hash: [0x44; 32],
            context: crate::beacon::pulse_context_fixture_v1(),
            height: 4,
            round: 0,
            finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
                height: 3,
                block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                    [0x55; 32],
                )),
            },
            signature: [0x66; 48],
            seed: [0x77; 32],
            pulse_id: [0x88; 32],
        };
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
    }
    fn sample_inrou_resolver_manifest() -> SoraInrouManifestV1 {
        SoraInrouManifestV1 {
            schema_version: SORA_INROU_MANIFEST_VERSION_V1,
            guest_images: BTreeMap::from([(
                SoraInrouGuestIsaV1::X8664,
                SoraInrouGuestImageV1 {
                    kernel_image_path: "/inrou/x86_64/vmlinux".to_owned(),
                    rootfs_image_path: "/inrou/x86_64/rootfs.ext4".to_owned(),
                    initrd_image_path: None,
                    published_artifact: SoraPublishedInrouGuestImageArtifactV1 {
                        manifest_digest_hex: "31".repeat(32),
                        content_cid: "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                            .to_owned(),
                    },
                },
            )]),
        }
    }
    fn sample_inrou_resolver_bundle(
        validator_account_id: AccountId,
        peer_id: String,
    ) -> SoraDeploymentBundleV1 {
        let mut bundle: SoraDeploymentBundleV1 = norito::json::from_str(include_str!(
            "../../../fixtures/soracloud/sora_deployment_bundle_v1.json"
        ))
        .expect("canonical Soracloud deployment fixture");
        bundle.schema_version = SORA_DEPLOYMENT_BUNDLE_VERSION_V1;
        bundle.container.runtime = SoraContainerRuntimeV1::Inrou;
        bundle.container.entrypoint = "/app/bin/service".to_owned();
        bundle.container.inrou = Some(sample_inrou_resolver_manifest());
        bundle.container.capabilities.network = SoraNetworkPolicyV1::Isolated;
        bundle.service.execution_plane = SoraServiceExecutionPlaneV1::HttpService;
        bundle.service.replicas = NonZeroU16::new(1).expect("nonzero replica count");
        bundle.service.placement_targets = BTreeSet::from([SoraInrouPlacementTargetV1 {
            validator_account_id,
            peer_id,
        }]);
        bundle.service.rollout.canary_percent = 0;
        bundle.service.state_bindings.clear();
        bundle.service.handlers.clear();
        bundle.service.artifacts.clear();
        bundle.service.lease_volumes = vec![
            SoraLeaseVolumeBindingV1 {
                volume_name: "root_disk".parse().expect("valid root volume name"),
                kind: SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
                storage_class: StorageClass::Warm,
                mount_path: "/".to_owned(),
                max_total_bytes: NonZeroU64::new(8 * 1024 * 1024 * 1024)
                    .expect("nonzero root volume size"),
            },
            SoraLeaseVolumeBindingV1 {
                volume_name: "service_data".parse().expect("valid data volume name"),
                kind: SoraLeaseVolumeKindV1::ServiceLeaseVolume,
                storage_class: StorageClass::Warm,
                mount_path: "/var/lib/soracloud/volumes/service_data".to_owned(),
                max_total_bytes: NonZeroU64::new(1024 * 1024).expect("nonzero data volume size"),
            },
        ];
        bundle.service.container.manifest_hash = bundle.container_manifest_hash();
        bundle
            .validate_for_admission()
            .expect("canonical Inrou resolver bundle");
        bundle
    }
    fn seed_active_inrou_resolver_world() -> (World, String, String, AccountId) {
        let mut world = seed_ordered_mailbox_validator_world();
        let (validator_account_id, peer_id) = world
            .view()
            .public_lane_validators()
            .iter()
            .next()
            .map(|(key, record)| (key.1.clone(), record.peer_id.to_string()))
            .expect("active validator fixture");
        let bundle = sample_inrou_resolver_bundle(validator_account_id.clone(), peer_id.clone());
        let service_name = bundle.service.service_name.as_ref().to_owned();
        let service_version = bundle.service.service_version.clone();
        let economics = bundle.service.economics.clone();
        let lease_started_height = 1;
        let lease_expires_height = 100;
        let service_lease = SoraServiceLeaseStateV1 {
            schema_version: SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: SoraServiceLeaseStatusV1::Active,
            quota_class: economics.quota_class,
            replica_count: bundle.service.replicas,
            deployment_deposit: economics.deployment_deposit,
            prepaid_runtime_balance: economics.prepaid_runtime_balance,
            runtime_price_per_block: economics.runtime_price_per_block,
            storage_price_per_gib_block: economics.storage_price_per_gib_block,
            egress_price_per_mib: economics.egress_price_per_mib,
            lease_started_height,
            lease_expires_height,
            reporting_epoch: 1,
            settled_egress_bytes: 0,
            egress_reporter_checkpoints: Vec::new(),
            accounted_egress_bytes: 0,
            last_status_reason: None,
        };
        let lease_volume_states = bundle
            .service
            .lease_volumes
            .iter()
            .map(|volume| SoraServiceLeaseVolumeStateV1 {
                schema_version: SORA_SERVICE_LEASE_VOLUME_STATE_VERSION_V1,
                economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
                volume_name: volume.volume_name.clone(),
                kind: volume.kind,
                storage_class: volume.storage_class,
                mount_path: volume.mount_path.clone(),
                max_total_bytes: volume.max_total_bytes.get(),
                lease_started_height,
                lease_expires_height,
                authoritative_generation: 1,
            })
            .collect();
        let deployment = SoraServiceDeploymentStateV1 {
            schema_version: SORA_SERVICE_DEPLOYMENT_STATE_VERSION_V1,
            service_name: bundle.service.service_name.clone(),
            current_service_version: service_version.clone(),
            current_service_manifest_hash: bundle.service_manifest_hash(),
            current_container_manifest_hash: bundle.container_manifest_hash(),
            revision_count: 1,
            process_generation: 1,
            process_started_sequence: 1,
            config_generation: 0,
            secret_generation: 0,
            service_configs: BTreeMap::new(),
            service_secrets: BTreeMap::new(),
            fhe_policy_records: BTreeMap::new(),
            active_rollout: None,
            last_rollout: None,
            service_lease: Some(service_lease),
            lease_volume_states,
        };
        deployment
            .validate_against_active_bundle(&bundle)
            .expect("canonical active Inrou deployment");
        let placement = SoraInrouReplicaPlacementV1 {
            replica_slot: 1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            lease_started_height,
            placement_incarnation: Hash::new(b"runtime resolver placement"),
            host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
            validator_account_id: validator_account_id.clone(),
            peer_id: peer_id.clone(),
            selected_guest_isa: SoraInrouGuestIsaV1::X8664,
        };
        let placement_record = SoraInrouServicePlacementRecordV1 {
            schema_version: SORA_INROU_SERVICE_PLACEMENT_RECORD_VERSION_V1,
            service_name: bundle.service.service_name.clone(),
            service_version: service_version.clone(),
            desired_replica_count: bundle.service.replicas.get(),
            eligible_validator_count: 1,
            placements: vec![placement],
            reconciled_at_ms: 1,
            last_error: None,
        };
        placement_record
            .validate()
            .expect("canonical active Inrou placement");
        let trusted_guest_artifact = bundle
            .container
            .inrou
            .as_ref()
            .and_then(|inrou| inrou.guest_images.get(&SoraInrouGuestIsaV1::X8664))
            .map(|image| image.published_artifact.clone())
            .expect("x86_64 guest artifact");
        let capability = SoraInrouHostCapabilityRecordV1 {
            schema_version: SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
            validator_account_id: validator_account_id.clone(),
            peer_id: peer_id.clone(),
            supported_guest_isas: BTreeSet::from([SoraInrouGuestIsaV1::X8664]),
            trusted_guest_artifact,
            max_hosted_replica_capacity: 1,
            max_cpu_millis: u32::try_from(
                bundle
                    .container
                    .resources
                    .checked_inrou_host_cpu_millis()
                    .expect("finite physical CPU reservation"),
            )
            .expect("physical CPU reservation fits u32"),
            max_memory_bytes: bundle
                .container
                .resources
                .checked_inrou_host_memory_bytes()
                .expect("finite physical memory reservation"),
            max_storage_bytes: inrou_bundle_per_replica_storage_bytes(&bundle)
                .expect("finite storage reservation"),
            advertised_at_ms: 1,
            heartbeat_expires_at_ms: 1_000,
        };
        capability.validate().expect("canonical host capability");
        world
            .soracloud_service_revisions_mut_for_testing()
            .insert((service_name.clone(), service_version.clone()), bundle);
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(deployment.service_name.clone(), deployment);
        world
            .soracloud_inrou_service_placements_mut_for_testing()
            .insert(
                (service_name.clone(), service_version.clone()),
                placement_record,
            );
        world
            .soracloud_inrou_host_capabilities_mut_for_testing()
            .insert(validator_account_id.clone(), capability);
        (world, service_name, service_version, validator_account_id)
    }
    #[test]
    fn active_inrou_resolver_requires_available_exact_allowlisted_physical_host() {
        let (mut world, service_name, service_version, validator_account_id) =
            seed_active_inrou_resolver_world();
        let resolve = |world: &World| {
            resolve_active_inrou_replica_assignments(
                &world.view(),
                &service_name,
                &service_version,
                2,
                2,
                |_| true,
            )
        };
        assert_eq!(
            resolve(&world).expect("canonical resolver state").len(),
            1,
            "the exact available allowlisted host at its physical reservation must resolve"
        );

        let placement_key = (service_name.clone(), service_version.clone());
        let mut placement_record = world
            .view()
            .soracloud_inrou_service_placements()
            .get(&placement_key)
            .cloned()
            .expect("placement fixture");
        placement_record.placements[0].host_availability =
            SoraInrouReplicaHostAvailabilityV1::Unavailable;
        world
            .soracloud_inrou_service_placements_mut_for_testing()
            .insert(placement_key.clone(), placement_record.clone());
        assert!(
            resolve(&world)
                .expect("unavailable placement remains structurally valid")
                .is_empty(),
            "an unavailable sticky assignment must not authorize runtime or ledger mutations"
        );
        placement_record.placements[0].host_availability =
            SoraInrouReplicaHostAvailabilityV1::Available;
        world
            .soracloud_inrou_service_placements_mut_for_testing()
            .insert(placement_key.clone(), placement_record);

        let original_bundle = world
            .view()
            .soracloud_service_revisions()
            .get(&placement_key)
            .cloned()
            .expect("bundle fixture");
        let original_peer_id = original_bundle
            .service
            .placement_targets
            .iter()
            .next()
            .expect("placement target")
            .peer_id
            .clone();
        let other_peer_id = checked_peer_id().to_string();
        assert_ne!(other_peer_id, original_peer_id);
        let mut non_allowlisting_bundle = original_bundle.clone();
        non_allowlisting_bundle.service.placement_targets =
            BTreeSet::from([SoraInrouPlacementTargetV1 {
                validator_account_id: validator_account_id.clone(),
                peer_id: other_peer_id,
            }]);
        let non_allowlisting_service_hash = non_allowlisting_bundle.service_manifest_hash();
        world
            .soracloud_service_revisions_mut_for_testing()
            .insert(placement_key.clone(), non_allowlisting_bundle);
        let mut deployment = world
            .view()
            .soracloud_service_deployments()
            .get(&original_bundle.service.service_name)
            .cloned()
            .expect("deployment fixture");
        deployment.current_service_manifest_hash = non_allowlisting_service_hash;
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(
                original_bundle.service.service_name.clone(),
                deployment.clone(),
            );
        assert!(
            resolve(&world)
                .expect("substituted signed allowlist remains structurally valid")
                .is_empty(),
            "an assignment absent from the exact signed validator/peer allowlist must not authorize runtime or ledger mutations"
        );

        let original_service_hash = original_bundle.service_manifest_hash();
        world
            .soracloud_service_revisions_mut_for_testing()
            .insert(placement_key, original_bundle.clone());
        deployment.current_service_manifest_hash = original_service_hash;
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(original_bundle.service.service_name.clone(), deployment);
        let guest_cpu_millis = original_bundle.container.resources.cpu_millis.get();
        let guest_memory_bytes = original_bundle.container.resources.memory_bytes.get();
        let mut capability = world
            .view()
            .soracloud_inrou_host_capabilities()
            .get(&validator_account_id)
            .cloned()
            .expect("host capability fixture");
        capability.max_cpu_millis = guest_cpu_millis;
        capability.max_memory_bytes = guest_memory_bytes;
        capability
            .validate()
            .expect("guest-only limits remain a structurally valid host advert");
        world
            .soracloud_inrou_host_capabilities_mut_for_testing()
            .insert(validator_account_id, capability);
        assert!(
            resolve(&world)
                .expect("finite physical reservation accounting")
                .is_empty(),
            "guest limits without fixed VMM overhead must not satisfy physical host capacity"
        );
    }
    #[test]
    fn active_inrou_resolver_resource_arithmetic_fails_closed() {
        let (mut world, service_name, service_version, _validator_account_id) =
            seed_active_inrou_resolver_world();
        let key = (service_name.clone(), service_version.clone());
        let mut overflow_bundle = world
            .view()
            .soracloud_service_revisions()
            .get(&key)
            .cloned()
            .expect("bundle fixture");
        overflow_bundle.container.resources.memory_bytes =
            NonZeroU64::new(u64::MAX).expect("nonzero maximum memory");
        overflow_bundle.service.container.manifest_hash = overflow_bundle.container_manifest_hash();
        let service_hash = overflow_bundle.service_manifest_hash();
        let container_hash = overflow_bundle.container_manifest_hash();
        world
            .soracloud_service_revisions_mut_for_testing()
            .insert(key, overflow_bundle);
        let service_name_id: Name = service_name.parse().expect("valid service name");
        let mut deployment = world
            .view()
            .soracloud_service_deployments()
            .get(&service_name_id)
            .cloned()
            .expect("deployment fixture");
        deployment.current_service_manifest_hash = service_hash;
        deployment.current_container_manifest_hash = container_hash;
        world
            .soracloud_service_deployments_mut_for_testing()
            .insert(service_name_id, deployment);
        let error = resolve_active_inrou_replica_assignments(
            &world.view(),
            &service_name,
            &service_version,
            2,
            2,
            |_| true,
        )
        .expect_err("VMM-overhead overflow must fail closed");
        assert!(
            error.contains("physical") || error.contains("malformed deployment bundle"),
            "unexpected overflow error: {error}"
        );
    }
    #[test]
    fn inrou_revision_identity_keeps_sticky_placement_and_guest_platform_exact() {
        let world = seed_ordered_mailbox_validator_world();
        let (validator_account_id, peer_id) = world
            .view()
            .public_lane_validators()
            .iter()
            .next()
            .map(|(key, record)| (key.1.clone(), record.peer_id.to_string()))
            .expect("active validator fixture");
        let current = sample_inrou_resolver_bundle(validator_account_id.clone(), peer_id);
        let mut candidate = current.clone();
        candidate.service.service_version = "2026.03.0".to_owned();
        candidate.container.bundle_hash = Hash::new(b"replacement application bundle");
        candidate.service.container.manifest_hash = candidate.container_manifest_hash();
        validate_soracloud_service_revision_identity(&current, &candidate)
            .expect("application implementation may change without changing Inrou host identity");

        let mut replica_drift = candidate.clone();
        replica_drift.service.replicas = NonZeroU16::new(2).expect("nonzero replica count");
        assert!(
            validate_soracloud_service_revision_identity(&current, &replica_drift)
                .expect_err("same-lease replica-count drift must fail")
                .contains("replica count")
        );

        let mut target_drift = candidate.clone();
        target_drift.service.placement_targets = BTreeSet::from([SoraInrouPlacementTargetV1 {
            validator_account_id,
            peer_id: checked_peer_id().to_string(),
        }]);
        assert!(
            validate_soracloud_service_revision_identity(&current, &target_drift)
                .expect_err("same-lease target drift must fail")
                .contains("placement-target allowlist")
        );

        let mut guest_drift = candidate;
        guest_drift
            .container
            .inrou
            .as_mut()
            .expect("Inrou guest manifest")
            .guest_images
            .get_mut(&SoraInrouGuestIsaV1::X8664)
            .expect("x86_64 guest")
            .published_artifact
            .manifest_digest_hex = "32".repeat(32);
        assert!(
            validate_soracloud_service_revision_identity(&current, &guest_drift)
                .expect_err("same-lease guest-platform drift must fail")
                .contains("guest-platform manifest")
        );
    }
    #[test]
    fn validator_peer_binding_follows_the_exact_active_record() {
        let mut world = seed_ordered_mailbox_validator_world();
        let (key, record) = world
            .view()
            .public_lane_validators()
            .iter()
            .next()
            .map(|(key, record)| (key.clone(), record.clone()))
            .expect("active validator fixture");
        let authoritative_peer = record.peer_id.to_string();
        let arbitrary_peer = checked_peer_id();
        assert_ne!(arbitrary_peer, record.peer_id);
        assert!(soracloud_validator_is_active(
            &world.view(),
            &key.1,
            1,
            |_| { true }
        ));
        assert!(soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &authoritative_peer,
            1,
            |_| true,
        ));
        assert!(!soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &arbitrary_peer.to_string(),
            1,
            |_| true,
        ));

        let mut rebound_record = record;
        rebound_record.peer_id = arbitrary_peer.clone();
        world
            .public_lane_validators_mut_for_testing()
            .insert(key.clone(), rebound_record);
        assert!(!soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &authoritative_peer,
            1,
            |_| true,
        ));
        assert!(soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &arbitrary_peer.to_string(),
            1,
            |_| true,
        ));
    }
    #[test]
    fn validator_authority_follows_half_open_tenure_not_lifecycle_label() {
        let mut world = seed_ordered_mailbox_validator_world();
        let (key, mut record) = world
            .view()
            .public_lane_validators()
            .iter()
            .next()
            .map(|(key, record)| (key.clone(), record.clone()))
            .expect("active validator fixture");
        let peer_id = record.peer_id.to_string();
        record.status = PublicLaneValidatorStatus::Exiting(99);
        record.deactivation_height = Some(5);
        world
            .public_lane_validators_mut_for_testing()
            .insert(key.clone(), record);

        assert!(soracloud_validator_is_active(
            &world.view(),
            &key.1,
            4,
            |_| true
        ));
        assert!(soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &peer_id,
            4,
            |_| true,
        ));
        assert!(!soracloud_validator_is_active(
            &world.view(),
            &key.1,
            5,
            |_| true
        ));
        assert!(!soracloud_validator_has_active_peer_binding(
            &world.view(),
            &key.1,
            &peer_id,
            5,
            |_| true,
        ));
    }
    #[test]
    fn local_read_debug_output_redacts_request_and_response_payloads() {
        let request = SoracloudLocalReadRequest {
            observed_height: 7,
            observed_block_hash: Some(Hash::new(b"block")),
            service_name: "public_service".to_owned(),
            service_version: "1.0.0".to_owned(),
            handler_name: "infer".to_owned(),
            handler_class: SoracloudLocalReadKind::Query,
            request_method: "POST".to_owned(),
            request_path: "/public/private-path-marker".to_owned(),
            handler_path: "/private-handler-path-marker".to_owned(),
            request_query: Some("token=private-query-marker".to_owned()),
            request_headers: BTreeMap::from([(
                "authorization".to_owned(),
                "private-header-marker".to_owned(),
            )]),
            request_body: b"private-request-body-marker".to_vec(),
            request_commitment: Hash::new(b"request"),
        };
        let response = SoracloudLocalReadResponse {
            response_bytes: b"private-response-body-marker".to_vec(),
            content_type: Some("private-content-type-marker".to_owned()),
            content_encoding: Some("private-content-encoding-marker".to_owned()),
            cache_control: Some("private-cache-control-marker".to_owned()),
            bindings: vec![SoracloudLocalReadBinding {
                binding_name: Some("private-binding-marker".to_owned()),
                state_key: Some("private-state-key-marker".to_owned()),
                payload_commitment: Some(Hash::new(b"payload")),
                artifact_hash: None,
            }],
            result_commitment: Hash::new(b"response"),
            certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
            runtime_receipt: None,
        };
        let rendered = format!("{request:?}\n{response:?}");
        for secret in [
            "private-path-marker",
            "private-handler-path-marker",
            "private-query-marker",
            "private-header-marker",
            "private-request-body-marker",
            "private-response-body-marker",
            "private-content-type-marker",
            "private-content-encoding-marker",
            "private-cache-control-marker",
            "private-binding-marker",
            "private-state-key-marker",
        ] {
            assert!(
                !rendered.contains(secret),
                "local-read Debug output exposed `{secret}`: {rendered}"
            );
        }
        assert!(rendered.contains("request_body_len: 27"));
        assert!(rendered.contains("response_bytes_len: 28"));
    }
    fn sample_ordered_mailbox_result() -> SoraOrderedMailboxResultV1 {
        let service_name: Name = "mailbox_service".parse().expect("valid service name");
        let handler_name: Name = "update".parse().expect("valid handler name");
        let mailbox_message_id = Hash::new(b"ordered mailbox source message");
        let response_commitment = Hash::new(b"ordered mailbox response");
        let runtime_execution_commitment = Hash::new(b"ordered mailbox runtime outcome");
        let runtime_state = SoraServiceRuntimeStateV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_RUNTIME_STATE_VERSION_V1,
            service_name: service_name.clone(),
            active_service_version: "1.0.0".to_owned(),
            health_status: SoraServiceHealthStatusV1::Healthy,
            load_factor_bps: 125,
            materialized_bundle_hash: Hash::new(b"ordered mailbox bundle"),
        };
        let validator_account_id = checked_account_id();
        let validator_peer_id = checked_peer_id();
        let payload = b"ordered outbound payload".to_vec();
        SoraOrderedMailboxResultV1 {
            schema_version: iroha_data_model::soracloud::SORA_ORDERED_MAILBOX_RESULT_VERSION_V1,
            observed_height: 7,
            observed_block_hash: Some(Hash::new(b"ordered mailbox observed block")),
            observed_sequence: 11,
            state_mutations: vec![
                iroha_data_model::soracloud::SoraOrderedMailboxStateMutationV1 {
                    schema_version:
                        iroha_data_model::soracloud::SORA_ORDERED_MAILBOX_STATE_MUTATION_VERSION_V1,
                    binding_name: "state".parse().expect("valid binding name"),
                    state_key: "/counter".to_owned(),
                    operation: SoraStateMutationOperationV1::Upsert,
                    encryption: SoraStateEncryptionV1::Plaintext,
                    value_payload: Some(b"1".to_vec()),
                },
            ],
            outbound_mailbox_messages: vec![SoraServiceMailboxMessageV1 {
                schema_version:
                    iroha_data_model::soracloud::SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
                message_id: Hash::prehashed([0; Hash::LENGTH]),
                from_service: service_name.clone(),
                from_service_version: String::new(),
                from_handler: handler_name.clone(),
                to_service: "mailbox_destination"
                    .parse()
                    .expect("valid destination service name"),
                to_service_version: String::new(),
                to_handler: "receive".parse().expect("valid destination handler name"),
                payload_commitment: Hash::new(&payload),
                payload_bytes: payload,
                delivery_delay_blocks: 1,
                enqueue_sequence: 0,
                enqueue_height: 0,
                available_after_height: 0,
                expires_at_height: 0,
            }],
            response_commitment,
            runtime_execution_commitment,
            content_type: Some("application/octet-stream".to_owned()),
            observed_runtime_state: None,
            runtime_state: Some(runtime_state),
            runtime_receipt: SoraRuntimeReceiptV1 {
                schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                receipt_id: Hash::new(b"uncommitted ordered mailbox receipt id"),
                service_name,
                service_version: "1.0.0".to_owned(),
                handler_name,
                handler_class: SoraServiceHandlerClassV1::Update,
                request_commitment: Hash::new(b"ordered mailbox request"),
                result_commitment: Hash::new(b"uncommitted ordered mailbox result"),
                certified_by: SoraCertifiedResponsePolicyV1::None,
                emitted_sequence: 0,
                mailbox_message_id: Some(mailbox_message_id),
                journal_artifact_hash: Some(Hash::new(b"ordered mailbox journal")),
                checkpoint_artifact_hash: None,
                execution_host: Some(SoraRuntimeDeterministicValidatorHostV1 {
                    lane_id: LaneId::SINGLE,
                    validator_account_id,
                    peer_id: validator_peer_id.to_string(),
                }),
            },
        }
    }
    fn sample_runtime_service_plan() -> SoracloudRuntimeServicePlan {
        SoracloudRuntimeServicePlan {
            service_name: "service".to_owned(),
            service_version: "1.0.0".to_owned(),
            role: SoracloudRuntimeRevisionRole::Active,
            traffic_percent: 100,
            runtime: SoraContainerRuntimeV1::Inrou,
            execution_plane: SoraServiceExecutionPlaneV1::HttpService,
            bundle_hash: "bundle-hash".to_owned(),
            bundle_path: "sorafs://bundle".to_owned(),
            entrypoint: "/sbin/init".to_owned(),
            inrou: Some(SoracloudRuntimeInrouPlan {
                selected_guest_isa: SoraInrouGuestIsaV1::X8664,
                kernel_image_path: "guest/vmlinuz".to_owned(),
                rootfs_image_path: "guest/rootfs.ext4".to_owned(),
                initrd_image_path: None,
                root_volume_name: "root".to_owned(),
            }),
            bundle_cache_path: "/runtime/cache/bundle".to_owned(),
            bundle_available_locally: true,
            process_generation: None,
            desired_replica_count: 1,
            local_replica_slots: vec![1],
            local_replicas: vec![SoracloudRuntimeReplicaPlan {
                replica_slot: 1,
                lease_started_height: 1,
                placement_incarnation: Hash::new(b"runtime-placement").to_string(),
                host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                validator_account_id: "validator".to_owned(),
                peer_id: "peer".to_owned(),
                materialization_dir: "/runtime/services/service/1.0.0/replica-0001".to_owned(),
                health_status: SoraServiceHealthStatusV1::Unavailable,
                listen_base_url: None,
                pid: None,
                last_error: None,
            }],
            health_status: SoraServiceHealthStatusV1::Unavailable,
            load_factor_bps: 0,
            authoritative_pending_mailbox_messages: 0,
            rollout_handle: None,
            config_generation: 0,
            secret_generation: 0,
            quota_class: None,
            service_lease_status: None,
            lease_expires_height: None,
            remaining_runtime_balance: None,
            config_entry_count: 0,
            secret_entry_count: 0,
            config_exports: Vec::new(),
            supports_host_read_config: false,
            supports_host_read_secret_envelope: false,
            materialization_dir: "/runtime/services/service/1.0.0".to_owned(),
            config_materialization_dir: "/runtime/services/service/1.0.0/config".to_owned(),
            effective_env: BTreeMap::new(),
            effective_env_materialization_path: "/runtime/services/service/1.0.0/env.json"
                .to_owned(),
            config_exports_materialization_dir: "/runtime/services/service/1.0.0/exports"
                .to_owned(),
            secret_envelopes_materialization_dir: "/runtime/services/service/1.0.0/secrets"
                .to_owned(),
            lease_volumes: Vec::new(),
            mailboxes: Vec::new(),
            artifacts: Vec::new(),
        }
    }
    #[test]
    fn checked_keypair_preserves_default_algorithm() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    }
    #[test]
    fn ordered_mailbox_result_commitment_binds_effects_but_not_occ_preconditions() {
        let result = sample_ordered_mailbox_result();
        let commitment = ordered_mailbox_result_commitment(&result);

        let mut changed_mutation = result.clone();
        changed_mutation.state_mutations[0].value_payload = Some(b"2".to_vec());
        assert_ne!(
            ordered_mailbox_result_commitment(&changed_mutation),
            commitment
        );

        let mut changed_outbound = result.clone();
        changed_outbound.outbound_mailbox_messages[0].expires_at_height += 1;
        assert_ne!(
            ordered_mailbox_result_commitment(&changed_outbound),
            commitment
        );

        let mut changed_runtime_state = result.clone();
        changed_runtime_state
            .runtime_state
            .as_mut()
            .expect("runtime-state projection")
            .load_factor_bps += 1;
        assert_ne!(
            ordered_mailbox_result_commitment(&changed_runtime_state),
            commitment
        );

        let mut changed_preconditions = result.clone();
        changed_preconditions.observed_height += 1;
        changed_preconditions.observed_sequence += 1;
        changed_preconditions.observed_block_hash = Some(Hash::new(b"different observed block"));
        changed_preconditions.observed_runtime_state = result.runtime_state.clone();
        assert_eq!(
            ordered_mailbox_result_commitment(&changed_preconditions),
            commitment
        );
    }
    #[test]
    fn ordered_mailbox_receipt_id_binds_every_immutable_receipt_field() {
        let receipt = sample_ordered_mailbox_result().runtime_receipt;
        let canonical = ordered_mailbox_runtime_receipt_id(&receipt)
            .expect("ordered-mailbox fixture names its source message");

        macro_rules! assert_field_bound {
            ($field:literal, $mutate:expr) => {{
                let mut changed = receipt.clone();
                ($mutate)(&mut changed);
                assert_ne!(
                    ordered_mailbox_runtime_receipt_id(&changed),
                    Some(canonical),
                    "ordered-mailbox receipt ID must bind {}",
                    $field
                );
            }};
        }

        assert_field_bound!("schema_version", |changed: &mut SoraRuntimeReceiptV1| {
            changed.schema_version += 1;
        });
        assert_field_bound!(
            "mailbox_message_id",
            |changed: &mut SoraRuntimeReceiptV1| {
                changed.mailbox_message_id = Some(Hash::new(b"different source message"));
            }
        );
        assert_field_bound!("service_name", |changed: &mut SoraRuntimeReceiptV1| {
            changed.service_name = "different_service".parse().expect("valid service name");
        });
        assert_field_bound!("service_version", |changed: &mut SoraRuntimeReceiptV1| {
            changed.service_version = "2.0.0".to_owned();
        });
        assert_field_bound!("handler_name", |changed: &mut SoraRuntimeReceiptV1| {
            changed.handler_name = "different_handler".parse().expect("valid handler name");
        });
        assert_field_bound!("handler_class", |changed: &mut SoraRuntimeReceiptV1| {
            changed.handler_class = SoraServiceHandlerClassV1::Query;
        });
        assert_field_bound!(
            "request_commitment",
            |changed: &mut SoraRuntimeReceiptV1| {
                changed.request_commitment = Hash::new(b"different request");
            }
        );
        assert_field_bound!("result_commitment", |changed: &mut SoraRuntimeReceiptV1| {
            changed.result_commitment = Hash::new(b"different result");
        });
        assert_field_bound!("certified_by", |changed: &mut SoraRuntimeReceiptV1| {
            changed.certified_by = SoraCertifiedResponsePolicyV1::AuditReceipt;
        });
        assert_field_bound!("execution_host", |changed: &mut SoraRuntimeReceiptV1| {
            changed.execution_host = None;
        });
        assert_field_bound!(
            "journal_artifact_hash",
            |changed: &mut SoraRuntimeReceiptV1| {
                changed.journal_artifact_hash = Some(Hash::new(b"different journal"));
            }
        );
        assert_field_bound!(
            "checkpoint_artifact_hash",
            |changed: &mut SoraRuntimeReceiptV1| {
                changed.checkpoint_artifact_hash = Some(Hash::new(b"different checkpoint"));
            }
        );

        let mut ledger_owned = receipt;
        ledger_owned.receipt_id = Hash::new(b"ignored prior receipt identifier");
        ledger_owned.emitted_sequence = 42;
        assert_eq!(
            ordered_mailbox_runtime_receipt_id(&ledger_owned),
            Some(canonical),
            "receipt identity must remain sequence-independent and non-recursive"
        );
    }
    #[test]
    fn ordered_mailbox_executor_uses_the_exact_peer_from_the_active_validator_record() {
        let mut world = seed_ordered_mailbox_validator_world();
        let payload = b"executor selection payload".to_vec();
        let mut message = SoraServiceMailboxMessageV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
            message_id: Hash::prehashed([0; Hash::LENGTH]),
            from_service: "source".parse().expect("valid source service"),
            from_service_version: "1.0.0".to_owned(),
            from_handler: "send".parse().expect("valid source handler"),
            to_service: "destination".parse().expect("valid destination service"),
            to_service_version: "2.0.0".to_owned(),
            to_handler: "receive".parse().expect("valid destination handler"),
            payload_commitment: Hash::new(&payload),
            payload_bytes: payload,
            delivery_delay_blocks: 0,
            enqueue_sequence: 3,
            enqueue_height: 3,
            available_after_height: 3,
            expires_at_height: 9,
        };
        message.message_id = derive_soracloud_mailbox_message_id_v1(&message);
        let validator_key = {
            let view = world.view();
            let (validator_key, validator_record) = view
                .public_lane_validators()
                .iter()
                .next()
                .map(|(key, record)| (key.clone(), record.clone()))
                .expect("active validator fixture");
            let selected = resolve_ordered_mailbox_executor(&view, &message, 4, |_| true)
                .expect("canonical active validator must be selected");

            assert_eq!(selected.lane_id, validator_key.0);
            assert_eq!(selected.validator_account_id, validator_key.1);
            assert_eq!(selected.peer_id, validator_record.peer_id.to_string());
            validator_key
        };

        let mut rebound_record = world
            .view()
            .public_lane_validators()
            .get(&validator_key)
            .cloned()
            .expect("active validator fixture");
        let rebound_peer = checked_peer_id();
        rebound_record.peer_id = rebound_peer.clone();
        world
            .public_lane_validators_mut_for_testing()
            .insert(validator_key, rebound_record);
        let selected = resolve_ordered_mailbox_executor(&world.view(), &message, 4, |_| true)
            .expect("the active record's independently canonical peer must remain eligible");
        assert_eq!(selected.peer_id, rebound_peer.to_string());
    }
    #[test]
    fn ordered_mailbox_executor_cannot_be_grinded_by_message_identity_or_payload() {
        let mut world = seed_ordered_mailbox_validator_world();
        let mut second_record = world
            .view()
            .public_lane_validators()
            .iter()
            .next()
            .map(|(_key, record)| record.clone())
            .expect("first active validator fixture");
        let second_validator = checked_account_id();
        second_record.validator = second_validator.clone();
        second_record.stake_account = second_validator.clone();
        second_record.peer_id = checked_peer_id();
        world.public_lane_validators_mut_for_testing().insert(
            (iroha_model_base::topology::LaneId::SINGLE, second_validator),
            second_record,
        );

        let payload = b"executor selection payload".to_vec();
        let mut message = SoraServiceMailboxMessageV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
            message_id: Hash::prehashed([0; Hash::LENGTH]),
            from_service: "source".parse().expect("valid source service"),
            from_service_version: "1.0.0".to_owned(),
            from_handler: "send".parse().expect("valid source handler"),
            to_service: "destination".parse().expect("valid destination service"),
            to_service_version: "2.0.0".to_owned(),
            to_handler: "receive".parse().expect("valid destination handler"),
            payload_commitment: Hash::new(&payload),
            payload_bytes: payload,
            delivery_delay_blocks: 0,
            enqueue_sequence: 3,
            enqueue_height: 3,
            available_after_height: 3,
            expires_at_height: 9,
        };
        message.message_id = derive_soracloud_mailbox_message_id_v1(&message);
        let selected = resolve_ordered_mailbox_executor(&world.view(), &message, 4, |_| true)
            .expect("one of two active validators must be selected");

        let mut payload_grind = message.clone();
        payload_grind.payload_bytes = b"grinded payload".to_vec();
        payload_grind.payload_commitment = Hash::new(&payload_grind.payload_bytes);
        payload_grind.message_id = derive_soracloud_mailbox_message_id_v1(&payload_grind);
        assert_ne!(payload_grind.message_id, message.message_id);
        assert_eq!(
            resolve_ordered_mailbox_executor(&world.view(), &payload_grind, 4, |_| true),
            Some(selected.clone()),
            "caller-controlled payload and its canonical id must not steer executor selection"
        );

        let mut identifier_grind = message;
        identifier_grind.message_id = Hash::new(b"caller-grinded message id");
        assert_eq!(
            resolve_ordered_mailbox_executor(&world.view(), &identifier_grind, 4, |_| true),
            Some(selected),
            "a substituted message id must not steer executor selection"
        );
    }
    #[test]
    fn latest_and_authoritative_sequences_use_the_persisted_watermark_and_saturate() {
        let mut world = World::new();
        let set_watermark = |world: &World, value| {
            let mut block = world.block();
            *block.soracloud_sequence_watermark.get_mut() = value;
            block.commit();
        };
        assert_eq!(latest_soracloud_sequence(&world.view()), 0);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), 1);

        let signer = checked_keypair().public_key().clone();
        world
            .soracloud_app_infra_audit_events_mut_for_testing()
            .insert(
                7,
                SoraAppInfraAuditEventV1 {
                    schema_version: SORA_APP_INFRA_AUDIT_EVENT_VERSION_V1,
                    sequence: 7,
                    action: SoraAppInfraActionV1::Deploy,
                    app_name: "sequence_app".parse().expect("valid app name"),
                    from_version: None,
                    to_version: "1.0.0".to_owned(),
                    app_manifest_hash: Hash::new(b"sequence-app-manifest"),
                    service_count: 1,
                    signer: signer.clone(),
                },
            );
        set_watermark(&world, 7);
        assert_eq!(latest_soracloud_sequence(&world.view()), 7);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), 8);

        // The watermark remains authoritative even after sequence-owning history is pruned.
        set_watermark(&world, 13);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), 14);

        let receipt_id = Hash::new(b"sequence-runtime-receipt");
        world.soracloud_runtime_receipts_mut_for_testing().insert(
            receipt_id,
            SoraRuntimeReceiptV1 {
                schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
                receipt_id,
                service_name: "sequence_service".parse().expect("valid service name"),
                service_version: "1.0.0".to_owned(),
                handler_name: "query".parse().expect("valid handler name"),
                handler_class: SoraServiceHandlerClassV1::Query,
                request_commitment: Hash::new(b"sequence-request"),
                result_commitment: Hash::new(b"sequence-result"),
                certified_by: SoraCertifiedResponsePolicyV1::AuditReceipt,
                emitted_sequence: 21,
                mailbox_message_id: None,
                journal_artifact_hash: None,
                checkpoint_artifact_hash: None,
                execution_host: None,
            },
        );
        set_watermark(&world, 21);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), 22);

        let mut mailbox_message = SoraServiceMailboxMessageV1 {
            schema_version: iroha_data_model::soracloud::SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
            message_id: Hash::prehashed([0; Hash::LENGTH]),
            from_service: "sequence_source".parse().expect("valid service name"),
            from_service_version: "1.0.0".to_string(),
            from_handler: "update".parse().expect("valid handler name"),
            to_service: "sequence_destination".parse().expect("valid service name"),
            to_service_version: "1.0.0".to_string(),
            to_handler: "update".parse().expect("valid handler name"),
            payload_bytes: b"sequence-mailbox-payload".to_vec(),
            payload_commitment: Hash::new(b"sequence-mailbox-payload"),
            delivery_delay_blocks: 0,
            enqueue_sequence: 35,
            enqueue_height: 35,
            available_after_height: 35,
            expires_at_height: 40,
        };
        mailbox_message.message_id = derive_soracloud_mailbox_message_id_v1(&mailbox_message);
        world
            .soracloud_mailbox_messages_mut_for_testing()
            .insert(mailbox_message.message_id, mailbox_message);
        set_watermark(&world, 35);
        assert_eq!(latest_soracloud_sequence(&world.view()), 35);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), 36);

        world
            .soracloud_app_infra_audit_events_mut_for_testing()
            .insert(
                u64::MAX,
                SoraAppInfraAuditEventV1 {
                    schema_version: SORA_APP_INFRA_AUDIT_EVENT_VERSION_V1,
                    sequence: u64::MAX,
                    action: SoraAppInfraActionV1::Upgrade,
                    app_name: "sequence_app".parse().expect("valid app name"),
                    from_version: Some("1.0.0".to_owned()),
                    to_version: "2.0.0".to_owned(),
                    app_manifest_hash: Hash::new(b"terminal-sequence-app-manifest"),
                    service_count: 1,
                    signer,
                },
            );
        set_watermark(&world, u64::MAX);
        assert_eq!(latest_soracloud_sequence(&world.view()), u64::MAX);
        assert_eq!(authoritative_soracloud_sequence(&world.view()), u64::MAX);
    }
    #[test]
    fn runtime_snapshot_json_requires_the_exact_v1_field_set() {
        let canonical = SoracloudRuntimeSnapshot::default();
        let canonical_value =
            norito::json::to_value(&canonical).expect("encode canonical runtime snapshot");
        assert_eq!(
            norito::json::from_value::<SoracloudRuntimeSnapshot>(canonical_value.clone())
                .expect("decode canonical runtime snapshot"),
            canonical
        );

        let mut unknown = canonical_value.clone();
        unknown
            .as_object_mut()
            .expect("snapshot JSON object")
            .insert("legacy_runtime".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeSnapshot>(unknown).is_err(),
            "same-version snapshots must reject unknown fields"
        );

        for required_field in [
            "observed_block_hash",
            "local_peer_id",
            "services",
            "apartments",
        ] {
            let mut missing = canonical_value.clone();
            missing
                .as_object_mut()
                .expect("snapshot JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudRuntimeSnapshot>(missing).is_err(),
                "same-version snapshots must require the canonically emitted {required_field} field"
            );
        }
    }

    #[test]
    fn runtime_snapshot_nested_records_require_the_exact_v1_field_set() {
        let apartment = SoracloudRuntimeApartmentPlan {
            apartment_name: "apartment".to_owned(),
            manifest_hash: "manifest-hash".to_owned(),
            status: SoraAgentRuntimeStatusV1::Running,
            process_generation: 1,
            lease_expires_height: 100,
            last_active_sequence: 1,
            materialization_dir: "/runtime/apartments/apartment".to_owned(),
            pending_wallet_request_count: 0,
            pending_mailbox_message_count: 0,
            autonomy_budget_remaining_units: 0,
            approved_artifact_count: 0,
            autonomy_run_count: 0,
            revoked_policy_capability_count: 0,
        };
        let mut apartment_value =
            norito::json::to_value(&apartment).expect("encode canonical runtime apartment plan");
        apartment_value
            .as_object_mut()
            .expect("runtime apartment plan JSON object")
            .insert("legacy_status".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeApartmentPlan>(apartment_value).is_err(),
            "same-version runtime apartment plans must reject unknown fields"
        );
    }

    #[test]
    fn runtime_service_plan_json_requires_the_exact_v1_field_set() {
        let canonical = sample_runtime_service_plan();
        let canonical_value =
            norito::json::to_value(&canonical).expect("encode canonical runtime service plan");
        assert_eq!(
            norito::json::from_value::<SoracloudRuntimeServicePlan>(canonical_value.clone())
                .expect("decode canonical runtime service plan"),
            canonical
        );
        let canonical_role = canonical.role;
        let canonical_role_value =
            norito::json::to_value(&canonical_role).expect("encode canonical runtime role");
        assert_eq!(
            norito::json::from_value::<SoracloudRuntimeRevisionRole>(canonical_role_value.clone())
                .expect("decode canonical runtime role"),
            canonical_role
        );
        let mut unknown_role = canonical_role_value;
        unknown_role
            .as_object_mut()
            .expect("runtime role JSON object")
            .insert("legacy_role".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeRevisionRole>(unknown_role).is_err(),
            "same-version runtime roles must reject unknown envelope fields"
        );
        for nullable_field in [
            "process_generation",
            "rollout_handle",
            "quota_class",
            "service_lease_status",
            "lease_expires_height",
            "remaining_runtime_balance",
        ] {
            assert!(
                canonical_value
                    .get(nullable_field)
                    .is_some_and(norito::json::Value::is_null),
                "canonical runtime service plan must emit explicit null for {nullable_field}"
            );
        }

        let mut unknown = canonical_value.clone();
        unknown
            .as_object_mut()
            .expect("runtime service plan JSON object")
            .insert("legacy_backend".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeServicePlan>(unknown).is_err(),
            "same-version runtime service plans must reject unknown fields"
        );

        for required_field in [
            "inrou",
            "process_generation",
            "desired_replica_count",
            "local_replica_slots",
            "local_replicas",
            "rollout_handle",
            "quota_class",
            "service_lease_status",
            "lease_expires_height",
            "remaining_runtime_balance",
            "config_exports",
            "effective_env",
            "effective_env_materialization_path",
            "config_exports_materialization_dir",
            "lease_volumes",
        ] {
            let mut missing = canonical_value.clone();
            missing
                .as_object_mut()
                .expect("runtime service plan JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudRuntimeServicePlan>(missing).is_err(),
                "same-version runtime service plans must require {required_field}"
            );
        }

        let inrou = canonical.inrou.as_ref().expect("Inrou plan fixture");
        let inrou_value =
            norito::json::to_value(inrou).expect("encode canonical runtime Inrou plan");
        assert_eq!(
            norito::json::from_value::<SoracloudRuntimeInrouPlan>(inrou_value.clone())
                .expect("decode canonical runtime Inrou plan"),
            *inrou
        );
        assert!(
            inrou_value
                .get("initrd_image_path")
                .is_some_and(norito::json::Value::is_null),
            "canonical runtime Inrou plan must emit explicit null for initrd_image_path"
        );
        for required_field in ["initrd_image_path"] {
            let mut missing = inrou_value.clone();
            missing
                .as_object_mut()
                .expect("runtime Inrou plan JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudRuntimeInrouPlan>(missing).is_err(),
                "same-version runtime Inrou plans must require {required_field}"
            );
        }
        let mut unknown_inrou = inrou_value;
        unknown_inrou
            .as_object_mut()
            .expect("runtime Inrou plan JSON object")
            .insert(
                "bootstrap_user_data_path".to_owned(),
                norito::json::Value::Null,
            );
        assert!(
            norito::json::from_value::<SoracloudRuntimeInrouPlan>(unknown_inrou).is_err(),
            "same-version runtime Inrou plans must reject the retired bootstrap overlay field"
        );

        let replica = canonical
            .local_replicas
            .first()
            .expect("runtime replica plan fixture");
        let replica_value =
            norito::json::to_value(replica).expect("encode canonical runtime replica plan");
        assert_eq!(
            norito::json::from_value::<SoracloudRuntimeReplicaPlan>(replica_value.clone())
                .expect("decode canonical runtime replica plan"),
            *replica
        );
        for required_field in ["listen_base_url", "pid", "last_error"] {
            assert!(
                replica_value
                    .get(required_field)
                    .is_some_and(norito::json::Value::is_null),
                "canonical runtime replica plan must emit explicit null for {required_field}"
            );
            let mut missing = replica_value.clone();
            missing
                .as_object_mut()
                .expect("runtime replica plan JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudRuntimeReplicaPlan>(missing).is_err(),
                "same-version runtime replica plans must require {required_field}"
            );
        }
        let mut missing_host_availability = replica_value.clone();
        missing_host_availability
            .as_object_mut()
            .expect("runtime replica plan JSON object")
            .remove("host_availability");
        assert!(
            norito::json::from_value::<SoracloudRuntimeReplicaPlan>(missing_host_availability)
                .is_err(),
            "same-version runtime replica plans must require host_availability"
        );
        let mut unknown_replica = replica_value;
        unknown_replica
            .as_object_mut()
            .expect("runtime replica plan JSON object")
            .insert("legacy_pid".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeReplicaPlan>(unknown_replica).is_err(),
            "same-version runtime replica plans must reject unknown fields"
        );
    }

    #[test]
    fn runtime_nested_plan_json_requires_the_exact_v1_field_set() {
        let mailbox = SoracloudRuntimeMailboxPlan {
            handler_name: "dispatch".to_owned(),
            queue_name: "dispatch-queue".to_owned(),
            max_pending_messages: 4,
            max_message_bytes: 1024,
            retention_blocks: 16,
        };
        let mut mailbox_value =
            norito::json::to_value(&mailbox).expect("encode canonical runtime mailbox plan");
        mailbox_value
            .as_object_mut()
            .expect("runtime mailbox plan JSON object")
            .insert("legacy_queue".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeMailboxPlan>(mailbox_value).is_err(),
            "same-version runtime mailbox plans must reject unknown fields"
        );

        let artifact = SoracloudRuntimeArtifactPlan {
            kind: SoraArtifactKindV1::Bundle,
            artifact_hash: "artifact-hash".to_owned(),
            artifact_path: "bundle.to".to_owned(),
            handler_name: None,
            local_cache_path: "/runtime/cache/artifact".to_owned(),
            available_locally: false,
        };
        let artifact_value =
            norito::json::to_value(&artifact).expect("encode canonical runtime artifact plan");
        assert!(
            artifact_value
                .get("handler_name")
                .is_some_and(norito::json::Value::is_null),
            "canonical runtime artifact plans must emit an explicit null handler_name"
        );
        let mut missing_handler = artifact_value.clone();
        missing_handler
            .as_object_mut()
            .expect("runtime artifact plan JSON object")
            .remove("handler_name");
        assert!(
            norito::json::from_value::<SoracloudRuntimeArtifactPlan>(missing_handler).is_err(),
            "same-version runtime artifact plans must require handler_name"
        );
        let mut unknown_artifact = artifact_value;
        unknown_artifact
            .as_object_mut()
            .expect("runtime artifact plan JSON object")
            .insert("legacy_handler".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeArtifactPlan>(unknown_artifact).is_err(),
            "same-version runtime artifact plans must reject unknown fields"
        );

        let lease = SoracloudRuntimeLeaseVolumePlan {
            volume_name: "root".to_owned(),
            kind: SoraLeaseVolumeKindV1::PersistentRootLeaseVolume,
            storage_class: StorageClass::Warm,
            mount_path: "/".to_owned(),
            max_total_bytes: 1024,
            lease_started_height: 1,
            lease_expires_height: 100,
            authoritative_generation: 1,
            local_materialization_dir: "/runtime/volumes/root".to_owned(),
        };
        let mut lease_value =
            norito::json::to_value(&lease).expect("encode canonical runtime lease-volume plan");
        lease_value
            .as_object_mut()
            .expect("runtime lease-volume plan JSON object")
            .insert("legacy_path".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudRuntimeLeaseVolumePlan>(lease_value).is_err(),
            "same-version runtime lease-volume plans must reject unknown fields"
        );
    }

    #[test]
    fn hosted_http_runtime_state_json_requires_the_exact_v1_field_set() {
        let canonical = SoracloudHostedHttpRuntimeStateV1 {
            schema_version: SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1,
            service_name: "service".to_owned(),
            service_version: "1.0.0".to_owned(),
            process_generation: 1,
            health_status: SoraServiceHealthStatusV1::Healthy,
            listen_base_url: None,
            pid: None,
            accounted_egress_bytes: 0,
            replicas: vec![SoracloudHostedHttpReplicaRuntimeStateV1 {
                replica_slot: 1,
                placement_incarnation: Hash::new(b"runtime-placement").to_string(),
                health_status: SoraServiceHealthStatusV1::Healthy,
                listen_base_url: None,
                pid: None,
                last_error: None,
                updated_at_ms: 1,
            }],
            last_error: None,
            updated_at_ms: 1,
        };
        let canonical_value =
            norito::json::to_value(&canonical).expect("encode canonical hosted runtime state");
        assert_eq!(
            norito::json::from_value::<SoracloudHostedHttpRuntimeStateV1>(canonical_value.clone())
                .expect("decode canonical hosted runtime state"),
            canonical
        );
        for nullable_field in ["listen_base_url", "pid", "last_error"] {
            assert!(
                canonical_value
                    .get(nullable_field)
                    .is_some_and(norito::json::Value::is_null),
                "canonical hosted runtime state must emit explicit null for {nullable_field}"
            );
            assert!(
                canonical_value
                    .pointer(&format!("/replicas/0/{nullable_field}"))
                    .is_some_and(norito::json::Value::is_null),
                "canonical hosted replica state must emit explicit null for {nullable_field}"
            );
        }

        let mut unknown = canonical_value.clone();
        unknown
            .as_object_mut()
            .expect("hosted runtime state JSON object")
            .insert("legacy_backend".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudHostedHttpRuntimeStateV1>(unknown).is_err(),
            "same-version hosted runtime state must reject unknown fields"
        );

        let mut unknown_replica = canonical_value.clone();
        unknown_replica
            .pointer_mut("/replicas/0")
            .and_then(norito::json::Value::as_object_mut)
            .expect("hosted replica JSON object")
            .insert("legacy_pid".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudHostedHttpRuntimeStateV1>(unknown_replica).is_err(),
            "same-version hosted replica state must reject unknown fields"
        );

        for required_field in [
            "listen_base_url",
            "pid",
            "accounted_egress_bytes",
            "replicas",
            "last_error",
        ] {
            let mut missing = canonical_value.clone();
            missing
                .as_object_mut()
                .expect("hosted runtime state JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudHostedHttpRuntimeStateV1>(missing).is_err(),
                "same-version hosted runtime state must require {required_field}"
            );
        }
        for required_field in ["listen_base_url", "pid", "last_error"] {
            let mut missing = canonical_value.clone();
            missing
                .pointer_mut("/replicas/0")
                .and_then(norito::json::Value::as_object_mut)
                .expect("hosted replica JSON object")
                .remove(required_field);
            assert!(
                norito::json::from_value::<SoracloudHostedHttpRuntimeStateV1>(missing).is_err(),
                "same-version hosted replica state must require {required_field}"
            );
        }
    }
    #[test]
    fn local_read_binding_json_requires_explicit_nullable_slots_and_rejects_unknown_fields() {
        let canonical = SoracloudLocalReadBinding {
            binding_name: None,
            state_key: None,
            payload_commitment: None,
            artifact_hash: None,
        };
        let canonical_value =
            norito::json::to_value(&canonical).expect("encode canonical local-read binding");
        for nullable_field in [
            "binding_name",
            "state_key",
            "payload_commitment",
            "artifact_hash",
        ] {
            assert!(
                canonical_value
                    .get(nullable_field)
                    .is_some_and(norito::json::Value::is_null),
                "canonical local-read binding must emit explicit null for {nullable_field}"
            );
            let mut missing = canonical_value.clone();
            missing
                .as_object_mut()
                .expect("local-read binding JSON object")
                .remove(nullable_field);
            assert!(
                norito::json::from_value::<SoracloudLocalReadBinding>(missing).is_err(),
                "local-read binding must require {nullable_field}"
            );
        }
        let mut unknown = canonical_value;
        unknown
            .as_object_mut()
            .expect("local-read binding JSON object")
            .insert("legacy_binding".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<SoracloudLocalReadBinding>(unknown).is_err(),
            "local-read binding must reject unknown nested fields"
        );
    }
    #[test]
    fn runtime_execution_error_has_stable_user_facing_context() {
        let error = SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            "missing canonical step_id",
        );
        assert_eq!(
            error.to_string(),
            "Soracloud runtime invalid request error: missing canonical step_id"
        );
        assert!(std::error::Error::source(&error).is_none());
    }
}
