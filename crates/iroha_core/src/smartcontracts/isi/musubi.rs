//! Musubi V1 package-registry instruction and query handlers.
//!
//! The registry uses only typed first-release stores. No legacy state-path
//! decoding or compatibility aliases live here.
use super::prelude::*;
use crate::state::deserialize::musubi_source_read::MusubiSourceReadOnly;
use crate::{
    governance::parliament::{
        canonical_governance_attempt_ids_v1, validate_parliament_randomness_redraw_lineage_v1,
    },
    prelude::ValidSingularQuery,
    smartcontracts::Execute,
    state::{
        GovernanceProposalStatus, MusubiResolverIndexRevisionV1, StateReadOnly, StateTransaction,
        WorldReadOnly,
    },
    telemetry::{MusubiGovernanceActionV1, MusubiGovernanceRejectionReasonV1},
};
#[cfg(test)]
use iroha_crypto::HashOf;
#[cfg(test)]
use iroha_data_model::block::BlockHeader;
use iroha_data_model::{
    asset::AssetId,
    events::data::{DataEvent, musubi::prelude::*},
    governance::types::{GovernanceAttemptStatusV1, ProposalContentId, ProposalKind},
    isi::{
        error::{InstructionExecutionError as Error, InvalidParameterError},
        musubi::*,
    },
    musubi::*,
    query::{error::QueryExecutionFail, musubi::prelude::*},
    sorafs::pin_registry::ReplicationOrderStatus,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use std::collections::{BTreeMap, BTreeSet};

mod attestation_records;
use attestation_records::load_location_provider_attestations;
mod current_providers;
mod pin_outbox;
mod replication_binding;
use crate::state::deserialize::musubi_source_read::{LookupCursor, MusubiRead, ReadFailure};
pub(crate) use current_providers::{CurrentProviderValidation, current_location_providers};
pub(crate) use pin_outbox::{PinOutboxOperationOrigin, capture_pin_outbox_operation_origin};
pub(crate) use replication_binding::validate_replication_order_archive_binding;
impl Execute for RegisterMusubiNamespaceBindingV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::NamespaceBinding,
            |state_transaction, rejection_reason| {
                self.binding
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                if let Some(existing) = state_transaction
                    .world
                    .musubi_namespace_bindings
                    .get(&self.binding.namespace)
                {
                    if existing != &self.binding {
                        return Err(invariant(format!(
                            "Musubi namespace '{}' is already bound",
                            self.binding.namespace
                        )));
                    }
                    ensure_namespace_current_owner(
                        existing,
                        authority,
                        state_transaction,
                        rejection_reason,
                    )
                    .map_err(|error| namespace_attempt_error(error, state_transaction))?;
                    return Ok(());
                }
                let policy = state_transaction.world.musubi_registry_policy.get().clone();
                classify_governance_rejection(
                    ensure_policy_revision(&policy, self.expected_policy_revision),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                ensure_admitted(
                    &policy,
                    Some(self.binding.home_dataspace),
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                ensure_namespace_registration_owner(
                    &self.binding,
                    authority,
                    state_transaction,
                    rejection_reason,
                )
                .map_err(|error| namespace_attempt_error(error, state_transaction))?;
                let event = MusubiEvent::NamespaceBound(self.binding.clone());
                state_transaction
                    .world
                    .musubi_namespace_bindings
                    .insert(self.binding.namespace.clone(), self.binding);
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RegisterMusubiArchiveV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::ArchiveRegistration,
            |state_transaction, rejection_reason| {
                self.commitment
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                self.staging_receipt
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let archive_id = self.commitment.archive_id();
                if let Some(existing) = state_transaction.world.musubi_archives.get(&archive_id) {
                    if existing.commitment != self.commitment
                        || existing.staging_receipt != self.staging_receipt
                    {
                        return Err(invariant(format!(
                            "Musubi archive '{}' is already registered with a different commitment or staging receipt",
                            digest_label(archive_id.as_bytes())
                        )));
                    }
                    if existing.registered_by != *authority {
                        return reject_governance_mutation(
                            rejection_reason,
                            MusubiGovernanceRejectionReasonV1::Unauthorized,
                            invariant(
                                "only the original Musubi archive registrant may replay registration",
                            ),
                        );
                    }
                    return Ok(());
                }
                let policy = state_transaction.world.musubi_registry_policy.get().clone();
                classify_governance_rejection(
                    ensure_policy_revision(&policy, self.expected_policy_revision),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                ensure_admitted(
                    &policy,
                    None,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                validate_seed_ingress_receipt(
                    &self.commitment,
                    &self.staging_receipt,
                    authority,
                    state_transaction,
                )?;
                let height = execution_height(state_transaction);
                let index_revision = state_transaction
                    .world
                    .musubi_resolver_index_revision
                    .get()
                    .get();
                state_transaction.world.musubi_archives.insert(
                    archive_id,
                    MusubiArchiveRecordV1 {
                        archive_id,
                        commitment: self.commitment,
                        staging_receipt: self.staging_receipt,
                        registered_by: authority.clone(),
                        registered_at_height: height,
                        location_revision: 1,
                        location_ids: Vec::new(),
                    },
                );
                let availability = MusubiArchiveAvailabilityV1 {
                    archive_id,
                    availability: MusubiStorageAvailabilityV1::Unavailable,
                    healthy_replicas: 0,
                    active_locations: 0,
                    finalized_height: height,
                    finalized_block_hash: execution_hash(state_transaction),
                    index_revision,
                };
                state_transaction
                    .world
                    .musubi_archive_availability
                    .insert(archive_id, availability);
                state_transaction
                    .world
                    .musubi_archive_reverse_references
                    .insert(
                        archive_id,
                        MusubiArchiveReverseReferencesV1 {
                            archive_id,
                            releases: Vec::new(),
                        },
                    );
                emit_musubi_event(
                    MusubiEvent::ArchiveRegistered(MusubiArchiveRegisteredEventV1 {
                        archive_id,
                        registered_by: authority.clone(),
                        location_revision: 1,
                        finalized_height: height,
                    }),
                    state_transaction,
                );
                emit_musubi_event(
                    MusubiEvent::ArchiveAvailabilityChanged(availability),
                    state_transaction,
                );
                Ok(())
            },
        )
    }
}
impl Execute for RegisterMusubiProviderBundleAttestationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::ArchiveLocation,
            |state_transaction, rejection_reason| {
                self.validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let key = self.attestation.key();
                let archive = state_transaction
                    .world
                    .musubi_archives
                    .get(&key.archive_id)
                    .cloned()
                    .ok_or_else(|| archive_not_found(key.archive_id))?;
                archive
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                if archive.archive_id != key.archive_id {
                    return Err(invariant(
                        "Musubi provider attestation archive has the wrong embedded identity",
                    ));
                }
                ensure_archive_manager(
                    &archive,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                if let Some(existing) = state_transaction
                    .world
                    .musubi_provider_bundle_attestations
                    .get(&key)
                {
                    existing
                        .validate()
                        .map_err(|error| invariant(error.reason()))?;
                    existing
                        .attestation
                        .verify(&existing.attestation.payload.binding)
                        .map_err(|error| invariant(error.reason()))?;
                    if existing.attestation_digest == self.attestation.digest()
                        && existing.attestation == self.attestation
                    {
                        validate_provider_bundle_attestation(
                            &archive,
                            &existing.attestation,
                            state_transaction,
                        )?;
                        return Ok(());
                    }
                    return Err(invariant(
                        "Musubi provider bundle attestation identity is permanently bound to different evidence",
                    ));
                }
                classify_governance_rejection(
                    ensure_revision(
                        "archive location",
                        archive.location_revision,
                        self.expected_location_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if matches!(
                    validate_replication_order_archive_binding(
                        &archive,
                        &key.replication_order,
                        state_transaction.world(),
                    )
                    .map_err(|error| invariant(error.reason()))?,
                    MusubiReplicationOrderLocationLifecycleV1::Retired(_)
                ) {
                    return Err(invariant(
                        "Musubi provider attestation replication-order binding is retired",
                    ));
                }
                validate_provider_bundle_attestation(
                    &archive,
                    &self.attestation,
                    state_transaction,
                )?;
                let finalized_height = execution_height(state_transaction);
                let record = MusubiProviderBundleAttestationRecordV1 {
                    key,
                    attestation_digest: self.attestation.digest(),
                    attestation: self.attestation,
                    registered_by: authority.clone(),
                    registered_at_height: finalized_height,
                };
                record
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                state_transaction
                    .world
                    .musubi_provider_bundle_attestations
                    .insert(key, record.clone());
                emit_musubi_event(
                    MusubiEvent::ProviderBundleAttestationRegistered(
                        MusubiProviderBundleAttestationRegisteredEventV1 {
                            key,
                            attestation_digest: record.attestation_digest,
                            registered_by: authority.clone(),
                            finalized_height,
                        },
                    ),
                    state_transaction,
                );
                Ok(())
            },
        )
    }
}
impl Execute for AddMusubiArchiveLocationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::ArchiveLocation,
            |state_transaction, rejection_reason| {
                self.validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let mut archive = state_transaction
                    .world
                    .musubi_archives
                    .get(&self.archive_id)
                    .cloned()
                    .ok_or_else(|| archive_not_found(self.archive_id))?;
                archive
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                if archive.archive_id != self.archive_id {
                    return Err(invariant(
                        "Musubi archive location request resolved the wrong archive record",
                    ));
                }
                ensure_archive_manager(
                    &archive,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                let key = MusubiArchiveLocationKeyV1::new(self.archive_id, self.location_id);
                let existing_location = state_transaction
                    .world
                    .musubi_archive_locations
                    .get(&key)
                    .cloned();
                match existing_location.as_ref() {
                    Some(existing) if existing.state == MusubiArchiveLocationStateV1::Retired => {
                        return Err(invariant(
                            "Musubi retired archive location identities cannot be reused",
                        ));
                    }
                    Some(existing) => {
                        if existing.key() != key {
                            return Err(invariant(
                                "Musubi archive location record has the wrong embedded identity",
                            ));
                        }
                        if archive
                            .location_ids
                            .binary_search(&self.location_id)
                            .is_err()
                        {
                            return Err(invariant(
                                "Musubi archive location directory is inconsistent",
                            ));
                        }
                        if archive.location_ids.len() > MUSUBI_MAX_ARCHIVE_LOCATIONS_V1 {
                            return Err(invariant("Musubi archive location bound is exhausted"));
                        }
                        // A committed response may be lost. Match only the fields supplied by
                        // this instruction so later lifecycle state/revision changes do not turn
                        // an exact retry into a renewal. The no-op path still validates every
                        // active reverse projection and immutable provider evidence before it
                        // returns without consuming another CAS revision or emitting an event.
                        if existing.pin_manifest == self.pin_manifest
                            && existing.replication_order == self.replication_order
                            && existing.provider_attestation_set_digest
                                == self.provider_attestation_set_digest
                            && existing.renew_after_epoch == self.renew_after_epoch
                            && existing.expires_at_epoch == self.expires_at_epoch
                        {
                            validate_exact_archive_location_replay(
                                &archive,
                                existing,
                                state_transaction,
                            )?;
                            return Ok(());
                        }
                    }
                    None => {}
                }
                classify_governance_rejection(
                    ensure_revision(
                        "archive location",
                        archive.location_revision,
                        self.expected_location_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if existing_location.is_none() {
                    if archive.location_ids.len() >= MUSUBI_MAX_ARCHIVE_LOCATIONS_V1 {
                        return Err(invariant("Musubi archive location bound is exhausted"));
                    }
                    archive.location_ids.push(self.location_id);
                    archive.location_ids.sort();
                    archive.location_ids.dedup();
                }
                if archive.location_ids.len() > MUSUBI_MAX_ARCHIVE_LOCATIONS_V1 {
                    return Err(invariant("Musubi archive location bound is exhausted"));
                }
                let providers = validate_sorafs_location(
                    &archive,
                    &self.pin_manifest,
                    &self.replication_order,
                    self.provider_attestation_set_digest,
                    self.expires_at_epoch,
                    state_transaction,
                )?;
                let next_revision = next_revision(archive.location_revision, "archive location")?;
                let state = if providers.len() >= usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1) {
                    MusubiArchiveLocationStateV1::Healthy
                } else {
                    MusubiArchiveLocationStateV1::Degraded
                };
                let location = MusubiArchiveLocationV1 {
                    location_id: self.location_id,
                    archive_id: self.archive_id,
                    pin_manifest: self.pin_manifest,
                    replication_order: self.replication_order,
                    providers,
                    provider_attestation_set_digest: self.provider_attestation_set_digest,
                    renew_after_epoch: self.renew_after_epoch,
                    expires_at_epoch: self.expires_at_epoch,
                    finalized_height: execution_height(state_transaction),
                    revision: next_revision,
                    state,
                };
                location
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let provider_count = u8::try_from(location.providers.len()).map_err(|_| {
                    invariant("Musubi archive location provider count overflows u8")
                })?;
                let location_event = MusubiArchiveLocationEventV1 {
                    location: key,
                    pin_manifest: location.pin_manifest,
                    replication_order: location.replication_order,
                    provider_attestation_set_digest: location.provider_attestation_set_digest,
                    provider_count,
                    transition: if existing_location.is_some() {
                        MusubiArchiveLocationTransitionV1::Renewed
                    } else {
                        MusubiArchiveLocationTransitionV1::Added
                    },
                    state: location.state,
                    revision: location.revision,
                    finalized_height: location.finalized_height,
                };
                bind_location_reverse_indices(
                    existing_location.as_ref(),
                    &location,
                    state_transaction,
                )?;
                archive.location_revision = next_revision;
                archive
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                state_transaction
                    .world
                    .musubi_archive_locations
                    .insert(key, location);
                state_transaction
                    .world
                    .musubi_archives
                    .insert(self.archive_id, archive);
                emit_musubi_event(
                    MusubiEvent::ArchiveLocationChanged(location_event),
                    state_transaction,
                );
                refresh_musubi_locations(&[key], state_transaction)?;
                Ok(())
            },
        )
    }
}
impl Execute for RetireMusubiArchiveLocationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::ArchiveLocation,
            |state_transaction, rejection_reason| {
                let mut archive = state_transaction
                    .world
                    .musubi_archives
                    .get(&self.archive_id)
                    .cloned()
                    .ok_or_else(|| archive_not_found(self.archive_id))?;
                ensure_archive_manager(
                    &archive,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                classify_governance_rejection(
                    ensure_revision(
                        "archive location",
                        archive.location_revision,
                        self.expected_location_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let key = MusubiArchiveLocationKeyV1::new(self.archive_id, self.location_id);
                let mut location = state_transaction
                    .world
                    .musubi_archive_locations
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi archive location was not found"))?;
                if location.state == MusubiArchiveLocationStateV1::Retired {
                    return Err(invariant("Musubi archive location is already retired"));
                }
                ensure_locations_may_be_invalidated(&[key], state_transaction.world())?;
                self.reason
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let next_revision = next_revision(archive.location_revision, "archive location")?;
                location.state = MusubiArchiveLocationStateV1::Retired;
                location.finalized_height = execution_height(state_transaction);
                location.revision = next_revision;
                retire_location_reverse_indices(&location, state_transaction)?;
                let location_event = MusubiArchiveLocationEventV1 {
                    location: key,
                    pin_manifest: location.pin_manifest,
                    replication_order: location.replication_order,
                    provider_attestation_set_digest: location.provider_attestation_set_digest,
                    provider_count: u8::try_from(location.providers.len()).map_err(|_| {
                        invariant("Musubi archive location provider count overflows u8")
                    })?,
                    transition: MusubiArchiveLocationTransitionV1::Retired,
                    state: location.state,
                    revision: location.revision,
                    finalized_height: location.finalized_height,
                };
                archive.location_revision = next_revision;
                archive
                    .location_ids
                    .retain(|location_id| *location_id != self.location_id);
                archive
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                state_transaction
                    .world
                    .musubi_archive_locations
                    .insert(key, location);
                state_transaction
                    .world
                    .musubi_archives
                    .insert(self.archive_id, archive);
                emit_musubi_event(
                    MusubiEvent::ArchiveLocationChanged(location_event),
                    state_transaction,
                );
                refresh_archive_availability(self.archive_id, state_transaction)?;
                Ok(())
            },
        )
    }
}
impl Execute for PublishMusubiReleaseV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Publish,
            |state_transaction, rejection_reason| {
                self.namespace
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                self.publication
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let release_id = self.publication.manifest.release.clone();
                let release_digest = self.publication.manifest.release_digest();
                if let Some(existing) = state_transaction.world.musubi_releases.get(&release_id) {
                    if existing.release_digest != release_digest
                        || existing.manifest != self.publication.manifest
                        || state_transaction
                            .world
                            .musubi_packages
                            .get(&release_id.package)
                            .is_none_or(|package| package.claimed_namespace != self.namespace)
                    {
                        return Err(invariant(format!(
                            "Musubi release '{release_id}' is permanently bound to different commitments"
                        )));
                    }
                    if existing.published_by != *authority {
                        return reject_governance_mutation(
                            rejection_reason,
                            MusubiGovernanceRejectionReasonV1::Unauthorized,
                            invariant(
                                "only the original Musubi release publisher may replay publication",
                            ),
                        );
                    }
                    return Ok(());
                }
                let policy = state_transaction.world.musubi_registry_policy.get().clone();
                classify_governance_rejection(
                    ensure_policy_revision(&policy, self.expected_policy_revision),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                ensure_admitted(
                    &policy,
                    Some(release_id.package.home_dataspace),
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                validate_publication_snapshot(&self.publication, state_transaction)?;
                validate_resolution_proof(
                    &self.publication,
                    state_transaction.world(),
                    state_transaction.block_hashes(),
                )?;
                let archive = state_transaction
                    .world
                    .musubi_archives
                    .get(&self.publication.manifest.archive_id)
                    .cloned()
                    .ok_or_else(|| archive_not_found(self.publication.manifest.archive_id))?;
                let availability = state_transaction
                    .world
                    .musubi_archive_availability
                    .get(&archive.archive_id)
                    .copied()
                    .ok_or_else(|| invariant("Musubi archive has no availability projection"))?;
                if availability.availability != MusubiStorageAvailabilityV1::Selectable {
                    return Err(invariant(
                        "Musubi release archive has not reached finalized replication quorum",
                    ));
                }
                validate_publication_archive_evidence(
                    &self.publication,
                    &archive,
                    authority,
                    state_transaction.world(),
                )?;
                let height = execution_height(state_transaction);
                let existing_package = state_transaction
                    .world
                    .musubi_packages
                    .get(&release_id.package)
                    .cloned();
                let first_claim = existing_package.is_none();
                let (package, governance_advance, first_member, first_metadata) =
                    match existing_package {
                        Some(mut package) => {
                            if package.claimed_namespace != self.namespace {
                                return Err(invariant(
                                    "Musubi publication namespace does not match the package claim",
                                ));
                            }
                            let expected = self.expected_governance_revision.ok_or_else(|| {
                        invalid_parameter(
                            "existing Musubi package publication requires a governance revision",
                        )
                    })?;
                            classify_governance_rejection(
                                ensure_revision(
                                    "package governance",
                                    package.revisions.governance,
                                    expected,
                                ),
                                rejection_reason,
                                MusubiGovernanceRejectionReasonV1::StaleRevision,
                            )?;
                            ensure_package_capability(
                                &release_id.package,
                                authority,
                                PackageCapability::Publish,
                                state_transaction.world(),
                                rejection_reason,
                            )?;
                            let advance = plan_package_governance_advance(
                                &mut package,
                                height,
                                None,
                                state_transaction.world(),
                            )?;
                            (package, Some(advance), None, None)
                        }
                        None => {
                            if self.expected_governance_revision.is_some() {
                                return Err(invalid_parameter(
                                    "first Musubi package claim must not supply a governance revision",
                                ));
                            }
                            let binding = namespace_binding_for_package(
                                &self.namespace,
                                &release_id.package,
                                state_transaction.world(),
                            )?;
                            ensure_namespace_claim_authority(
                                &binding,
                                self.namespace_delegation.as_ref(),
                                authority,
                                state_transaction,
                                rejection_reason,
                            )
                            .map_err(|error| namespace_attempt_error(error, state_transaction))?;
                            let package = MusubiPackageRecordV1 {
                                package: release_id.package.clone(),
                                claimed_namespace: self.namespace,
                                claimed_namespace_binding: binding.digest(),
                                owners: vec![authority.clone()],
                                member_accounts: vec![authority.clone()],
                                claimed_at_height: height,
                                revisions: MusubiPackageRevisionsV1 {
                                    governance: 1,
                                    metadata: 1,
                                    archive_locations: 1,
                                },
                            };
                            let member = MusubiPackageMemberV1 {
                                package: release_id.package.clone(),
                                account: authority.clone(),
                                role: MusubiPackageRoleV1::Owner,
                                accepted_at_height: height,
                                governance_revision: 1,
                            };
                            member
                                .validate()
                                .map_err(|error| invariant(error.reason()))?;
                            let metadata = MusubiPackageMetadataRecordV1 {
                                package: release_id.package.clone(),
                                metadata: self.publication.manifest.metadata.clone(),
                                revision: 1,
                                changed_by: authority.clone(),
                                changed_at_height: height,
                            };
                            metadata
                                .validate()
                                .map_err(|error| invariant(error.reason()))?;
                            (package, None, Some(member), Some(metadata))
                        }
                    };
                package
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let initial_reason = MusubiReasonV1::new("initial publication")
                    .expect("static Musubi reason is valid");
                let yank = MusubiReleaseYankV1 {
                    release: release_id.clone(),
                    yanked: false,
                    reason: initial_reason,
                    changed_by: authority.clone(),
                    changed_at_height: height,
                    revision: 1,
                };
                let record = MusubiReleaseRecordV1 {
                    manifest: self.publication.manifest.clone(),
                    release_digest,
                    published_by: authority.clone(),
                    published_at_height: height,
                    yank: yank.clone(),
                    artifact_governance: MusubiArtifactGovernanceStateV1::Available,
                    revisions: MusubiReleaseRevisionsV1 {
                        yank: 1,
                        artifact_governance: 1,
                    },
                };
                record
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let planned_index_revision = plan_resolver_index_revision(state_transaction)?;
                let index_revision = planned_index_revision.get();
                let reverse_references = plan_archive_reverse_reference(
                    archive.archive_id,
                    release_id.clone(),
                    state_transaction.world(),
                )?;
                let latest_selectable = state_transaction
                    .world
                    .musubi_resolver_index
                    .range(package_release_start(&release_id.package)..)
                    .take_while(|(release, _)| release.package == release_id.package)
                    .filter(|(_, row)| row.selection.fresh_selectable())
                    .map(|(release, _)| release.version.clone())
                    .chain(std::iter::once(release_id.version.clone()))
                    .max();
                let directory =
                    plan_package_directory_entry(&package, latest_selectable, index_revision)?;
                let row = MusubiResolverReleaseRowV1 {
                    release: release_id.clone(),
                    release_digest,
                    archive_id: archive.archive_id,
                    source_digest: archive.commitment.source_tree_digest,
                    interface_digest: self.publication.manifest.interface_digest,
                    abi: self.publication.manifest.abi,
                    dependencies: self.publication.manifest.dependencies,
                    selection: MusubiReleaseSelectionStateV1 {
                        yank,
                        storage: availability,
                        governance: MusubiArtifactGovernanceStateV1::Available,
                    },
                    index_revision,
                };
                row.validate().map_err(|error| invariant(error.reason()))?;
                let package_claimed_event = first_claim.then(|| {
                    MusubiEvent::PackageClaimed(MusubiPackageClaimedEventV1 {
                        package: release_id.package.clone(),
                        namespace: package.claimed_namespace.clone(),
                        claimed_by: authority.clone(),
                        governance_revision: package.revisions.governance,
                        finalized_height: height,
                    })
                });
                let metadata_event = first_metadata
                    .clone()
                    .map(MusubiEvent::PackageMetadataChanged);
                *state_transaction
                    .world
                    .musubi_resolver_index_revision
                    .get_mut() = planned_index_revision;
                if let Some(member) = first_member {
                    state_transaction
                        .world
                        .musubi_package_members
                        .insert(member.key(), member.clone());
                    upsert_maintainer_directory(
                        MusubiMaintainerDirectoryEntryV1::Accepted(member),
                        state_transaction,
                    );
                }
                if let Some(metadata) = first_metadata {
                    state_transaction
                        .world
                        .musubi_package_metadata
                        .insert(metadata.package.clone(), metadata);
                }
                state_transaction
                    .world
                    .musubi_packages
                    .insert(release_id.package.clone(), package);
                state_transaction
                    .world
                    .musubi_releases
                    .insert(release_id.clone(), record);
                state_transaction
                    .world
                    .musubi_archive_reverse_references
                    .insert(archive.archive_id, reverse_references);
                state_transaction
                    .world
                    .musubi_resolver_index
                    .insert(release_id.clone(), row);
                state_transaction
                    .world
                    .musubi_public_directory
                    .insert(directory.selector.clone(), directory);
                if let Some(event) = package_claimed_event {
                    emit_musubi_event(event, state_transaction);
                }
                if let Some(event) = metadata_event {
                    emit_musubi_event(event, state_transaction);
                }
                if let Some(advance) = governance_advance {
                    advance.apply_invitation_updates(state_transaction);
                    for event in advance.invitation_events {
                        emit_musubi_event(event, state_transaction);
                    }
                }
                emit_musubi_event(
                    MusubiEvent::ReleasePublished(MusubiReleasePublishedEventV1 {
                        release: release_id,
                        release_digest,
                        archive_id: archive.archive_id,
                        published_by: authority.clone(),
                        finalized_height: height,
                    }),
                    state_transaction,
                );
                Ok(())
            },
        )
    }
}
impl Execute for SetMusubiReleaseYankV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Yank,
            |state_transaction, rejection_reason| {
                self.release
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                self.reason
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let mut release = state_transaction
                    .world
                    .musubi_releases
                    .get(&self.release)
                    .cloned()
                    .ok_or_else(|| release_not_found(&self.release))?;
                ensure_package_capability(
                    &self.release.package,
                    authority,
                    PackageCapability::Yank,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                classify_governance_rejection(
                    ensure_revision(
                        "release yank",
                        release.revisions.yank,
                        self.expected_yank_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if release.yank.yanked == self.yanked {
                    return Err(invariant("Musubi release yank state is unchanged"));
                }
                let next = next_revision(release.revisions.yank, "release yank")?;
                release.yank = MusubiReleaseYankV1 {
                    release: self.release.clone(),
                    yanked: self.yanked,
                    reason: self.reason,
                    changed_by: authority.clone(),
                    changed_at_height: execution_height(state_transaction),
                    revision: next,
                };
                release.revisions.yank = next;
                let index_revision = bump_resolver_index_revision(state_transaction)?;
                let mut row = state_transaction
                    .world
                    .musubi_resolver_index
                    .get(&self.release)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi release is absent from the resolver index"))?;
                row.selection.yank = release.yank.clone();
                row.index_revision = index_revision;
                release
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                row.validate().map_err(|error| invariant(error.reason()))?;
                let event = MusubiEvent::ReleaseYankChanged(MusubiReleaseYankEventV1 {
                    yank: release.yank.clone(),
                    archive_id: release.manifest.archive_id,
                });
                state_transaction
                    .world
                    .musubi_releases
                    .insert(self.release.clone(), release);
                state_transaction
                    .world
                    .musubi_resolver_index
                    .insert(self.release.clone(), row);
                refresh_directory_for_package(
                    &self.release.package,
                    index_revision,
                    state_transaction,
                )?;
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for SetMusubiPackageMetadataV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Metadata,
            |state_transaction, rejection_reason| {
                self.metadata
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                ensure_package_capability(
                    &self.package,
                    authority,
                    PackageCapability::Metadata,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                classify_governance_rejection(
                    ensure_revision(
                        "package metadata",
                        package.revisions.metadata,
                        self.expected_metadata_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let next = next_revision(package.revisions.metadata, "package metadata")?;
                package.revisions.metadata = next;
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package.clone(), package);
                let metadata = MusubiPackageMetadataRecordV1 {
                    package: self.package.clone(),
                    metadata: self.metadata,
                    revision: next,
                    changed_by: authority.clone(),
                    changed_at_height: execution_height(state_transaction),
                };
                state_transaction
                    .world
                    .musubi_package_metadata
                    .insert(self.package.clone(), metadata.clone());
                let index_revision = bump_resolver_index_revision(state_transaction)?;
                refresh_directory_for_package(&self.package, index_revision, state_transaction)?;
                emit_musubi_event(
                    MusubiEvent::PackageMetadataChanged(metadata),
                    state_transaction,
                );
                Ok(())
            },
        )
    }
}
impl Execute for InviteMusubiPackageMaintainerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Invite,
            |state_transaction, rejection_reason| {
                validate_role(self.role)?;
                ensure_package_owner(
                    &self.package,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let height = execution_height(state_transaction);
                if self.expires_at_height <= height {
                    return Err(invalid_parameter(
                        "Musubi package invitation expiry must be in the future",
                    ));
                }
                if package
                    .member_accounts
                    .binary_search(&self.invited_account)
                    .is_ok()
                {
                    return Err(invariant(
                        "Musubi package invitation targets an existing member",
                    ));
                }
                if state_transaction
                    .world
                    .musubi_package_invitations
                    .get(&self.invite_id)
                    .is_some()
                {
                    return Err(invariant("Musubi package invitation id is already used"));
                }
                let active_pending = active_pending_invitation_count(
                    &self.package,
                    height,
                    state_transaction.world(),
                );
                if active_pending >= MUSUBI_MAX_PENDING_INVITATIONS_V1 {
                    return Err(invariant(
                        "Musubi package pending-invitation bound is exhausted",
                    ));
                }
                let next = next_revision(package.revisions.governance, "package governance")?;
                let invitation = MusubiMaintainerInvitationV1 {
                    invite_id: self.invite_id,
                    package: self.package.clone(),
                    invited_by: authority.clone(),
                    invited_account: self.invited_account,
                    role: self.role,
                    expected_governance_revision: next,
                    expires_at_height: self.expires_at_height,
                    state: MusubiInvitationStateV1::Pending,
                };
                invitation
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    None,
                    state_transaction.world(),
                )?;
                let event = MusubiEvent::MaintainerInvited(invitation.clone());
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                advance.apply_invitation_updates(state_transaction);
                state_transaction
                    .world
                    .musubi_package_invitations
                    .insert(self.invite_id, invitation.clone());
                upsert_maintainer_directory(
                    MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation),
                    state_transaction,
                );
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for AcceptMusubiPackageMaintainerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Accept,
            |state_transaction, rejection_reason| {
                let invitation = state_transaction
                    .world
                    .musubi_package_invitations
                    .get(&self.invite_id)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi package invitation was not found"))?;
                if invitation.package != self.package
                    || invitation.invited_account != *authority
                    || invitation.state != MusubiInvitationStateV1::Pending
                {
                    if invitation.invited_account != *authority {
                        *rejection_reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
                    }
                    return Err(invariant(
                        "Musubi package invitation is not pending for this authority",
                    ));
                }
                if execution_height(state_transaction) > invitation.expires_at_height {
                    return Err(invariant(
                        "Musubi package invitation has expired; the next successful package governance mutation commits bounded expiry cleanup",
                    ));
                }
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                classify_governance_rejection(
                    ensure_revision(
                        "package invitation",
                        invitation.expected_governance_revision,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if package.member_accounts.binary_search(authority).is_ok() {
                    return Err(invariant(
                        "Musubi package invitation targets an existing member",
                    ));
                }
                if package.member_accounts.len() >= MUSUBI_MAX_PACKAGE_MEMBERS_V1 {
                    return Err(invariant("Musubi package member bound is exhausted"));
                }
                let maintainer_count = package
                    .member_accounts
                    .len()
                    .saturating_sub(package.owners.len());
                if matches!(invitation.role, MusubiPackageRoleV1::Maintainer(_))
                    && maintainer_count >= MUSUBI_MAX_PACKAGE_MAINTAINERS_V1
                {
                    return Err(invariant("Musubi package maintainer bound is exhausted"));
                }
                if invitation.role == MusubiPackageRoleV1::Owner
                    && package.owners.len() >= MUSUBI_MAX_PACKAGE_OWNERS_V1
                {
                    return Err(invariant("Musubi package owner bound is exhausted"));
                }
                let height = execution_height(state_transaction);
                if invitation.role == MusubiPackageRoleV1::Owner {
                    package.owners.push(authority.clone());
                    package.owners.sort();
                    package.owners.dedup();
                }
                package.member_accounts.push(authority.clone());
                package.member_accounts.sort();
                package.member_accounts.dedup();
                package
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    Some((self.invite_id, MusubiInvitationStateV1::Accepted)),
                    state_transaction.world(),
                )?;
                let next = advance.revision;
                let invitation = advance
                    .terminal_invitation
                    .clone()
                    .ok_or_else(|| invariant("Musubi accepted invitation was not terminalized"))?;
                let member = MusubiPackageMemberV1 {
                    package: self.package.clone(),
                    account: authority.clone(),
                    role: invitation.role,
                    accepted_at_height: height,
                    governance_revision: next,
                };
                state_transaction.world.musubi_package_members.insert(
                    MusubiPackageMemberKeyV1::new(self.package.clone(), authority.clone()),
                    member.clone(),
                );
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                advance.apply_invitation_updates(state_transaction);
                upsert_maintainer_directory(
                    MusubiMaintainerDirectoryEntryV1::Accepted(member.clone()),
                    state_transaction,
                );
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(MusubiEvent::MaintainerAccepted(member), state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RevokeMusubiPackageMaintainerInvitationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Invite,
            |state_transaction, rejection_reason| {
                ensure_package_owner(
                    &self.package,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let invitation = state_transaction
                    .world
                    .musubi_package_invitations
                    .get(&self.invite_id)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi package invitation was not found"))?;
                if invitation.package != self.package
                    || invitation.state != MusubiInvitationStateV1::Pending
                {
                    return Err(invariant(
                        "Musubi package invitation is not pending for this package",
                    ));
                }
                let height = execution_height(state_transaction);
                if height > invitation.expires_at_height {
                    return Err(invariant(
                        "Musubi package invitation has expired; the next successful package governance mutation commits bounded expiry cleanup",
                    ));
                }
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    Some((self.invite_id, MusubiInvitationStateV1::Revoked)),
                    state_transaction.world(),
                )?;
                let next = advance.revision;
                let invitation = advance
                    .terminal_invitation
                    .clone()
                    .ok_or_else(|| invariant("Musubi revoked invitation was not terminalized"))?;
                let event = MusubiEvent::MaintainerInvitationRevoked(
                    MusubiMaintainerInvitationLifecycleEventV1 {
                        package: self.package.clone(),
                        invite_id: self.invite_id,
                        invited_account: invitation.invited_account.clone(),
                        governance_revision: next,
                        finalized_height: height,
                    },
                );
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                advance.apply_invitation_updates(state_transaction);
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for SetMusubiPackageMaintainerRoleV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::SetRole,
            |state_transaction, rejection_reason| {
                validate_role(self.role)?;
                ensure_package_owner(
                    &self.package,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let key = MusubiPackageMemberKeyV1::new(self.package.clone(), self.account.clone());
                let mut member = state_transaction
                    .world
                    .musubi_package_members
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi package member was not found"))?;
                if member.role == self.role {
                    return Err(invariant("Musubi package member role is unchanged"));
                }
                if member.role == MusubiPackageRoleV1::Owner
                    && self.role != MusubiPackageRoleV1::Owner
                    && package.owners.len() == 1
                {
                    return reject_governance_mutation(
                        rejection_reason,
                        MusubiGovernanceRejectionReasonV1::LastOwner,
                        invariant("Musubi package must retain its last owner"),
                    );
                }
                if member.role != MusubiPackageRoleV1::Owner
                    && self.role == MusubiPackageRoleV1::Owner
                    && package.owners.len() >= MUSUBI_MAX_PACKAGE_OWNERS_V1
                {
                    return Err(invariant("Musubi package owner bound is exhausted"));
                }
                if member.role == MusubiPackageRoleV1::Owner
                    && matches!(self.role, MusubiPackageRoleV1::Maintainer(_))
                    && package
                        .member_accounts
                        .len()
                        .saturating_sub(package.owners.len())
                        >= MUSUBI_MAX_PACKAGE_MAINTAINERS_V1
                {
                    return Err(invariant("Musubi package maintainer bound is exhausted"));
                }
                let height = execution_height(state_transaction);
                package.owners.retain(|owner| owner != &self.account);
                if self.role == MusubiPackageRoleV1::Owner {
                    package.owners.push(self.account.clone());
                    package.owners.sort();
                    package.owners.dedup();
                }
                package
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    None,
                    state_transaction.world(),
                )?;
                let next = advance.revision;
                member.role = self.role;
                member.governance_revision = next;
                let event = MusubiEvent::MaintainerRoleChanged(member.clone());
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                state_transaction
                    .world
                    .musubi_package_members
                    .insert(key, member.clone());
                upsert_maintainer_directory(
                    MusubiMaintainerDirectoryEntryV1::Accepted(member),
                    state_transaction,
                );
                advance.apply_invitation_updates(state_transaction);
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RemoveMusubiPackageMaintainerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Remove,
            |state_transaction, rejection_reason| {
                ensure_package_owner(
                    &self.package,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let key = MusubiPackageMemberKeyV1::new(self.package.clone(), self.account.clone());
                let member = state_transaction
                    .world
                    .musubi_package_members
                    .get(&key)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi package member was not found"))?;
                let directory_key = MusubiMaintainerDirectoryKeyV1::accepted(
                    member.package.clone(),
                    member.account.clone(),
                );
                if member.role == MusubiPackageRoleV1::Owner && package.owners.len() == 1 {
                    return reject_governance_mutation(
                        rejection_reason,
                        MusubiGovernanceRejectionReasonV1::LastOwner,
                        invariant("Musubi package must retain its last owner"),
                    );
                }
                package.owners.retain(|owner| owner != &self.account);
                package
                    .member_accounts
                    .retain(|account| account != &self.account);
                let height = execution_height(state_transaction);
                package
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    None,
                    state_transaction.world(),
                )?;
                let next = advance.revision;
                let event = MusubiEvent::MaintainerRemoved(MusubiPackageMemberRemovedEventV1 {
                    package: self.package.clone(),
                    account: self.account.clone(),
                    previous_role: member.role,
                    governance_revision: next,
                    finalized_height: height,
                });
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                state_transaction.world.musubi_package_members.remove(key);
                state_transaction
                    .world
                    .musubi_maintainer_directory
                    .remove(directory_key);
                advance.apply_invitation_updates(state_transaction);
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RegisterMusubiAliasV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Alias,
            |state_transaction, rejection_reason| {
                self.alias
                    .validate()
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let existing = state_transaction
                    .world
                    .musubi_aliases
                    .get(&self.alias)
                    .cloned();
                if existing
                    .as_ref()
                    .is_some_and(|record| record.target != self.target)
                {
                    return Err(invariant(format!(
                        "Musubi alias '{}' is permanent and already registered",
                        self.alias
                    )));
                }
                if existing.is_some() {
                    ensure_package_owner(
                        &self.target,
                        authority,
                        state_transaction.world(),
                        rejection_reason,
                    )?;
                    return Ok(());
                }
                let policy = state_transaction.world.musubi_registry_policy.get().clone();
                ensure_admitted(
                    &policy,
                    Some(self.target.home_dataspace),
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                if policy.alias_pricing.revision != self.expected_pricing_revision {
                    return reject_governance_mutation(
                        rejection_reason,
                        MusubiGovernanceRejectionReasonV1::Payment,
                        stale_revision(
                            "alias pricing",
                            policy.alias_pricing.revision,
                            self.expected_pricing_revision,
                        ),
                    );
                }
                ensure_package_owner(
                    &self.target,
                    authority,
                    state_transaction.world(),
                    rejection_reason,
                )?;
                if !package_has_active_release(&self.target, state_transaction.world()) {
                    return Err(invariant(
                        "Musubi alias target must have at least one active release",
                    ));
                }
                let price = policy.alias_pricing.price_for(&self.alias);
                let source = AssetId::new(
                    state_transaction.gov.sorafs_pin_fee_asset_id.clone(),
                    authority.clone(),
                );
                let treasury = state_transaction
                    .gov
                    .sorafs_pin_fee_treasury_account
                    .clone();
                classify_governance_rejection(
                    crate::smartcontracts::isi::asset::isi::execute_user_numeric_asset_transfer(
                        state_transaction,
                        authority,
                        source,
                        treasury,
                        Quantity::from(price),
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::Payment,
                )?;
                let height = execution_height(state_transaction);
                let record = MusubiAliasRecordV1 {
                    alias: self.alias.clone(),
                    target: self.target.clone(),
                    registered_by: authority.clone(),
                    pricing_revision: policy.alias_pricing.revision,
                    paid_xor: price,
                    registered_at_height: height,
                    history_revision: 1,
                };
                record
                    .validate(&policy.alias_pricing)
                    .map_err(|error| invariant(error.reason()))?;
                state_transaction
                    .world
                    .musubi_aliases
                    .insert(self.alias.clone(), record);
                let history = MusubiAliasHistoryEntryV1 {
                    alias: self.alias,
                    revision: 1,
                    action: MusubiAliasHistoryActionV1::Registered,
                    previous_target: None,
                    target: self.target,
                    governance_action: None,
                    finalized_height: height,
                };
                let event = MusubiEvent::AliasRegistered(history.clone());
                state_transaction
                    .world
                    .musubi_alias_history
                    .insert(history.key(), history);
                let _ = bump_resolver_index_revision(state_transaction)?;
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RecoverMusubiPackageV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Recovery,
            |state_transaction, rejection_reason| {
                let action =
                    MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
                        package: self.package.clone(),
                        owners: self.owners.clone(),
                        expected_revision: self.expected_governance_revision,
                    });
                verify_parliament_decision(
                    &self.decision,
                    &action,
                    state_transaction,
                    rejection_reason,
                )?;
                let mut package = state_transaction
                    .world
                    .musubi_packages
                    .get(&self.package)
                    .cloned()
                    .ok_or_else(|| package_not_found(&self.package))?;
                classify_governance_rejection(
                    ensure_revision(
                        "package governance",
                        package.revisions.governance,
                        self.expected_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                let height = execution_height(state_transaction);
                let existing_members = package
                    .member_accounts
                    .iter()
                    .map(|account| {
                        let key =
                            MusubiPackageMemberKeyV1::new(self.package.clone(), account.clone());
                        let member = state_transaction
                            .world
                            .musubi_package_members
                            .get(&key)
                            .cloned()
                            .ok_or_else(|| {
                                invariant("Musubi package member directory is inconsistent")
                            })?;
                        Ok((key, member))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                for (_, member) in &existing_members {
                    if member.role == MusubiPackageRoleV1::Owner
                        && !self.owners.contains(&member.account)
                    {
                        package
                            .member_accounts
                            .retain(|account| account != &member.account);
                    }
                }
                for owner in &self.owners {
                    if package.member_accounts.binary_search(owner).is_err() {
                        package.member_accounts.push(owner.clone());
                        package.member_accounts.sort();
                        package.member_accounts.dedup();
                    }
                }
                package.owners = self.owners;
                package
                    .validate()
                    .map_err(|error| invariant(error.reason()))?;
                let advance = plan_package_governance_advance(
                    &mut package,
                    height,
                    None,
                    state_transaction.world(),
                )?;
                let next = advance.revision;
                let owner_count = u8::try_from(package.owners.len())
                    .map_err(|_| invariant("Musubi package owner count overflows u8"))?;
                let event = MusubiEvent::PackageRecovered(MusubiPackageRecoveredEventV1 {
                    package: self.package.clone(),
                    action_digest: self.decision.action_digest,
                    owner_count,
                    governance_revision: next,
                    finalized_height: height,
                });
                consume_parliament_decision(self.decision, state_transaction)?;
                for (key, member) in existing_members {
                    if member.role == MusubiPackageRoleV1::Owner
                        && !package.owners.contains(&member.account)
                    {
                        state_transaction.world.musubi_package_members.remove(key);
                        state_transaction.world.musubi_maintainer_directory.remove(
                            MusubiMaintainerDirectoryKeyV1::accepted(
                                member.package,
                                member.account,
                            ),
                        );
                    }
                }
                for owner in &package.owners {
                    let member = MusubiPackageMemberV1 {
                        package: self.package.clone(),
                        account: owner.clone(),
                        role: MusubiPackageRoleV1::Owner,
                        accepted_at_height: height,
                        governance_revision: next,
                    };
                    state_transaction.world.musubi_package_members.insert(
                        MusubiPackageMemberKeyV1::new(self.package.clone(), owner.clone()),
                        member.clone(),
                    );
                    upsert_maintainer_directory(
                        MusubiMaintainerDirectoryEntryV1::Accepted(member),
                        state_transaction,
                    );
                }
                state_transaction
                    .world
                    .musubi_packages
                    .insert(self.package, package);
                advance.apply_invitation_updates(state_transaction);
                for event in advance.invitation_events {
                    emit_musubi_event(event, state_transaction);
                }
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for RetargetMusubiAliasV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Alias,
            |state_transaction, rejection_reason| {
                let action = MusubiParliamentActionV1::RetargetAlias(MusubiRetargetAliasV1 {
                    alias: self.alias.clone(),
                    target: self.target.clone(),
                    expected_revision: self.expected_history_revision,
                });
                verify_parliament_decision(
                    &self.decision,
                    &action,
                    state_transaction,
                    rejection_reason,
                )?;
                if state_transaction
                    .world
                    .musubi_packages
                    .get(&self.target)
                    .is_none()
                {
                    return Err(package_not_found(&self.target));
                }
                let mut alias = state_transaction
                    .world
                    .musubi_aliases
                    .get(&self.alias)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi alias was not found"))?;
                classify_governance_rejection(
                    ensure_revision(
                        "alias history",
                        alias.history_revision,
                        self.expected_history_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if alias.target == self.target {
                    return Err(invariant("Musubi alias retarget is unchanged"));
                }
                let next = next_revision(alias.history_revision, "alias history")?;
                let previous_target = alias.target.clone();
                alias.target = self.target.clone();
                alias.history_revision = next;
                state_transaction
                    .world
                    .musubi_aliases
                    .insert(self.alias.clone(), alias);
                let history = MusubiAliasHistoryEntryV1 {
                    alias: self.alias,
                    revision: next,
                    action: MusubiAliasHistoryActionV1::ParliamentRetarget,
                    previous_target: Some(previous_target),
                    target: self.target,
                    governance_action: Some(self.decision.action_digest),
                    finalized_height: execution_height(state_transaction),
                };
                let event = MusubiEvent::AliasRetargeted(history.clone());
                state_transaction
                    .world
                    .musubi_alias_history
                    .insert(history.key(), history);
                consume_parliament_decision(self.decision, state_transaction)?;
                let _ = bump_resolver_index_revision(state_transaction)?;
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for SetMusubiArtifactTakedownV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Takedown,
            |state_transaction, rejection_reason| {
                let action =
                    MusubiParliamentActionV1::TakedownArtifact(MusubiTakedownArtifactActionV1 {
                        release: self.release.clone(),
                        reason: self.reason.clone(),
                        expected_artifact_governance_revision: self
                            .expected_artifact_governance_revision,
                    });
                verify_parliament_decision(
                    &self.decision,
                    &action,
                    state_transaction,
                    rejection_reason,
                )?;
                let mut release = state_transaction
                    .world
                    .musubi_releases
                    .get(&self.release)
                    .cloned()
                    .ok_or_else(|| release_not_found(&self.release))?;
                classify_governance_rejection(
                    ensure_revision(
                        "artifact governance",
                        release.revisions.artifact_governance,
                        self.expected_artifact_governance_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                if !matches!(
                    release.artifact_governance,
                    MusubiArtifactGovernanceStateV1::Available
                ) {
                    return Err(invariant("Musubi artifact is already taken down"));
                }
                let next =
                    next_revision(release.revisions.artifact_governance, "artifact governance")?;
                let governance =
                    MusubiArtifactGovernanceStateV1::TakenDown(MusubiArtifactTakedownV1 {
                        action_digest: self.decision.action_digest,
                        reason: self.reason,
                        applied_at_height: execution_height(state_transaction),
                    });
                release.artifact_governance = governance.clone();
                release.revisions.artifact_governance = next;
                let event = MusubiEvent::ArtifactTakenDown(MusubiArtifactTakedownEventV1 {
                    release: self.release.clone(),
                    archive_id: release.manifest.archive_id,
                    action_digest: self.decision.action_digest,
                    governance_revision: next,
                    finalized_height: execution_height(state_transaction),
                });
                let index_revision = bump_resolver_index_revision(state_transaction)?;
                let mut row = state_transaction
                    .world
                    .musubi_resolver_index
                    .get(&self.release)
                    .cloned()
                    .ok_or_else(|| invariant("Musubi release is absent from the resolver index"))?;
                row.selection.governance = governance;
                row.index_revision = index_revision;
                state_transaction
                    .world
                    .musubi_releases
                    .insert(self.release.clone(), release);
                state_transaction
                    .world
                    .musubi_resolver_index
                    .insert(self.release.clone(), row);
                consume_parliament_decision(self.decision, state_transaction)?;
                refresh_directory_for_package(
                    &self.release.package,
                    index_revision,
                    state_transaction,
                )?;
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for SetMusubiRegistryPolicyV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_governance_mutation(
            state_transaction,
            MusubiGovernanceActionV1::Policy,
            |state_transaction, rejection_reason| {
                let action =
                    MusubiParliamentActionV1::SetRegistryPolicy(MusubiSetRegistryPolicyActionV1 {
                        policy: self.policy.clone(),
                        expected_revision: self.expected_policy_revision,
                    });
                verify_parliament_decision(
                    &self.decision,
                    &action,
                    state_transaction,
                    rejection_reason,
                )?;
                let current_policy = state_transaction.world.musubi_registry_policy.get().clone();
                classify_governance_rejection(
                    ensure_revision(
                        "registry policy",
                        current_policy.revision,
                        self.expected_policy_revision,
                    ),
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::StaleRevision,
                )?;
                self.policy
                    .validate_successor(&current_policy)
                    .map_err(|error| invalid_parameter(error.reason()))?;
                let allowlisted_dataspaces =
                    u16::try_from(self.policy.allowlisted_dataspaces.len())
                        .map_err(|_| invariant("Musubi registry allowlist count overflows u16"))?;
                let event = MusubiEvent::RegistryPolicyChanged(MusubiRegistryPolicyEventV1 {
                    revision: self.policy.revision,
                    mode: self.policy.mode,
                    alias_pricing_revision: self.policy.alias_pricing.revision,
                    allowlisted_dataspaces,
                    action_digest: self.decision.action_digest,
                    finalized_height: execution_height(state_transaction),
                });
                *state_transaction.world.musubi_registry_policy.get_mut() = self.policy;
                consume_parliament_decision(self.decision, state_transaction)?;
                let _ = bump_resolver_index_revision(state_transaction)?;
                emit_musubi_event(event, state_transaction);
                Ok(())
            },
        )
    }
}
impl Execute for AssertMusubiReleaseDigestV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let release = state_transaction
            .world
            .musubi_releases
            .get(&self.release)
            .ok_or_else(|| release_not_found(&self.release))?;
        if release.release_digest == self.expected_digest {
            Ok(())
        } else {
            Err(invariant(format!(
                "Musubi release '{}' digest assertion failed",
                self.release
            )))
        }
    }
}
include!("musubi/query_execution.rs");
fn upsert_maintainer_directory(
    entry: MusubiMaintainerDirectoryEntryV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) {
    state_transaction
        .world
        .musubi_maintainer_directory
        .insert(entry.key(), entry);
}
#[must_use = "a package-governance advance plan must be applied after fallible checks complete"]
struct PackageGovernanceAdvance {
    revision: u64,
    invitation_updates: Vec<PackageInvitationUpdate>,
    invitation_events: Vec<MusubiEvent>,
    terminal_invitation: Option<MusubiMaintainerInvitationV1>,
}
struct PackageInvitationUpdate {
    directory_key: MusubiMaintainerDirectoryKeyV1,
    invitation: MusubiMaintainerInvitationV1,
    keep_pending: bool,
}
impl PackageGovernanceAdvance {
    fn apply_invitation_updates(&self, state_transaction: &mut StateTransaction<'_, '_>) {
        for update in &self.invitation_updates {
            state_transaction
                .world
                .musubi_package_invitations
                .insert(update.invitation.invite_id, update.invitation.clone());
            if update.keep_pending {
                upsert_maintainer_directory(
                    MusubiMaintainerDirectoryEntryV1::PendingInvitation(update.invitation.clone()),
                    state_transaction,
                );
            } else {
                state_transaction
                    .world
                    .musubi_maintainer_directory
                    .remove(update.directory_key.clone());
            }
        }
    }
}
fn plan_package_governance_advance(
    package: &mut MusubiPackageRecordV1,
    finalized_height: u64,
    target_transition: Option<(MusubiInviteIdV1, MusubiInvitationStateV1)>,
    world: &impl WorldReadOnly,
) -> Result<PackageGovernanceAdvance, Error> {
    if target_transition.as_ref().is_some_and(|(_, state)| {
        !matches!(
            state,
            MusubiInvitationStateV1::Accepted | MusubiInvitationStateV1::Revoked
        )
    }) {
        return Err(invariant(
            "Musubi invitation target transition must be terminal",
        ));
    }
    let previous_revision = package.revisions.governance;
    let revision = next_revision(previous_revision, "package governance")?;
    let directory_bound = MUSUBI_MAX_PACKAGE_MEMBERS_V1
        .checked_add(MUSUBI_MAX_PENDING_INVITATIONS_V1)
        .expect("bounded Musubi maintainer directory size fits usize");
    let entries = world
        .musubi_maintainer_directory()
        .range(MusubiMaintainerDirectoryKeyV1::package_start(package.package.clone())..)
        .take_while(|(key, _)| key.package == package.package)
        .take(directory_bound.saturating_add(1))
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect::<Vec<_>>();
    if entries.len() > directory_bound {
        return Err(invariant(
            "Musubi maintainer directory exceeds its package-local bound",
        ));
    }
    let pending = entries
        .into_iter()
        .filter_map(|(key, entry)| match entry {
            MusubiMaintainerDirectoryEntryV1::Accepted(_) => None,
            MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation) => {
                Some((key, invitation))
            }
        })
        .collect::<Vec<_>>();
    if pending.len() > MUSUBI_MAX_PENDING_INVITATIONS_V1 {
        return Err(invariant(
            "Musubi package exceeds the pending-invitation bound",
        ));
    }
    for (directory_key, invitation) in &pending {
        invitation
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        let expected_key = MusubiMaintainerDirectoryKeyV1::pending(
            invitation.package.clone(),
            invitation.invited_account.clone(),
            invitation.invite_id,
        );
        if directory_key != &expected_key
            || invitation.package != package.package
            || invitation.state != MusubiInvitationStateV1::Pending
            || invitation.expected_governance_revision != previous_revision
            || world
                .musubi_package_invitations()
                .get(&invitation.invite_id)
                != Some(invitation)
        {
            return Err(invariant(
                "Musubi pending-invitation directory is inconsistent with package governance",
            ));
        }
    }
    if let Some((target_id, _)) = target_transition.as_ref() {
        let target = pending
            .iter()
            .find(|(_, invitation)| invitation.invite_id == *target_id)
            .map(|(_, invitation)| invitation)
            .ok_or_else(|| {
                invariant("Musubi target invitation is absent from the pending directory")
            })?;
        if target.expires_at_height < finalized_height {
            return Err(invariant(
                "Musubi target invitation expired before its terminal transition",
            ));
        }
    }
    let mut updates = Vec::with_capacity(pending.len());
    let mut invitation_events = Vec::new();
    let mut terminal_invitation = None;
    for (directory_key, mut invitation) in pending {
        invitation.expected_governance_revision = revision;
        let keep_pending = if let Some((target_id, target_state)) = target_transition
            && invitation.invite_id == target_id
        {
            invitation.state = target_state;
            terminal_invitation = Some(invitation.clone());
            false
        } else if invitation.expires_at_height < finalized_height {
            invitation.state = MusubiInvitationStateV1::Expired;
            invitation_events.push(MusubiEvent::MaintainerInvitationExpired(
                MusubiMaintainerInvitationLifecycleEventV1 {
                    package: invitation.package.clone(),
                    invite_id: invitation.invite_id,
                    invited_account: invitation.invited_account.clone(),
                    governance_revision: revision,
                    finalized_height,
                },
            ));
            false
        } else {
            true
        };
        invitation
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        updates.push(PackageInvitationUpdate {
            directory_key,
            invitation,
            keep_pending,
        });
    }
    package.revisions.governance = revision;
    Ok(PackageGovernanceAdvance {
        revision,
        invitation_updates: updates,
        invitation_events,
        terminal_invitation,
    })
}
fn active_pending_invitation_count(
    package: &MusubiPackageIdV1,
    current_height: u64,
    world: &impl WorldReadOnly,
) -> usize {
    world
        .musubi_maintainer_directory()
        .range(MusubiMaintainerDirectoryKeyV1::package_start(package.clone())..)
        .take_while(|(key, _)| &key.package == package)
        .take(MUSUBI_MAX_PACKAGE_MEMBERS_V1 + MUSUBI_MAX_PENDING_INVITATIONS_V1)
        .filter(|(_, entry)| {
            matches!(
                entry,
                MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation)
                    if invitation.state == MusubiInvitationStateV1::Pending
                        && invitation.expires_at_height >= current_height
            )
        })
        .count()
}
#[cfg(test)]
fn pending_invitation_count(package: &MusubiPackageIdV1, world: &impl WorldReadOnly) -> usize {
    world
        .musubi_maintainer_directory()
        .range(MusubiMaintainerDirectoryKeyV1::package_start(package.clone())..)
        .take_while(|(key, _)| &key.package == package)
        .take(MUSUBI_MAX_PACKAGE_MEMBERS_V1 + MUSUBI_MAX_PENDING_INVITATIONS_V1)
        .filter(|(key, _)| key.invitation.is_some())
        .count()
}
fn maintainer_directory_entry_visible_at_height(
    entry: &MusubiMaintainerDirectoryEntryV1,
    finalized_height: u64,
) -> bool {
    match entry {
        MusubiMaintainerDirectoryEntryV1::Accepted(_) => true,
        MusubiMaintainerDirectoryEntryV1::PendingInvitation(invitation) => {
            invitation.expires_at_height >= finalized_height
        }
    }
}
#[derive(Clone, Copy)]
enum PackageCapability {
    Publish,
    Yank,
    Metadata,
    ArchiveLocations,
}
fn execute_governance_mutation<'block, 'state>(
    state_transaction: &mut StateTransaction<'block, 'state>,
    action: MusubiGovernanceActionV1,
    execute: impl FnOnce(
        &mut StateTransaction<'block, 'state>,
        &mut MusubiGovernanceRejectionReasonV1,
    ) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut rejection_reason = MusubiGovernanceRejectionReasonV1::Other;
    let result = execute(state_transaction, &mut rejection_reason);
    #[cfg(feature = "telemetry")]
    {
        if result.is_err() && !state_transaction.is_execution_deferred() {
            state_transaction
                .telemetry
                .record_musubi_governance_rejection(action, rejection_reason);
        }
    }
    #[cfg(not(feature = "telemetry"))]
    let _ = action;
    result
}
fn classify_governance_rejection<T>(
    result: Result<T, Error>,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
    reason: MusubiGovernanceRejectionReasonV1,
) -> Result<T, Error> {
    result.inspect_err(|_error| {
        *rejection_reason = reason;
    })
}
fn reject_governance_mutation<T>(
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
    reason: MusubiGovernanceRejectionReasonV1,
    error: Error,
) -> Result<T, Error> {
    *rejection_reason = reason;
    Err(error)
}
fn validate_role(role: MusubiPackageRoleV1) -> Result<(), Error> {
    if matches!(role, MusubiPackageRoleV1::Maintainer(permissions) if permissions.is_empty()) {
        Err(invalid_parameter(
            "Musubi maintainer role must grant at least one permission",
        ))
    } else {
        Ok(())
    }
}
fn ensure_package_owner(
    package: &MusubiPackageIdV1,
    authority: &AccountId,
    world: &impl WorldReadOnly,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    let record = world
        .musubi_packages()
        .get(package)
        .ok_or_else(|| package_not_found(package))?;
    if record.owners.binary_search(authority).is_ok() {
        Ok(())
    } else {
        *rejection_reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
        Err(invariant(format!(
            "authority '{authority}' is not an owner of Musubi package '{package}'"
        )))
    }
}
fn ensure_package_capability(
    package: &MusubiPackageIdV1,
    authority: &AccountId,
    capability: PackageCapability,
    world: &impl WorldReadOnly,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    let record = world
        .musubi_packages()
        .get(package)
        .ok_or_else(|| package_not_found(package))?;
    if record.owners.binary_search(authority).is_ok() {
        return Ok(());
    }
    let key = MusubiPackageMemberKeyV1::new(package.clone(), authority.clone());
    let permitted = world
        .musubi_package_members()
        .get(&key)
        .is_some_and(|member| match member.role {
            MusubiPackageRoleV1::Owner => true,
            MusubiPackageRoleV1::Maintainer(permissions) => match capability {
                PackageCapability::Publish => permissions.publish,
                PackageCapability::Yank => permissions.yank,
                PackageCapability::Metadata => permissions.metadata,
                PackageCapability::ArchiveLocations => permissions.archive_locations,
            },
        });
    if permitted {
        Ok(())
    } else {
        *rejection_reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
        Err(invariant(format!(
            "authority '{authority}' lacks the required Musubi package capability for '{package}'"
        )))
    }
}
pub(crate) fn ensure_archive_manager(
    archive: &MusubiArchiveRecordV1,
    authority: &AccountId,
    world: &impl WorldReadOnly,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    let references = world
        .musubi_archive_reverse_references()
        .get(&archive.archive_id);
    let Some(references) = references.filter(|references| !references.releases.is_empty()) else {
        if &archive.registered_by == authority {
            return Ok(());
        }
        *rejection_reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
        return Err(invariant("authority cannot manage this Musubi archive"));
    };
    for release in &references.releases {
        ensure_package_capability(
            &release.package,
            authority,
            PackageCapability::ArchiveLocations,
            world,
            rejection_reason,
        )?;
    }
    Ok(())
}
fn namespace_attempt_error(
    error: crate::execution_attempt::ExecutionAttemptError<Error>,
    state: &mut StateTransaction<'_, '_>,
) -> Error {
    match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            let _ = state.defer_execution(reason);
            invariant("local Musubi namespace resolution did not complete")
        }
    }
}
fn ensure_namespace_registration_owner(
    binding: &MusubiNamespaceBindingV1,
    authority: &AccountId,
    state_transaction: &StateTransaction<'_, '_>,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let (owner, generation) = namespace_owner_and_generation(binding, state_transaction)?;
    binding
        .validate_authority_generation(generation)
        .map_err(|error| invalid_parameter(error.reason()))?;
    ensure_resolved_namespace_owner(binding, authority, &owner, rejection_reason)
        .map_err(Into::into)
}
fn ensure_namespace_current_owner(
    binding: &MusubiNamespaceBindingV1,
    authority: &AccountId,
    state_transaction: &StateTransaction<'_, '_>,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let (owner, _) = namespace_owner_and_generation(binding, state_transaction)?;
    ensure_resolved_namespace_owner(binding, authority, &owner, rejection_reason)
        .map_err(Into::into)
}
fn ensure_resolved_namespace_owner(
    binding: &MusubiNamespaceBindingV1,
    authority: &AccountId,
    owner: &AccountId,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    if owner == authority {
        Ok(())
    } else {
        *rejection_reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
        Err(invariant(format!(
            "authority '{authority}' does not own Musubi namespace '{}'",
            binding.namespace
        )))
    }
}
fn namespace_owner_and_generation(
    binding: &MusubiNamespaceBindingV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(AccountId, u64), crate::execution_attempt::ExecutionAttemptError<Error>> {
    validate_namespace_home_dataspace(
        binding,
        state_transaction.world(),
        &state_transaction.nexus.dataspace_catalog,
        state_transaction.block_unix_timestamp_ms(),
    )?;
    match &binding.scope {
        MusubiPackageScopeV1::Domain(domain) => {
            let domain_id =
                DomainId::try_new(domain.as_ref(), binding.namespace.dataspace_segment())
                    .map_err(|error| invalid_parameter(error.reason()))?;
            let owner = state_transaction
                .world
                .domains()
                .get(&domain_id)
                .map(|registered| registered.owned_by().clone())
                .ok_or_else(|| {
                    invariant(format!(
                        "Musubi namespace domain '{domain_id}' is not registered"
                    ))
                })?;
            let generation = state_transaction
                .world
                .musubi_domain_ownership_generation(&domain_id);
            Ok((owner, generation))
        }
        MusubiPackageScopeV1::DataspaceRoot => {
            Ok(crate::sns::active_dataspace_owner_and_generation_by_alias(
                state_transaction.world(),
                binding.namespace.dataspace_segment(),
                state_transaction.block_unix_timestamp_ms(),
            )
            .map_err(|error| error.into_attempt_error(|error| invariant(error.to_string())))?
            .ok_or_else(|| {
                invariant(format!(
                    "Musubi namespace dataspace '{}' has no active SNS owner",
                    binding.namespace.dataspace_segment()
                ))
            })?)
        }
    }
}
fn validate_namespace_home_dataspace(
    binding: &MusubiNamespaceBindingV1,
    world: &impl WorldReadOnly,
    catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    current_time_ms: u64,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let alias = binding.namespace.dataspace_segment();
    let resolved =
        crate::sns::resolve_active_dataspace_id_by_alias(world, catalog, alias, current_time_ms)
            .map_err(|error| {
                error.into_attempt_error(|error| {
        invariant(format!(
            "Musubi namespace dataspace alias '{alias}' cannot be resolved canonically: {error}"
        ))
    })
            })?;
    if resolved != binding.home_dataspace {
        return Err(invariant(format!(
            "Musubi namespace dataspace alias '{alias}' resolves to {resolved}, not declared home dataspace {}",
            binding.home_dataspace
        )).into());
    }
    Ok(())
}
fn ensure_namespace_claim_authority(
    binding: &MusubiNamespaceBindingV1,
    delegation: Option<&MusubiNamespaceDelegationV1>,
    authority: &AccountId,
    state_transaction: &StateTransaction<'_, '_>,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    let (owner, generation) = namespace_owner_and_generation(binding, state_transaction)?;
    validate_namespace_claim_authority_classified(
        binding,
        delegation,
        authority,
        &owner,
        generation,
        execution_height(state_transaction),
        Some(rejection_reason),
    )
    .map_err(Into::into)
}
#[cfg(test)]
fn validate_namespace_claim_authority(
    binding: &MusubiNamespaceBindingV1,
    delegation: Option<&MusubiNamespaceDelegationV1>,
    authority: &AccountId,
    authoritative_owner: &AccountId,
    authoritative_owner_generation: u64,
    current_height: u64,
) -> Result<(), Error> {
    validate_namespace_claim_authority_classified(
        binding,
        delegation,
        authority,
        authoritative_owner,
        authoritative_owner_generation,
        current_height,
        None,
    )
}
fn validate_namespace_claim_authority_classified(
    binding: &MusubiNamespaceBindingV1,
    delegation: Option<&MusubiNamespaceDelegationV1>,
    authority: &AccountId,
    authoritative_owner: &AccountId,
    authoritative_owner_generation: u64,
    current_height: u64,
    mut rejection_reason: Option<&mut MusubiGovernanceRejectionReasonV1>,
) -> Result<(), Error> {
    binding
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if authoritative_owner_generation == 0 {
        return Err(invariant(
            "Musubi namespace authoritative ownership generation must be non-zero",
        ));
    }
    if authoritative_owner == authority {
        return Ok(());
    }
    let delegation = delegation.ok_or_else(|| {
        if let Some(reason) = rejection_reason.as_mut() {
            **reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
        }
        invariant(format!(
            "authority '{authority}' neither owns nor has a delegation for Musubi namespace '{}'",
            binding.namespace
        ))
    })?;
    delegation
        .verify(
            binding,
            authoritative_owner,
            authoritative_owner_generation,
            authority,
            current_height,
        )
        .map_err(|error| {
            if let Some(reason) = rejection_reason.as_mut() {
                **reason = MusubiGovernanceRejectionReasonV1::Unauthorized;
            }
            invariant(error.reason())
        })
}
fn namespace_binding_for_package(
    namespace: &MusubiNamespaceV1,
    package: &MusubiPackageIdV1,
    world: &impl WorldReadOnly,
) -> Result<MusubiNamespaceBindingV1, Error> {
    let binding = world
        .musubi_namespace_bindings()
        .get(namespace)
        .cloned()
        .ok_or_else(|| {
            invariant(format!(
                "Musubi namespace '{namespace}' has no immutable binding"
            ))
        })?;
    if binding.home_dataspace != package.home_dataspace || binding.scope != package.scope {
        return Err(invariant(format!(
            "Musubi namespace '{namespace}' does not identify package '{package}'"
        )));
    }
    Ok(binding)
}
fn ensure_policy_revision(policy: &MusubiRegistryPolicyV1, expected: u64) -> Result<(), Error> {
    ensure_revision("registry policy", policy.revision, expected)
}
fn ensure_admitted(
    policy: &MusubiRegistryPolicyV1,
    dataspace: Option<DataSpaceId>,
    authority: &AccountId,
    world: &impl WorldReadOnly,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    match policy.mode {
        MusubiRegistryAdmissionModeV1::Open => Ok(()),
        MusubiRegistryAdmissionModeV1::Closed => reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::PolicyClosed,
            invariant("Musubi registry admission is closed for new records"),
        ),
        MusubiRegistryAdmissionModeV1::Allowlisted => {
            let admitted = if let Some(dataspace) = dataspace {
                policy
                    .allowlisted_dataspaces
                    .binary_search(&dataspace)
                    .is_ok()
            } else {
                world
                    .account_dataspaces(authority)
                    .map_err(|error| invariant(error.reason()))?
                    .iter()
                    .any(|candidate| {
                        policy
                            .allowlisted_dataspaces
                            .binary_search(candidate)
                            .is_ok()
                    })
            };
            if admitted {
                Ok(())
            } else {
                reject_governance_mutation(
                    rejection_reason,
                    MusubiGovernanceRejectionReasonV1::PolicyClosed,
                    invariant("Musubi registry admission requires an allowlisted dataspace"),
                )
            }
        }
    }
}
fn bind_location_reverse_indices(
    existing: Option<&MusubiArchiveLocationV1>,
    location: &MusubiArchiveLocationV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let key = location.key();
    let archive = state_transaction
        .world
        .musubi_archives
        .get(&location.archive_id)
        .cloned()
        .ok_or_else(|| invariant("Musubi order binding references a missing archive"))?;
    let new_order_lifecycle = validate_replication_order_archive_binding(
        &archive,
        &location.replication_order,
        state_transaction.world(),
    )
    .map_err(|error| invariant(error.reason()))?;
    match state_transaction
        .world
        .musubi_locations_by_pin
        .get(&location.pin_manifest)
    {
        None => {}
        Some(reference)
            if reference.active
                && reference.location == key
                && existing.is_some_and(|record| record.pin_manifest == location.pin_manifest) => {}
        Some(_) => {
            return Err(invariant(
                "Musubi SoraFS pin manifests cannot be reused by another location or renewal",
            ));
        }
    }
    match new_order_lifecycle {
        MusubiReplicationOrderLocationLifecycleV1::PreLocation => {}
        MusubiReplicationOrderLocationLifecycleV1::Active(bound_location)
            if *bound_location == key && existing == Some(location) => {}
        MusubiReplicationOrderLocationLifecycleV1::Active(_)
        | MusubiReplicationOrderLocationLifecycleV1::Retired(_) => {
            return Err(invariant(
                "Musubi SoraFS replication orders cannot be reused by another location or renewal",
            ));
        }
    }
    if let Some(existing) = existing {
        let old_pin = state_transaction
            .world
            .musubi_locations_by_pin
            .get(&existing.pin_manifest)
            .cloned()
            .ok_or_else(|| invariant("Musubi pin reverse index is inconsistent"))?;
        if !old_pin.active || old_pin.location != key {
            return Err(invariant("Musubi pin reverse index is inconsistent"));
        }
        if existing.pin_manifest != location.pin_manifest {
            state_transaction.world.musubi_locations_by_pin.insert(
                existing.pin_manifest,
                MusubiPinLocationReferenceV1 {
                    active: false,
                    ..old_pin
                },
            );
        }
        let old_order = state_transaction
            .world
            .musubi_locations_by_replication_order
            .get(&existing.replication_order)
            .cloned()
            .ok_or_else(|| invariant("Musubi order reverse index is inconsistent"))?;
        old_order
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        if old_order.active_location() != Some(key)
            || old_order.binding.archive_id != location.archive_id
            || old_order.binding.commitment != archive.commitment
        {
            return Err(invariant("Musubi order reverse index is inconsistent"));
        }
        if existing.replication_order != location.replication_order {
            let mut retired = old_order;
            retired.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Retired(
                MusubiRetiredReplicationOrderLocationV1::new(key, existing.providers.clone()),
            );
            state_transaction
                .world
                .musubi_locations_by_replication_order
                .insert(existing.replication_order, retired);
        }
        for provider in &existing.providers {
            state_transaction
                .world
                .musubi_locations_by_provider
                .remove(MusubiProviderLocationKeyV1::new(*provider, key));
        }
    }
    state_transaction.world.musubi_locations_by_pin.insert(
        location.pin_manifest,
        MusubiPinLocationReferenceV1 {
            pin_manifest: location.pin_manifest,
            location: key,
            active: true,
        },
    );
    let mut active_order = state_transaction
        .world
        .musubi_locations_by_replication_order
        .get(&location.replication_order)
        .cloned()
        .ok_or_else(|| invariant("Musubi order reverse index is inconsistent"))?;
    active_order.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Active(key);
    active_order
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    state_transaction
        .world
        .musubi_locations_by_replication_order
        .insert(location.replication_order, active_order);
    for provider in &location.providers {
        state_transaction
            .world
            .musubi_locations_by_provider
            .insert(MusubiProviderLocationKeyV1::new(*provider, key), ());
    }
    Ok(())
}
fn validate_exact_archive_location_replay(
    archive: &MusubiArchiveRecordV1,
    location: &MusubiArchiveLocationV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    archive
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    location
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    let execution_height = execution_height(state_transaction);
    if location.revision > archive.location_revision
        || archive.registered_at_height > location.finalized_height
        || location.finalized_height > execution_height
    {
        return Err(invariant(
            "Musubi archive location revision or finalized height is inconsistent",
        ));
    }
    let records = load_location_provider_attestations(archive, location, state_transaction.world())
        .map_err(|error| invariant(error.reason()))?;
    if records.len() != location.providers.len() {
        return Err(invariant(
            "Musubi archive location provider attestation registry is inconsistent",
        ));
    }
    let key = location.key();
    let pin_reference = state_transaction
        .world
        .musubi_locations_by_pin
        .get(&location.pin_manifest)
        .ok_or_else(|| invariant("Musubi pin reverse index is inconsistent"))?;
    pin_reference
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if pin_reference.pin_manifest != location.pin_manifest
        || pin_reference.location != key
        || !pin_reference.active
    {
        return Err(invariant("Musubi pin reverse index is inconsistent"));
    }
    let order_reference = state_transaction
        .world
        .musubi_locations_by_replication_order
        .get(&location.replication_order)
        .ok_or_else(|| invariant("Musubi order reverse index is inconsistent"))?;
    order_reference
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if order_reference.binding.replication_order != location.replication_order
        || order_reference.binding.archive_id != archive.archive_id
        || order_reference.binding.commitment != archive.commitment
        || order_reference.active_location() != Some(key)
    {
        return Err(invariant("Musubi order reverse index is inconsistent"));
    }
    for provider in &location.providers {
        let provider_key = MusubiProviderLocationKeyV1::new(*provider, key);
        provider_key
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        if state_transaction
            .world
            .musubi_locations_by_provider
            .get(&provider_key)
            .is_none()
        {
            return Err(invariant("Musubi provider reverse index is inconsistent"));
        }
    }
    Ok(())
}
fn retire_location_reverse_indices(
    location: &MusubiArchiveLocationV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let key = location.key();
    let pin = state_transaction
        .world
        .musubi_locations_by_pin
        .get(&location.pin_manifest)
        .cloned()
        .ok_or_else(|| invariant("Musubi pin reverse index is inconsistent"))?;
    if !pin.active || pin.location != key {
        return Err(invariant("Musubi pin reverse index is inconsistent"));
    }
    state_transaction.world.musubi_locations_by_pin.insert(
        location.pin_manifest,
        MusubiPinLocationReferenceV1 {
            active: false,
            ..pin
        },
    );
    let order = state_transaction
        .world
        .musubi_locations_by_replication_order
        .get(&location.replication_order)
        .cloned()
        .ok_or_else(|| invariant("Musubi order reverse index is inconsistent"))?;
    order
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    let archive = state_transaction
        .world
        .musubi_archives
        .get(&location.archive_id)
        .ok_or_else(|| invariant("Musubi order binding references a missing archive"))?;
    if order.active_location() != Some(key)
        || order.binding.archive_id != archive.archive_id
        || order.binding.commitment != archive.commitment
    {
        return Err(invariant("Musubi order reverse index is inconsistent"));
    }
    let mut retired = order;
    retired.lifecycle = MusubiReplicationOrderLocationLifecycleV1::Retired(
        MusubiRetiredReplicationOrderLocationV1::new(key, location.providers.clone()),
    );
    state_transaction
        .world
        .musubi_locations_by_replication_order
        .insert(location.replication_order, retired);
    for provider in &location.providers {
        state_transaction
            .world
            .musubi_locations_by_provider
            .remove(MusubiProviderLocationKeyV1::new(*provider, key));
    }
    Ok(())
}
pub(crate) fn validate_provider_bundle_attestation(
    archive: &MusubiArchiveRecordV1,
    attestation: &MusubiProviderBundleVerificationAttestationV1,
    state_transaction: &impl StateReadOnly,
) -> Result<(), Error> {
    attestation
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    let binding = &attestation.payload.binding;
    validate_replication_order_archive_binding(
        archive,
        &binding.replication_order,
        state_transaction.world(),
    )
    .map_err(|error| invariant(error.reason()))?;
    let order = state_transaction
        .world()
        .replication_orders()
        .get(&binding.replication_order)
        .ok_or_else(|| invariant("Musubi provider attestation replication order was not found"))?;
    let completion = order
        .provider_completion(binding.provider_id)
        .ok_or_else(|| invariant("Musubi provider attestation has no finalized completion"))?;
    let current_owner = state_transaction
        .world()
        .provider_owners()
        .get(&binding.provider_id)
        .ok_or_else(|| invariant("Musubi provider attestation owner is no longer admitted"))?;
    let anchor_index = binding
        .finalized_anchor
        .height
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok());
    let canonical_anchor = anchor_index.and_then(|index| {
        state_transaction
            .block_hashes()
            .get(index)
            .map(|hash| *hash.as_ref())
    });
    if binding.network_id != *state_transaction.network_id()
        || order.order_id != binding.replication_order
        || order.manifest_root_cid != archive.commitment.root_cid
        || completion.completed_by != completion.completion_authority.completion_signer
        || current_owner != &completion.completion_authority.provider_owner
        || binding.completed_by != completion.completed_by
        || binding.completion_authority != completion.completion_authority
        || binding.assignment_revision != completion.assignment_revision
        || binding.completion_epoch != completion.completion_epoch
        || binding.finalized_anchor != completion.finalized_anchor
        || canonical_anchor != Some(binding.finalized_anchor.block_hash)
        || binding.archive_id != archive.archive_id
        || binding.bundle_digest != archive.commitment.bundle_digest
        || binding.descriptor_digest != archive.commitment.descriptor_digest
        || binding.semantic_release_manifest_digest
            != archive
                .staging_receipt
                .payload
                .binding
                .semantic_release_manifest_digest
        || binding.source_tree_digest != archive.commitment.source_tree_digest
    {
        return Err(invariant(
            "Musubi provider attestation does not match the finalized completion or bundle commitment",
        ));
    }
    attestation
        .verify(binding)
        .map_err(|error| invariant(error.reason()))
}
fn validate_sorafs_location(
    archive: &MusubiArchiveRecordV1,
    pin_manifest: &iroha_data_model::sorafs::pin_registry::ManifestDigest,
    replication_order: &iroha_data_model::sorafs::pin_registry::ReplicationOrderId,
    provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
    expires_at_epoch: u64,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<Vec<iroha_data_model::sorafs::capacity::ProviderId>, Error> {
    archive
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if matches!(
        validate_replication_order_archive_binding(
            archive,
            replication_order,
            state_transaction.world(),
        )
        .map_err(|error| invariant(error.reason()))?,
        MusubiReplicationOrderLocationLifecycleV1::Retired(_)
    ) {
        return Err(invariant(
            "Musubi archive replication-order binding is retired",
        ));
    }
    let commitment = &archive.commitment;
    let pin = state_transaction
        .world
        .pin_manifests
        .get(pin_manifest)
        .ok_or_else(|| invariant("Musubi archive pin manifest was not found"))?;
    if !pin.status.is_active()
        || pin.root_cid != commitment.root_cid
        || pin.chunker != commitment.chunker
        || pin.chunk_digest_sha3_256 != *commitment.chunk_plan_digest.as_bytes()
        || pin.por_root != *commitment.por_root.as_bytes()
        || pin.content_length != commitment.content_length
        || pin.policy.min_replicas < MUSUBI_MIN_HEALTHY_REPLICAS_V1
        || pin.policy.retention_epoch != expires_at_epoch
    {
        return Err(invariant(
            "Musubi archive pin is not finalized or does not match the archive commitment",
        ));
    }
    let order = state_transaction
        .world
        .replication_orders
        .get(replication_order)
        .ok_or_else(|| invariant("Musubi archive replication order was not found"))?;
    if order.manifest_digest != *pin_manifest
        || order.manifest_root_cid != commitment.root_cid
        || order.deadline_epoch > expires_at_epoch
        || !matches!(order.status, ReplicationOrderStatus::Completed(_))
    {
        return Err(invariant(
            "Musubi replication order is not finalized for the requested archive pin",
        ));
    }
    let mut providers = order
        .provider_completions
        .iter()
        .map(|completion| completion.provider_id)
        .collect::<Vec<_>>();
    providers.sort();
    if providers.is_empty()
        || providers.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
        || providers.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invariant(
            "Musubi replication order has an invalid provider completion set",
        ));
    }
    let mut references = Vec::with_capacity(providers.len());
    let mut verification_lock_digest = None;
    let add_height = execution_height(state_transaction);
    for provider in &providers {
        let key = MusubiProviderBundleAttestationKeyV1 {
            archive_id: archive.archive_id,
            replication_order: *replication_order,
            provider_id: *provider,
        };
        let record = state_transaction
            .world
            .musubi_provider_bundle_attestations
            .get(&key)
            .ok_or_else(|| {
                invariant("Musubi finalized completion has no registered provider attestation")
            })?;
        record
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        if record.key != key || record.registered_at_height >= add_height {
            return Err(invariant(
                "Musubi provider attestation must be finalized before archive location admission",
            ));
        }
        validate_provider_bundle_attestation(archive, &record.attestation, state_transaction)?;
        let binding = &record.attestation.payload.binding;
        if verification_lock_digest
            .replace(binding.verification_lock_digest)
            .is_some_and(|digest| digest != binding.verification_lock_digest)
        {
            return Err(invariant(
                "Musubi provider attestations disagree on the verification lock",
            ));
        }
        references.push(record.attestation.reference());
    }
    let computed_set_digest = musubi_provider_bundle_attestation_set_digest_v1(
        archive.archive_id,
        *replication_order,
        &references,
    )
    .map_err(|error| invariant(error.reason()))?;
    if computed_set_digest != provider_attestation_set_digest {
        return Err(invariant(
            "Musubi provider attestation set digest does not cover the finalized completion set",
        ));
    }
    Ok(providers)
}
fn validate_seed_ingress_receipt(
    commitment: &MusubiArchiveCommitmentV1,
    receipt: &MusubiSeedIngressReceiptV1,
    authority: &AccountId,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let binding = &receipt.payload.binding;
    let archive_id = commitment.archive_id();
    if binding.network_id != *state_transaction.network_id()
        || binding.publisher != *authority
        || binding.archive_id != archive_id
        || binding.car_body_digest != commitment.car_digest
        || binding.car_body_length != commitment.car_size
    {
        return Err(invariant(
            "Musubi seed-ingress receipt does not match the network, publisher, or archive body",
        ));
    }
    let admitted_owner = state_transaction
        .world
        .provider_owners
        .get(&binding.seed_provider)
        .ok_or_else(|| invariant("Musubi seed-ingress provider is not admitted"))?;
    if admitted_owner != &binding.ingress_broker {
        return Err(invariant(
            "Musubi seed-ingress receipt was not signed by the admitted provider owner",
        ));
    }
    receipt
        .verify(binding, execution_time_ms(state_transaction)?)
        .map_err(|error| invariant(error.reason()))
}
fn validate_publication_archive_evidence(
    publication: &MusubiPublicationV1,
    archive: &MusubiArchiveRecordV1,
    authority: &AccountId,
    world: &impl WorldReadOnly,
) -> Result<(), Error> {
    let receipt_binding = &archive.staging_receipt.payload.binding;
    let semantic_digest = publication.manifest.semantic_digest();
    if receipt_binding.publisher != *authority
        || receipt_binding.semantic_release_manifest_digest != semantic_digest
    {
        return Err(invariant(
            "Musubi release does not match the authenticated seed-ingress receipt",
        ));
    }
    let mut verified_providers = BTreeSet::new();
    for location_id in &archive.location_ids {
        let key = MusubiArchiveLocationKeyV1::new(archive.archive_id, *location_id);
        let location = world
            .musubi_archive_locations()
            .get(&key)
            .ok_or_else(|| invariant("Musubi archive location directory is inconsistent"))?;
        let records = load_location_provider_attestations(archive, location, world)
            .map_err(|error| invariant(error.reason()))?;
        for record in records.iter() {
            let binding = &record.attestation.payload.binding;
            if binding.semantic_release_manifest_digest != semantic_digest
                || binding.verification_lock_digest != publication.manifest.verification_lock_digest
                || binding.bundle_digest != archive.commitment.bundle_digest
                || binding.descriptor_digest != archive.commitment.descriptor_digest
                || binding.source_tree_digest != archive.commitment.source_tree_digest
            {
                return Err(invariant(
                    "Musubi provider bundle attestation does not match the release bundle",
                ));
            }
            verified_providers.insert(binding.provider_id);
        }
    }
    if verified_providers.len() < usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1) {
        return Err(invariant(
            "Musubi release lacks three distinct parsed-bundle provider attestations",
        ));
    }
    Ok(())
}
fn validate_publication_snapshot(
    publication: &MusubiPublicationV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    validate_musubi_registry_snapshot_history_v1(
        &publication.resolution.snapshot,
        state_transaction,
    )
}
/// Require a canonical finalized Musubi registry ancestor whose resolver
/// revision was active at the claimed height.
///
/// Daemon-side publication adapters should use this helper instead of
/// duplicating the consensus-owned resolver-revision activation rules.
///
/// # Errors
///
/// Returns an instruction execution error when the snapshot is malformed, is
/// not on the current finalized chain, or claims a resolver revision outside
/// that revision's recorded activation interval.
pub fn validate_musubi_registry_snapshot_history_v1(
    snapshot: &MusubiRegistrySnapshotV1,
    state_ro: &impl StateReadOnly,
) -> Result<(), Error> {
    validate_publication_snapshot_history(
        snapshot,
        state_ro.world(),
        state_ro.block_hashes(),
        state_ro.world().musubi_resolver_index_revision(),
    )
}
fn canonical_finalized_hash(
    block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
    finalized_height: u64,
) -> Option<[u8; 32]> {
    finalized_height
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| block_hashes.hash_at(index))
        .map(|hash| *hash.as_ref())
}
fn validate_publication_snapshot_history(
    snapshot: &MusubiRegistrySnapshotV1,
    world: &impl WorldReadOnly,
    block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
    current_revision: u64,
) -> Result<(), Error> {
    let current_height = u64::try_from(block_hashes.hash_count())
        .map_err(|_| invariant("Musubi finalized height overflows u64"))?;
    validate_publication_snapshot_anchor(
        snapshot,
        current_height,
        canonical_finalized_hash(block_hashes, snapshot.finalized_height),
        current_revision,
    )?;
    let revision = MusubiResolverIndexRevisionV1::new(snapshot.index_revision)
        .map_err(|error| invariant(error.reason()))?;
    let checkpoints = world.musubi_resolver_index_checkpoints();
    let activation = checkpoints.get(&revision).ok_or_else(|| {
        invariant(
            "Musubi publication proof snapshot references an unrecorded resolver-index revision",
        )
    })?;
    if activation.index_revision != revision.get() {
        return Err(invariant(
            "Musubi resolver checkpoint key does not match its embedded revision",
        ));
    }
    validate_publication_snapshot_anchor(
        activation,
        current_height,
        canonical_finalized_hash(block_hashes, activation.finalized_height),
        current_revision,
    )?;
    if activation.finalized_height > snapshot.finalized_height {
        return Err(invariant(
            "Musubi publication proof snapshot predates its resolver revision activation",
        ));
    }
    if let Some((successor_revision, successor)) = checkpoints
        .range((
            std::ops::Bound::Excluded(revision),
            std::ops::Bound::Unbounded,
        ))
        .next()
    {
        if successor.index_revision != successor_revision.get() {
            return Err(invariant(
                "Musubi resolver checkpoint key does not match its embedded revision",
            ));
        }
        validate_publication_snapshot_anchor(
            successor,
            current_height,
            canonical_finalized_hash(block_hashes, successor.finalized_height),
            current_revision,
        )?;
        if successor.finalized_height <= snapshot.finalized_height {
            return Err(invariant(
                "Musubi publication proof snapshot is outside its resolver revision activation interval",
            ));
        }
    }
    Ok(())
}
fn validate_publication_snapshot_anchor(
    snapshot: &MusubiRegistrySnapshotV1,
    current_height: u64,
    finalized_hash: Option<[u8; 32]>,
    current_revision: u64,
) -> Result<(), Error> {
    snapshot
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    let finalized_hash = finalized_hash
        .ok_or_else(|| invariant("Musubi publication requires a canonical finalized snapshot"))?;
    if snapshot.finalized_height > current_height
        || snapshot.finalized_block_hash != finalized_hash
        || snapshot.index_revision > current_revision
    {
        return Err(invariant(
            "Musubi publication proof snapshot is not a canonical finalized registry ancestor",
        ));
    }
    Ok(())
}
fn validate_resolution_proof(
    publication: &MusubiPublicationV1,
    world: &impl WorldReadOnly,
    block_hashes: &(impl crate::state::BlockHashRead + ?Sized),
) -> Result<(), Error> {
    let nodes = publication
        .resolution
        .lock
        .nodes
        .iter()
        .map(|node| (&node.release, node))
        .collect::<BTreeMap<_, _>>();
    for node in &publication.resolution.lock.nodes {
        let row = world
            .musubi_resolver_index()
            .get(&node.release)
            .ok_or_else(|| {
                invariant(format!(
                    "Musubi proof release '{}' is absent from the resolver index",
                    node.release
                ))
            })?;
        row.validate().map_err(|error| {
            invariant(format!(
                "Musubi proof release '{}' has an invalid resolver row: {}",
                node.release,
                error.reason()
            ))
        })?;
        let snapshot = &publication.resolution.snapshot;
        let storage = &row.selection.storage;
        if storage.index_revision > snapshot.index_revision {
            return Err(invariant(format!(
                "Musubi proof release '{}' storage revision is newer than the claimed resolver snapshot",
                node.release
            )));
        }
        if row.index_revision > snapshot.index_revision {
            return Err(invariant(format!(
                "Musubi proof release '{}' is newer than the claimed resolver snapshot",
                node.release
            )));
        }
        if storage.finalized_height > snapshot.finalized_height {
            return Err(invariant(format!(
                "Musubi proof release '{}' storage state is newer than the claimed finalized snapshot",
                node.release
            )));
        }
        if storage.finalized_height == snapshot.finalized_height
            && storage.finalized_block_hash != snapshot.finalized_block_hash
        {
            return Err(invariant(format!(
                "Musubi proof release '{}' storage state does not match the claimed finalized block",
                node.release
            )));
        }
        if canonical_finalized_hash(block_hashes, storage.finalized_height)
            != Some(storage.finalized_block_hash)
        {
            return Err(invariant(format!(
                "Musubi proof release '{}' storage state is not anchored to its canonical finalized block",
                node.release
            )));
        }
        if row.selection.yank.changed_at_height > snapshot.finalized_height {
            return Err(invariant(format!(
                "Musubi proof release '{}' yank state is newer than the claimed finalized snapshot",
                node.release
            )));
        }
        if !row.selection.fresh_selectable()
            || row.release_digest != node.release_digest
            || row.archive_id != node.archive_id
            || row.source_digest != node.source_digest
            || row.interface_digest != node.interface_digest
            || row.abi != node.abi
        {
            return Err(invariant(format!(
                "Musubi proof release '{}' does not match a fresh-selectable resolver row",
                node.release
            )));
        }
        if row.dependencies.len() != node.dependencies.len()
            || row
                .dependencies
                .iter()
                .zip(&node.dependencies)
                .any(|(requirement, exact)| {
                    requirement.alias != exact.alias
                        || requirement.package != exact.package
                        || requirement.requirement != exact.requirement
                        || exact.kind != MusubiDependencyKindV1::Normal
                })
        {
            return Err(invariant(format!(
                "Musubi proof release '{}' dependency edges do not match the published row",
                node.release
            )));
        }
    }
    let mut reachable = BTreeSet::new();
    let mut pending = publication
        .resolution
        .lock
        .root_dependencies
        .iter()
        .map(|edge| edge.selected.clone())
        .collect::<Vec<_>>();
    while let Some(release) = pending.pop() {
        if !reachable.insert(release.clone()) {
            continue;
        }
        let node = nodes
            .get(&release)
            .ok_or_else(|| invariant("Musubi proof references an absent exact node"))?;
        pending.extend(
            node.dependencies
                .iter()
                .filter(|edge| edge.kind == MusubiDependencyKindV1::Normal)
                .map(|edge| edge.selected.clone()),
        );
    }
    if reachable.len() != nodes.len() {
        return Err(invariant(
            "Musubi publication proof contains unreachable exact nodes",
        ));
    }
    Ok(())
}
fn plan_archive_reverse_reference(
    archive_id: ArchiveId,
    release: MusubiReleaseIdV1,
    world: &impl WorldReadOnly,
) -> Result<MusubiArchiveReverseReferencesV1, Error> {
    let mut references = world
        .musubi_archive_reverse_references()
        .get(&archive_id)
        .cloned()
        .ok_or_else(|| {
            invariant("Musubi archive is missing its exact reverse-reference projection")
        })?;
    references
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if references.archive_id != archive_id {
        return Err(invariant(
            "Musubi archive reverse-reference projection has the wrong archive identity",
        ));
    }
    references.releases.push(release);
    references.releases.sort();
    references.releases.dedup();
    references
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    Ok(references)
}
/// Prevent an explicit lifecycle change from removing the last quorum-healthy
/// location of an active or yanked release.
pub(crate) fn ensure_locations_may_be_invalidated(
    locations: &[MusubiArchiveLocationKeyV1],
    world: &impl WorldReadOnly,
) -> Result<(), Error> {
    let excluded = locations.iter().copied().collect::<BTreeSet<_>>();
    let archives = locations
        .iter()
        .map(|location| location.archive_id)
        .collect::<BTreeSet<_>>();
    for archive_id in archives {
        if !archive_has_protected_release(archive_id, world) {
            continue;
        }
        let archive = world
            .musubi_archives()
            .get(&archive_id)
            .ok_or_else(|| archive_not_found(archive_id))?;
        let mut remaining_providers = BTreeSet::new();
        for location_id in &archive.location_ids {
            let key = MusubiArchiveLocationKeyV1::new(archive_id, *location_id);
            if excluded.contains(&key) {
                continue;
            }
            if let Some(providers) = world
                .musubi_archive_locations()
                .get(&key)
                .and_then(|location| current_location_providers(location, world))
            {
                remaining_providers.extend(providers);
            }
        }
        if !provider_count_is_healthy(remaining_providers.len()) {
            return Err(invariant(
                "Musubi active or yanked releases must retain a quorum-healthy archive location",
            ));
        }
    }
    Ok(())
}
/// Prevent provider removal from making a protected archive entirely
/// unfetchable. Falling below fresh-selection quorum remains allowed.
pub(crate) fn ensure_provider_may_be_removed(
    provider: iroha_data_model::sorafs::capacity::ProviderId,
    locations: &[MusubiArchiveLocationKeyV1],
    world: &impl WorldReadOnly,
) -> Result<(), Error> {
    let archives = locations
        .iter()
        .map(|location| location.archive_id)
        .collect::<BTreeSet<_>>();
    for archive_id in archives {
        if !archive_has_protected_release(archive_id, world) {
            continue;
        }
        let archive = world
            .musubi_archives()
            .get(&archive_id)
            .ok_or_else(|| archive_not_found(archive_id))?;
        let has_remaining = archive.location_ids.iter().any(|location_id| {
            let key = MusubiArchiveLocationKeyV1::new(archive_id, *location_id);
            world
                .musubi_archive_locations()
                .get(&key)
                .and_then(|location| current_location_providers(location, world))
                .is_some_and(|providers| providers.into_iter().any(|item| item != provider))
        });
        if !has_remaining {
            return Err(invariant(
                "SoraFS provider removal would eliminate the last fetchable location of an active or yanked Musubi release",
            ));
        }
    }
    Ok(())
}
const fn provider_count_is_healthy(provider_count: usize) -> bool {
    provider_count >= MUSUBI_MIN_HEALTHY_REPLICAS_V1 as usize
}
/// Recompute location and universal resolver projections after an underlying SoraFS lifecycle
/// change. Every lookup is exact or bounded by archive-local directories populated at registration.
pub(crate) fn refresh_musubi_locations(
    locations: &[MusubiArchiveLocationKeyV1],
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let locations = locations.iter().copied().collect::<BTreeSet<_>>();
    let mut archives = BTreeSet::new();
    for key in locations {
        let Some(mut location) = state_transaction
            .world
            .musubi_archive_locations
            .get(&key)
            .cloned()
        else {
            continue;
        };
        if location.state == MusubiArchiveLocationStateV1::Retired {
            continue;
        }
        archives.insert(key.archive_id);
        let healthy_replicas = current_location_providers(&location, state_transaction.world())
            .map_or(0, |providers| providers.len());
        let next_state = if healthy_replicas >= usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1) {
            MusubiArchiveLocationStateV1::Healthy
        } else {
            MusubiArchiveLocationStateV1::Degraded
        };
        if location.state == next_state {
            continue;
        }
        let mut archive = state_transaction
            .world
            .musubi_archives
            .get(&key.archive_id)
            .cloned()
            .ok_or_else(|| archive_not_found(key.archive_id))?;
        let revision = next_revision(archive.location_revision, "archive location lifecycle")?;
        archive.location_revision = revision;
        location.revision = revision;
        location.finalized_height = execution_height(state_transaction);
        location.state = next_state;
        let event = MusubiArchiveLocationEventV1 {
            location: key,
            pin_manifest: location.pin_manifest,
            replication_order: location.replication_order,
            provider_attestation_set_digest: location.provider_attestation_set_digest,
            provider_count: u8::try_from(location.providers.len())
                .map_err(|_| invariant("Musubi archive location provider count overflows u8"))?,
            transition: MusubiArchiveLocationTransitionV1::EvidenceRefreshed,
            state: location.state,
            revision: location.revision,
            finalized_height: location.finalized_height,
        };
        state_transaction
            .world
            .musubi_archive_locations
            .insert(key, location);
        state_transaction
            .world
            .musubi_archives
            .insert(key.archive_id, archive);
        emit_musubi_event(
            MusubiEvent::ArchiveLocationChanged(event),
            state_transaction,
        );
    }
    for archive_id in archives {
        refresh_archive_availability(archive_id, state_transaction)?;
    }
    Ok(())
}
fn refresh_archive_availability(
    archive_id: ArchiveId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let previous = state_transaction
        .world
        .musubi_archive_availability
        .get(&archive_id)
        .copied()
        .ok_or_else(|| {
            invariant("Musubi archive is missing its authoritative availability projection")
        })?;
    let references =
        exact_archive_projection_references(archive_id, previous, state_transaction.world())?;
    let archive = state_transaction
        .world
        .musubi_archives
        .get(&archive_id)
        .cloned()
        .ok_or_else(|| archive_not_found(archive_id))?;
    archive
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if archive.archive_id != archive_id {
        return Err(invariant(
            "Musubi archive record has the wrong embedded archive identity",
        ));
    }
    let locations = archive
        .location_ids
        .iter()
        .map(|location_id| {
            let key = MusubiArchiveLocationKeyV1::new(archive_id, *location_id);
            let location = state_transaction
                .world
                .musubi_archive_locations
                .get(&key)
                .cloned()
                .ok_or_else(|| invariant("Musubi archive location directory is inconsistent"))?;
            if location.key() != key {
                return Err(invariant(
                    "Musubi archive location record has the wrong embedded identity",
                ));
            }
            location
                .validate()
                .map_err(|error| invariant(error.reason()))?;
            if location.revision > archive.location_revision {
                return Err(invariant(
                    "Musubi archive location revision exceeds its archive revision",
                ));
            }
            Ok(location)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if locations
        .iter()
        .any(|record| record.state == MusubiArchiveLocationStateV1::Retired)
    {
        return Err(invariant(
            "Musubi active archive location directory contains a retired record",
        ));
    }
    let current = locations
        .iter()
        .filter_map(|location| {
            current_location_providers(location, state_transaction.world())
                .map(|providers| (location, providers))
        })
        .collect::<Vec<_>>();
    let mut providers = current
        .iter()
        .flat_map(|(_, providers)| providers.iter().copied())
        .collect::<Vec<_>>();
    providers.sort();
    providers.dedup();
    let active_locations = u8::try_from(current.len())
        .map_err(|_| invariant("Musubi active archive-location count overflows u8"))?;
    let healthy_replicas = u16::try_from(providers.len())
        .map_err(|_| invariant("Musubi healthy replica count overflows u16"))?;
    let availability = if healthy_replicas >= MUSUBI_MIN_HEALTHY_REPLICAS_V1 {
        MusubiStorageAvailabilityV1::Selectable
    } else if active_locations > 0 && healthy_replicas > 0 {
        MusubiStorageAvailabilityV1::BelowQuorum
    } else {
        MusubiStorageAvailabilityV1::Unavailable
    };
    if previous.availability == availability
        && previous.healthy_replicas == healthy_replicas
        && previous.active_locations == active_locations
    {
        return Ok(());
    }
    let release_count = u64::try_from(references.len())
        .map_err(|_| invariant("Musubi archive reverse-reference count overflows u64"))?;
    let replication_shortfall_update = plan_replication_shortfall_transition(
        *state_transaction
            .world
            .musubi_replication_shortfall_releases
            .get(),
        previous.availability,
        availability,
        release_count,
    )?;
    let index_revision = bump_resolver_index_revision(state_transaction)?;
    let projection = MusubiArchiveAvailabilityV1 {
        archive_id,
        availability,
        healthy_replicas,
        active_locations,
        finalized_height: execution_height(state_transaction),
        finalized_block_hash: execution_hash(state_transaction),
        index_revision,
    };
    projection
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    state_transaction
        .world
        .musubi_archive_availability
        .insert(archive_id, projection);
    if let Some(replication_shortfall_releases) = replication_shortfall_update {
        *state_transaction
            .world
            .musubi_replication_shortfall_releases
            .get_mut() = replication_shortfall_releases;
    }
    let mut packages = BTreeSet::new();
    for release in references {
        let mut row = state_transaction
            .world
            .musubi_resolver_index
            .get(&release)
            .cloned()
            .ok_or_else(|| {
                invariant("Musubi archive reverse reference is missing its exact resolver row")
            })?;
        row.selection.storage = projection;
        row.index_revision = index_revision;
        packages.insert(release.package.clone());
        state_transaction
            .world
            .musubi_resolver_index
            .insert(release, row);
    }
    for package in packages {
        refresh_directory_for_package(&package, index_revision, state_transaction)?;
    }
    emit_musubi_event(
        MusubiEvent::ArchiveAvailabilityChanged(projection),
        state_transaction,
    );
    Ok(())
}
fn exact_archive_projection_references(
    archive_id: ArchiveId,
    availability: MusubiArchiveAvailabilityV1,
    world: &impl WorldReadOnly,
) -> Result<Vec<MusubiReleaseIdV1>, Error> {
    let archive = world
        .musubi_archives()
        .get(&archive_id)
        .ok_or_else(|| archive_not_found(archive_id))?;
    archive
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if archive.archive_id != archive_id {
        return Err(invariant(
            "Musubi archive record has the wrong embedded archive identity",
        ));
    }
    availability
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if availability.archive_id != archive_id {
        return Err(invariant(
            "Musubi archive availability projection has the wrong archive identity",
        ));
    }
    let references = world
        .musubi_archive_reverse_references()
        .get(&archive_id)
        .ok_or_else(|| {
            invariant("Musubi archive is missing its exact reverse-reference projection")
        })?;
    references
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    if references.archive_id != archive_id {
        return Err(invariant(
            "Musubi archive reverse-reference projection has the wrong archive identity",
        ));
    }
    let mut packages = BTreeSet::new();
    for release_id in &references.releases {
        let release = world.musubi_releases().get(release_id).ok_or_else(|| {
            invariant("Musubi archive reverse reference names a missing authoritative release")
        })?;
        release
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        if release.manifest.release != *release_id || release.manifest.archive_id != archive_id {
            return Err(invariant(
                "Musubi archive reverse reference disagrees with its authoritative release",
            ));
        }
        let row = world
            .musubi_resolver_index()
            .get(release_id)
            .ok_or_else(|| {
                invariant("Musubi archive reverse reference is missing its exact resolver row")
            })?;
        row.validate().map_err(|error| invariant(error.reason()))?;
        if row.release != *release_id
            || row.release_digest != release.release_digest
            || row.archive_id != archive_id
            || row.source_digest != archive.commitment.source_tree_digest
            || row.interface_digest != release.manifest.interface_digest
            || row.abi != release.manifest.abi
            || row.dependencies.as_slice() != release.manifest.dependencies.as_slice()
            || row.selection.yank != release.yank
            || row.selection.storage != availability
            || row.selection.governance != release.artifact_governance
        {
            return Err(invariant(
                "Musubi resolver row diverges from its authoritative archive/release projections",
            ));
        }
        packages.insert(release_id.package.clone());
    }
    for package_id in packages {
        let package = world.musubi_packages().get(&package_id).ok_or_else(|| {
            invariant("Musubi archive projection references a missing package record")
        })?;
        package
            .validate()
            .map_err(|error| invariant(error.reason()))?;
        if package.package != package_id {
            return Err(invariant(
                "Musubi archive projection package identity is inconsistent",
            ));
        }
    }
    Ok(references.releases.clone())
}
fn refresh_directory_for_package(
    package: &MusubiPackageIdV1,
    index_revision: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let package_record = state_transaction
        .world
        .musubi_packages
        .get(package)
        .cloned()
        .ok_or_else(|| package_not_found(package))?;
    let latest_selectable = state_transaction
        .world
        .musubi_resolver_index
        .range(package_release_start(package)..)
        .take_while(|(release, _)| release.package == *package)
        .filter(|(_, row)| row.selection.fresh_selectable())
        .map(|(release, _)| release.version.clone())
        .max();
    let entry = plan_package_directory_entry(&package_record, latest_selectable, index_revision)?;
    state_transaction
        .world
        .musubi_public_directory
        .insert(entry.selector.clone(), entry);
    Ok(())
}
fn plan_package_directory_entry(
    package: &MusubiPackageRecordV1,
    latest_selectable: Option<MusubiVersionV1>,
    index_revision: u64,
) -> Result<MusubiOrderedPackageEntryV1, Error> {
    let selector = MusubiPackageSelectorV1 {
        namespace: package.claimed_namespace.clone(),
        name: package.package.name.clone(),
    };
    let entry = MusubiOrderedPackageEntryV1 {
        selector,
        package: package.package.clone(),
        latest_selectable,
        metadata_revision: package.revisions.metadata,
        index_revision,
    };
    entry
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    Ok(entry)
}
fn archive_has_protected_release(archive_id: ArchiveId, world: &impl WorldReadOnly) -> bool {
    world
        .musubi_archive_reverse_references()
        .get(&archive_id)
        .into_iter()
        .flat_map(|references| &references.releases)
        .filter_map(|release| world.musubi_releases().get(release))
        .any(|record| {
            matches!(
                record.artifact_governance,
                MusubiArtifactGovernanceStateV1::Available
            )
        })
}
fn package_has_active_release(package: &MusubiPackageIdV1, world: &impl WorldReadOnly) -> bool {
    world
        .musubi_resolver_index()
        .range(package_release_start(package)..)
        .take_while(|(release, _)| release.package == *package)
        .any(|(_, row)| row.selection.fresh_selectable())
}
fn package_release_start(package: &MusubiPackageIdV1) -> MusubiReleaseIdV1 {
    MusubiReleaseIdV1::new(
        package.clone(),
        MusubiVersionV1::new(0, 0, 0, vec![MusubiPrereleaseIdentifierV1::Numeric(0)])
            .expect("the static minimum Musubi version is valid"),
    )
}
fn package_release_page_start(
    package: &MusubiPackageIdV1,
    page: &MusubiPageRequestV1,
) -> Result<MusubiReleaseIdV1, MusubiQueryExecutionErrorV1> {
    if let Some(cursor) = &page.cursor {
        let version = cursor.last_key.parse::<MusubiVersionV1>().map_err(|_| {
            MusubiQueryExecutionErrorV1::cursor(MusubiCursorFailureV1::LastKeyStale)
        })?;
        Ok(MusubiReleaseIdV1::new(package.clone(), version))
    } else {
        Ok(package_release_start(package))
    }
}
fn verify_parliament_decision(
    decision: &MusubiGovernanceDecisionV1,
    action: &MusubiParliamentActionV1,
    state_transaction: &StateTransaction<'_, '_>,
    rejection_reason: &mut MusubiGovernanceRejectionReasonV1,
) -> Result<(), Error> {
    decision.validate().map_err(|error| {
        *rejection_reason = MusubiGovernanceRejectionReasonV1::InvalidDecision;
        invalid_parameter(error.reason())
    })?;
    action.validate().map_err(|error| {
        *rejection_reason = MusubiGovernanceRejectionReasonV1::InvalidDecision;
        invalid_parameter(error.reason())
    })?;
    if decision.action_digest != action.action_digest() {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant("Musubi Parliament decision does not bind the exact requested action"),
        );
    }
    if state_transaction
        .world
        .musubi_governance_decisions
        .get(&decision.decision_id)
        .is_some()
    {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::Replay,
            invariant("Musubi Parliament decision was already consumed"),
        );
    }
    let proposal = state_transaction
        .world
        .governance_proposals
        .get(&decision.decision_id)
        .ok_or_else(|| {
            *rejection_reason = MusubiGovernanceRejectionReasonV1::InvalidDecision;
            invariant("Musubi Parliament decision has no governance proposal")
        })?;
    if proposal.kind.fingerprint() != decision.decision_id {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant(
                "Musubi Parliament proposal storage key differs from its exact typed fingerprint",
            ),
        );
    }
    if proposal.status != GovernanceProposalStatus::Enacted {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant("Musubi Parliament proposal is not enacted at the claimed height"),
        );
    }
    let proposal_content_id = ProposalContentId::new(decision.decision_id);
    let mut history = Vec::new();
    let mut history_ended = false;
    for attempt_id in canonical_governance_attempt_ids_v1(proposal_content_id) {
        let Some(attempt) = state_transaction.world.parliament_attempts.get(&attempt_id) else {
            history_ended = true;
            continue;
        };
        if history_ended {
            return reject_governance_mutation(
                rejection_reason,
                MusubiGovernanceRejectionReasonV1::InvalidDecision,
                invariant("Musubi Parliament proposal has a sparse attempt history"),
            );
        }
        if let Err(error) = attempt.validate() {
            return reject_governance_mutation(
                rejection_reason,
                MusubiGovernanceRejectionReasonV1::InvalidDecision,
                invariant(format!("Musubi Parliament attempt is invalid: {error}")),
            );
        }
        if attempt.attempt().id != attempt_id
            || attempt.proposal_content_id() != proposal_content_id
        {
            return reject_governance_mutation(
                rejection_reason,
                MusubiGovernanceRejectionReasonV1::InvalidDecision,
                invariant("Musubi Parliament attempt is stored under the wrong canonical key"),
            );
        }
        if let Err(error) = attempt.validate_proposal_bindings_v1(&proposal.kind) {
            return reject_governance_mutation(
                rejection_reason,
                MusubiGovernanceRejectionReasonV1::InvalidDecision,
                invariant(format!(
                    "Musubi Parliament attempt has invalid proposal bindings: {error}"
                )),
            );
        }
        history.push(attempt);
    }
    if let Err(error) = validate_parliament_randomness_redraw_lineage_v1(history.iter().copied()) {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant(format!(
                "Musubi Parliament proposal has invalid attempt lineage: {error}"
            )),
        );
    }
    let mut enacted_attempts = history.into_iter().filter(|attempt| {
        attempt.attempt().status == GovernanceAttemptStatusV1::Enacted
            && attempt.terminal_height() == Some(decision.enacted_at_height)
            && attempt.certificate().is_some_and(|certificate| {
                certificate.proposal_content_id == proposal_content_id
                    && certificate.enact_at_height == decision.enacted_at_height
            })
    });
    if enacted_attempts.next().is_none() || enacted_attempts.next().is_some() {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant(
                "Musubi Parliament decision has no unique enacted attempt at the claimed height",
            ),
        );
    }
    match &proposal.kind {
        ProposalKind::MusubiRegistryGovernance(enacted) if enacted == action => {}
        _ => {
            return reject_governance_mutation(
                rejection_reason,
                MusubiGovernanceRejectionReasonV1::InvalidDecision,
                invariant("Musubi Parliament proposal payload does not match the requested action"),
            );
        }
    }
    let minimum = decision
        .enacted_at_height
        .checked_add(state_transaction.gov.min_enactment_delay)
        .ok_or_else(|| {
            *rejection_reason = MusubiGovernanceRejectionReasonV1::InvalidDecision;
            invariant("Musubi Parliament delay overflows block height")
        })?;
    if decision.execute_after_height < minimum
        || execution_height(state_transaction) < decision.execute_after_height
    {
        return reject_governance_mutation(
            rejection_reason,
            MusubiGovernanceRejectionReasonV1::InvalidDecision,
            invariant("Musubi Parliament decision has not satisfied the enactment delay"),
        );
    }
    Ok(())
}
fn consume_parliament_decision(
    decision: MusubiGovernanceDecisionV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let consumption = MusubiGovernanceDecisionConsumptionV1 {
        decision,
        minimum_enactment_delay: state_transaction.gov.min_enactment_delay,
        consumed_at_height: execution_height(state_transaction),
    };
    consumption
        .validate()
        .map_err(|error| invariant(error.reason()))?;
    state_transaction
        .world
        .musubi_governance_decisions
        .insert(decision.decision_id, consumption);
    Ok(())
}
fn bump_resolver_index_revision(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<u64, Error> {
    let next = plan_resolver_index_revision(state_transaction)?;
    *state_transaction
        .world
        .musubi_resolver_index_revision
        .get_mut() = next;
    Ok(next.get())
}
fn plan_replication_shortfall_transition(
    current: u64,
    previous: MusubiStorageAvailabilityV1,
    next: MusubiStorageAvailabilityV1,
    release_count: u64,
) -> Result<Option<u64>, Error> {
    let previous_selectable = previous == MusubiStorageAvailabilityV1::Selectable;
    let next_selectable = next == MusubiStorageAvailabilityV1::Selectable;
    if previous_selectable == next_selectable || release_count == 0 {
        return Ok(None);
    }
    if next_selectable {
        current
            .checked_sub(release_count)
            .map(Some)
            .ok_or_else(|| invariant("Musubi replication-shortfall release count would underflow"))
    } else {
        current
            .checked_add(release_count)
            .map(Some)
            .ok_or_else(|| invariant("Musubi replication-shortfall release count would overflow"))
    }
}
fn plan_resolver_index_revision(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<MusubiResolverIndexRevisionV1, Error> {
    (*state_transaction.world.musubi_resolver_index_revision.get())
        .checked_next()
        .ok_or_else(|| invariant("Musubi resolver-index revision overflow"))
}
fn execution_height(state_transaction: &StateTransaction<'_, '_>) -> u64 {
    state_transaction._curr_block.height().get()
}
fn execution_hash(state_transaction: &StateTransaction<'_, '_>) -> [u8; 32] {
    *state_transaction._curr_block.hash().as_ref()
}
fn execution_time_ms(state_transaction: &StateTransaction<'_, '_>) -> Result<u64, Error> {
    u64::try_from(state_transaction._curr_block.creation_time().as_millis())
        .map_err(|_| invariant("Musubi block creation time overflows u64 milliseconds"))
}
fn ensure_revision(label: &str, actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(stale_revision(label, actual, expected))
    }
}
fn next_revision(revision: u64, label: &str) -> Result<u64, Error> {
    revision
        .checked_add(1)
        .ok_or_else(|| invariant(format!("Musubi {label} revision overflow")))
}
fn stale_revision(label: &str, actual: u64, expected: u64) -> Error {
    invariant(format!(
        "stale Musubi {label} revision: expected {expected}, current {actual}"
    ))
}
fn package_not_found(package: &MusubiPackageIdV1) -> Error {
    invariant(format!("Musubi package '{package}' was not found"))
}
fn release_not_found(release: &MusubiReleaseIdV1) -> Error {
    invariant(format!("Musubi release '{release}' was not found"))
}
fn archive_not_found(archive: ArchiveId) -> Error {
    invariant(format!(
        "Musubi archive '{}' was not found",
        digest_label(archive.as_bytes())
    ))
}
fn digest_label(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}
fn invalid_parameter(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn invariant(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}
fn emit_musubi_event(event: MusubiEvent, state_transaction: &mut StateTransaction<'_, '_>) {
    state_transaction
        .world
        .emit_events(Some(DataEvent::Musubi(event)));
}
#[cfg(test)]
mod rejection_allocation_tests;

#[cfg(test)]
mod tests {
    use iroha_model_base::topology::DataSpaceId;
    include!("musubi/archive_replay_tests.rs");
    include!("musubi/attestation_records_tests.rs");
    include!("musubi/current_providers_tests.rs");
    include!("musubi/replication_binding_tests.rs");
    include!("musubi/governance_tests.rs");
    include!("musubi/pin_outbox_high_water_tests.rs");
    include!("musubi/initial_publication_admission_tests.rs");
}
