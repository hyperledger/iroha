//! Fixed local evidence for the existing current-provider predicate.
//!
//! Both completion comparison and returned provider identities use the admitted
//! V1 location bound. No heap container or full attestation clone is needed.
//! TODO: signature backends and surrounding projection traversal still require
//! their original allocation/work owner; these fixed containers do not fund them.

use super::*;
use crate::state::deserialize::musubi_source_read::MusubiSourceReadOnly;
use iroha_data_model::sorafs::capacity::ProviderId;

/// Current provider identities with protocol-bounded, allocation-free storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CurrentLocationProviders {
    values: [ProviderId; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
    len: usize,
}

impl std::ops::Deref for CurrentLocationProviders {
    type Target = [ProviderId];

    fn deref(&self) -> &Self::Target {
        &self.values[..self.len]
    }
}

impl IntoIterator for CurrentLocationProviders {
    type Item = ProviderId;
    type IntoIter =
        std::iter::Take<std::array::IntoIter<ProviderId, MUSUBI_MAX_LOCATION_PROVIDERS_V1>>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter().take(self.len)
    }
}

/// Recheck complete attestation and current SoraFS authority before returning identities.
pub(crate) fn current_location_providers(
    location: &MusubiArchiveLocationV1,
    world: &impl MusubiSourceReadOnly,
) -> Option<CurrentLocationProviders> {
    match try_current_location_providers(location, world) {
        Ok(providers) => providers,
        Err(never) => match never {},
    }
}

/// Preserve local source refusal independently of unavailable provider evidence.
pub(crate) fn try_current_location_providers<W: MusubiRead>(
    location: &MusubiArchiveLocationV1,
    world: &W,
) -> Result<Option<CurrentLocationProviders>, W::Error> {
    CurrentProviderValidation::new().advance(location, world)
}

/// Retained current-provider predicate for one unchanged original location.
/// Completed model checks, signatures and provider edges survive source refusal.
pub(crate) struct CurrentProviderValidation {
    queries: [crate::state::deserialize::musubi_source_read::LookupCursor; 7],
    phase: u8,
    provider: usize,
    provider_step: u8,
    completions: [usize; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
    providers: CurrentLocationProviders,
    binding: super::replication_binding::ReplicationBindingValidation,
    attestations: super::attestation_records::ProviderAttestationValidation,
    unavailable: bool,
}
impl CurrentProviderValidation {
    /// Begin without allocating or resolving any source row.
    pub(crate) fn new() -> Self {
        Self {
            phase: 0,
            queries: [crate::state::deserialize::musubi_source_read::LookupCursor::new(); 7],
            provider: 0,
            provider_step: 0,
            completions: [0; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
            providers: CurrentLocationProviders {
                values: [ProviderId::new([0; 32]); MUSUBI_MAX_LOCATION_PROVIDERS_V1],
                len: 0,
            },
            binding: super::replication_binding::ReplicationBindingValidation::new(),
            attestations: super::attestation_records::ProviderAttestationValidation::new(),
            unavailable: false,
        }
    }
    /// Finish this original location or retain its unchanged cursor on local refusal.
    /// Only the enclosing immutable source owner may reuse this cursor.
    pub(crate) fn advance<W: MusubiRead>(
        &mut self,
        location: &MusubiArchiveLocationV1,
        world: &W,
    ) -> Result<Option<CurrentLocationProviders>, W::Error> {
        if self.unavailable {
            return Ok(None);
        }
        if self.phase == 8 {
            return Ok(Some(self.providers));
        }
        let result = self.advance_inner(location, world)?;
        if result.is_none() {
            self.unavailable = true;
        }
        Ok(result)
    }
    fn advance_inner<W: MusubiRead>(
        &mut self,
        location: &MusubiArchiveLocationV1,
        world: &W,
    ) -> Result<Option<CurrentLocationProviders>, W::Error> {
        if self.phase == 0 {
            if location.state == MusubiArchiveLocationStateV1::Retired
                || location.validate().is_err()
            {
                return Ok(None);
            }
            self.phase = 1;
        }
        let key = location.key();
        if self.phase == 1 {
            if !world
                .musubi_locations_by_pin_get_retained(&location.pin_manifest, &mut self.queries[0])?
                .is_some_and(|reference| reference.active && reference.location == key)
            {
                return Ok(None);
            }
            self.phase = 2;
        }
        if self.phase <= 6 {
            let Some(archive) =
                world.musubi_archives_get_retained(&location.archive_id, &mut self.queries[1])?
            else {
                return Ok(None);
            };
            if self.phase == 2 {
                if archive.validate().is_err() {
                    return Ok(None);
                }
                self.phase = 3;
            }
            if self.phase == 3 {
                let lifecycle =
                    match self
                        .binding
                        .advance(archive, &location.replication_order, world)
                    {
                        Ok(lifecycle) => lifecycle,
                        Err(ReadFailure::Predicate(_)) => return Ok(None),
                        Err(ReadFailure::Source(original)) => return Err(original),
                    };
                if !matches!(lifecycle, MusubiReplicationOrderLocationLifecycleV1::Active(bound_location) if *bound_location == key)
                {
                    return Ok(None);
                }
                self.phase = 4;
            }
            if self.phase == 4 {
                let Some(pin) = world
                    .pin_manifests_get_retained(&location.pin_manifest, &mut self.queries[2])?
                else {
                    return Ok(None);
                };
                if !pin.status.is_active()
                    || pin.root_cid != archive.commitment.root_cid
                    || pin.chunker != archive.commitment.chunker
                    || pin.chunk_digest_sha3_256 != *archive.commitment.chunk_plan_digest.as_bytes()
                    || pin.por_root != *archive.commitment.por_root.as_bytes()
                    || pin.content_length != archive.commitment.content_length
                    || pin.policy.retention_epoch != location.expires_at_epoch
                {
                    return Ok(None);
                }
                self.phase = 5;
            }
            if self.phase == 5 {
                let Some(order) = world.replication_orders_get_retained(
                    &location.replication_order,
                    &mut self.queries[3],
                )?
                else {
                    return Ok(None);
                };
                if order.manifest_digest != location.pin_manifest
                    || order.manifest_root_cid != archive.commitment.root_cid
                    || !matches!(order.status, ReplicationOrderStatus::Completed(_))
                {
                    return Ok(None);
                }
                if order.provider_completions.len() != location.providers.len() {
                    return Ok(None);
                }
                for (index, slot) in self.completions[..location.providers.len()]
                    .iter_mut()
                    .enumerate()
                {
                    *slot = index;
                }
                self.completions[..location.providers.len()]
                    .sort_unstable_by_key(|index| order.provider_completions[*index].provider_id);
                if !self.completions[..location.providers.len()]
                    .iter()
                    .zip(&location.providers)
                    .all(|(index, provider)| {
                        order.provider_completions[*index].provider_id == *provider
                    })
                {
                    return Ok(None);
                }
                self.phase = 6;
            }
            if self.phase == 6 {
                match self
                    .attestations
                    .advance(archive, location, world, |_, _| {})
                {
                    Ok(()) => {}
                    Err(ReadFailure::Predicate(_)) => return Ok(None),
                    Err(ReadFailure::Source(original)) => return Err(original),
                }
                self.phase = 7;
            }
        }
        let Some(order) = world
            .replication_orders_get_retained(&location.replication_order, &mut self.queries[3])?
        else {
            return Ok(None);
        };
        while self.provider < location.providers.len() {
            let provider = &location.providers[self.provider];
            if self.provider_step == 0 {
                let reverse_key = MusubiProviderLocationKeyV1::new(*provider, key);
                if world
                    .musubi_locations_by_provider_get_retained(&reverse_key, &mut self.queries[4])?
                    .is_none()
                {
                    self.provider += 1;
                    self.queries[4..]
                        .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                    continue;
                }
                self.provider_step = 1;
            }
            let Some(owner) = world.provider_owners_get_retained(provider, &mut self.queries[5])?
            else {
                self.provider += 1;
                self.queries[4..]
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                self.provider_step = 0;
                continue;
            };
            // Reborrow the already verified original record. No signature or model
            // validation is repeated, and no record/controller is copied into scratch.
            let attestation_key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: location.archive_id,
                replication_order: location.replication_order,
                provider_id: *provider,
            };
            let Some(record) = world.musubi_provider_bundle_attestations_get_retained(
                &attestation_key,
                &mut self.queries[6],
            )?
            else {
                return Ok(None);
            };
            let completion = &order.provider_completions[self.completions[self.provider]];
            let binding = &record.attestation.payload.binding;
            if completion.completed_by == completion.completion_authority.completion_signer
                && completion.completion_authority.provider_owner == *owner
                && binding.provider_id == *provider
                && binding.completed_by == completion.completed_by
                && binding.completion_authority == completion.completion_authority
                && binding.assignment_revision == completion.assignment_revision
                && binding.completion_epoch == completion.completion_epoch
                && binding.finalized_anchor == completion.finalized_anchor
            {
                self.providers.values[self.providers.len] = *provider;
                self.providers.len += 1;
            }
            self.provider += 1;
            self.queries[4..]
                .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
            self.provider_step = 0;
        }
        self.phase = 8;
        Ok(Some(self.providers))
    }
}
