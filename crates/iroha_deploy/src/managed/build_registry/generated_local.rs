//! Original generated-local intent and fresh native discovery; no readiness or activation owner.

use super::*;
use crate::{
    localnet::{LocalnetServiceProfile, service_authorities::StreamTokenAuthorityRole},
    managed::{
        PreparedLocalnet,
        native_operation::{
            ManagedTransactionFinality, invalid, now_ms, read_selected_peers, require_deadline,
        },
        service_authority::{NetworkPurpose, ServiceAuthority},
        stream_token_custody::{ManagedStreamTokenCustody, RetainedCustodyEnrollment},
    },
};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    provider_admission::discovery::account_read::VerifiedAccountReadProviderV1,
};
use iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock;
use iroha_storage_client::musubi_archive_fetch::GeneratedLocalProviderTransportV1;

pub(super) fn prepare(
    prepared: PreparedLocalnet,
    deadline: Instant,
) -> Result<Option<(Config, PreparedMusubiArchiveFetchConfigV1)>> {
    require_deadline(deadline)?;
    if prepared.context.dataspace_id != 0
        || prepared.service_profile != LocalnetServiceProfile::StreamTokenAuthorities
    {
        return Ok(None);
    }
    let authority = ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry)?;
    let plans = authority.provider_plans()?;
    let config = authority.config.clone();
    let mut originals = Vec::with_capacity(3);
    for (slot, plan) in plans.iter().enumerate() {
        let inventory = authority.provider_inventory(plan.provider_id())?;
        if plan.network_id() != config.network_id
            || usize::from(plan.slot()) != slot
            || plan.peer_index() != slot
            || &plan.reserve_terms().provider_account
                != &inventory
                    .authority(StreamTokenAuthorityRole::IssuerOperator)?
                    .account
        {
            return Err(invalid("generated build registry original scope differs"));
        }
        originals.push(
            GeneratedLocalProviderTransportV1::select(
                plan.network_id(),
                config.chain.as_str(),
                plan.provider_id(),
                &plan.reserve_terms().provider_account,
                plan.admission_material(),
            )
            .map_err(|_| invalid("invalid original generated provider transport"))?,
        );
    }
    let originals = originals
        .try_into()
        .map_err(|_| invalid("generated transport count differs"))?;
    // This closure is retained by the prepared configuration and every client built from it.
    // The original operation.lock therefore cannot be released between discovery and use.
    let owner = Mutex::new(authority);
    let transport = PreparedMusubiArchiveFetchConfigV1::from_generated_local_account_registry(
        config.clone(),
        Arc::new(move |provider| {
            check_deadline(deadline)?;
            let mut owner = owner.try_lock().map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => MusubiArchiveDiscoveryErrorV1::Unavailable,
                std::sync::TryLockError::Poisoned(_) => MusubiArchiveDiscoveryErrorV1::Rejected,
            })?;
            discover(&mut owner, provider, deadline).map(|(current, _)| current)
        }),
        originals,
        DISCOVERY_FRESHNESS,
    )
    .map_err(|_| invalid("cannot prepare generated build registry"))?;
    require_deadline(deadline)?;
    Ok(Some((config, transport)))
}

/// Timing from actual current native discovery, not an activation or signing capability.
/// Only the existing verifier below constructs this observation.
pub(in crate::managed) struct GeneratedServiceObservation {
    valid_until_unix_ms: u64,
    advert_issued_at_unix_ms: u64,
    advert_expires_at_unix_ms: u64,
}
impl GeneratedServiceObservation {
    pub(in crate::managed) fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
    pub(in crate::managed) fn advert_interval(&self) -> (u64, u64) {
        (
            self.advert_issued_at_unix_ms,
            self.advert_expires_at_unix_ms,
        )
    }
}

/// Read-only startup postcondition, reusing exactly the cold registry's native verifier.
/// The minimum is only a rejection bound; it cannot create authenticated state.
pub(in crate::managed) fn observe_generated_service(
    prepared: &PreparedLocalnet,
    provider: ProviderId,
    enrollment: &RetainedCustodyEnrollment,
    required: ManagedTransactionFinality,
    deadline: Instant,
) -> Result<GeneratedServiceObservation> {
    require_deadline(deadline)?;
    if required.height < enrollment.finalized().height
        || (required.height == enrollment.finalized().height && &required != enrollment.finalized())
        || required.height == 0
        || *required.block_hash.as_ref() == [0; 32]
        || prepared.context.dataspace_id != 0
        || prepared.service_profile != LocalnetServiceProfile::StreamTokenAuthorities
    {
        return Err(invalid("generated activation discovery scope differs"));
    }
    let parent = crate::managed::service_bootstrap::ManagedServiceBootstrap::open(prepared)?;
    let policies = parent.selected_policies()?;
    drop(parent);
    let policies = policies.provider(provider)?;
    if enrollment.statement().binding != policies.custody.binding {
        return Err(invalid(
            "selected enrollment differs from original custody policy",
        ));
    }
    // A prepared archive transport owns BuildRegistry for its entire client lifetime. The
    // worker's bounded observations retain a separate exclusive cursor, with the same original
    // profile admission and native discovery verifier; neither owner can block the other.
    let mut owner = ServiceAuthority::open_network(prepared, NetworkPurpose::ServiceObservation)?;
    let (current, block) = discover(&mut owner, provider, deadline)
        .map_err(|_| invalid("fresh native generated provider discovery is unavailable"))?;
    // The sole custody owner qualifies the exact retained record at discovery's same
    // independently authenticated Global cut, including sequence, bytes and revocation.
    ManagedStreamTokenCustody::open(prepared, provider)?.verify_current_enrollment_at(
        enrollment,
        &policies.custody,
        required.height,
        *required.block_hash.as_ref(),
        &block,
        deadline,
    )?;
    if current.discovery().height() < required.height
        || current.token_public_key() != &policies.custody.binding.public_key
        || u64::from(current.token_key_revision()) != policies.custody.binding.key_revision
        || current.enrollment_expires_at_unix_ms() != enrollment.statement().expires_at_unix_ms
    {
        return Err(invalid(
            "current native provider signer differs from original activation",
        ));
    }
    let plan = owner
        .provider_plans()?
        .iter()
        .find(|plan| plan.provider_id() == provider)
        .ok_or_else(|| invalid("original generated provider plan is absent"))?;
    GeneratedLocalProviderTransportV1::select(
        plan.network_id(),
        owner.config.chain.as_str(),
        plan.provider_id(),
        &plan.reserve_terms().provider_account,
        plan.admission_material(),
    )
    .and_then(|original| original.authenticate_current(&current))
    .map_err(|_| invalid("current native provider differs from original generated transport"))?;
    let valid_until = current
        .enrollment_expires_at_unix_ms()
        .min(policies.custody.active_until_unix_ms)
        .min(policies.gateway.valid_until_unix_ms)
        .min(
            current
                .discovery()
                .admission()
                .envelope()
                .retention_epoch
                .checked_mul(1_000)
                .ok_or_else(|| invalid("provider admission interval overflow"))?,
        )
        .min(
            current
                .discovery()
                .advert()
                .expires_at
                .checked_mul(1_000)
                .ok_or_else(|| invalid("provider advertisement interval overflow"))?,
        );
    owner.validate_profile()?;
    require_deadline(deadline)?;
    if now_ms()? >= valid_until {
        return Err(invalid("native generated provider observation expired"));
    }
    Ok(GeneratedServiceObservation {
        valid_until_unix_ms: valid_until,
        advert_issued_at_unix_ms: current
            .discovery()
            .advert()
            .issued_at
            .checked_mul(1_000)
            .ok_or_else(|| invalid("provider advertisement interval overflow"))?,
        advert_expires_at_unix_ms: current
            .discovery()
            .advert()
            .expires_at
            .checked_mul(1_000)
            .ok_or_else(|| invalid("provider advertisement interval overflow"))?,
    })
}

fn discover(
    owner: &mut ServiceAuthority,
    provider: ProviderId,
    deadline: Instant,
) -> std::result::Result<
    (VerifiedAccountReadProviderV1, VerifiedSumeragiBlock),
    MusubiArchiveDiscoveryErrorV1,
> {
    check_deadline(deadline)?;
    owner
        .provider_inventory(provider)
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?;
    owner
        .validate_profile()
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?;
    let finality = owner.observe_finality(deadline);
    check_deadline(deadline)?;
    let finality = finality.map_err(|_| MusubiArchiveDiscoveryErrorV1::Unavailable)?;
    let block = finality
        .verified_tip()
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?;
    block
        .verify_global_scope(owner.config.network_id, owner.config.chain.as_str())
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?;
    let schema = iroha_core::state::State::native_world_schema_hash_v1()
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Unavailable)?;
    let result = read_selected_peers(&owner.peers, deadline, |client, selected_deadline| {
        client
            .with_request_deadline(selected_deadline)
            .get_account_read_provider_discovery(provider, schema, &block, now_ms()?)
            .map_err(|_| invalid("generated native provider discovery unavailable or invalid"))
    });
    check_deadline(deadline)?;
    let verified = result.map_err(|_| MusubiArchiveDiscoveryErrorV1::Unavailable)?;
    let discovery = verified.discovery();
    if verified.chain_id() != owner.config.chain.as_str()
        || discovery.network_id() != owner.config.network_id
        || discovery.height() != block.height()
        || discovery.context_id() != block.context_id()
        || discovery.owner()
            != &owner
                .provider_inventory(provider)
                .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?
                .authority(StreamTokenAuthorityRole::IssuerOperator)
                .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?
                .account
    {
        return Err(MusubiArchiveDiscoveryErrorV1::Rejected);
    }
    owner
        .validate_profile()
        .map_err(|_| MusubiArchiveDiscoveryErrorV1::Rejected)?;
    check_deadline(deadline)?;
    Ok((verified, block))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod activation_tests;

#[cfg(test)]
mod readback_origin_tests;
