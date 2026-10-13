//! Publisher-owned acquisition of immutable provider attestations from original configured origins.
//! Native registration remains the current eligibility fence; HTTP inventories never prove finality.
use super::*;
use std::time::Instant;

const SET_LIMITS: DecodeLimits = DecodeLimits::new(
    MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES,
    MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES,
    2 * MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES,
    16 * MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES,
    128,
);

pub fn parse_attestation_origin(
    raw: &str,
) -> Result<Url, ProductionPublicationConfigurationErrorV1> {
    let invalid = || {
        ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_ATTESTATION_ORIGIN_INVALID",
        )
    };
    if raw.is_empty() || raw.len() > 2048 {
        return Err(invalid());
    }
    let url: Url = raw.parse().map_err(|_| invalid())?;
    if url.as_str() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || !(url.scheme() == "https"
            || url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1")))
    {
        return Err(invalid());
    }
    Ok(url)
}

fn invalid_set() -> PublicationBackendError {
    PublicationBackendError::permanent("PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID")
}

pub(super) fn validate_original_attestations(
    request: &PublicationRequestV1,
    response: &MusubiStorageCoordinationResponseV1,
    attestations: &[MusubiProviderBundleVerificationAttestationV1],
) -> Result<(), PublicationBackendError> {
    let MusubiStorageLocationDispositionV1::NeedsRegistration {
        completed_providers,
        ..
    } = &response.disposition
    else {
        return Err(PublicationBackendError::permanent(
            "ARCHIVE_LOCATION_UNJOURNALED_FINALITY",
        ));
    };
    if completed_providers.len()
        < usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
        || completed_providers.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
        || completed_providers.len() != attestations.len()
        || completed_providers
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid_set());
    }
    for (provider, attestation) in completed_providers.iter().zip(attestations) {
        attestation
            .verify(&attestation.payload.binding)
            .map_err(|_| invalid_set())?;
        let binding = &attestation.payload.binding;
        if binding.provider_id != *provider
            || binding.network_id != request.network_id()
            || binding.archive_id != request.archive_commitment.archive_id()
            || binding.replication_order != response.replication_order
            || binding.bundle_digest != request.archive_commitment.bundle_digest
            || binding.descriptor_digest != request.archive_commitment.descriptor_digest
            || binding.source_tree_digest != request.archive_commitment.source_tree_digest
            || binding.semantic_release_manifest_digest
                != response
                    .archive
                    .staging_receipt
                    .payload
                    .binding
                    .semantic_release_manifest_digest
            || binding.verification_lock_digest
                != request.publication.manifest.verification_lock_digest
        {
            return Err(invalid_set());
        }
    }
    Ok(())
}

impl<V> ProductionPublicationRuntimeV1<V> {
    /// Reuse the exact full original set before considering any additional provider request.
    pub(super) fn acquire_provider_attestation_set(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        request: &PublicationRequestV1,
        response: &MusubiStorageCoordinationResponseV1,
        anchored: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<PublicationProviderAttestationSetCheckpointV1, PublicationBackendError> {
        norito::with_decode_limits_scope(SET_LIMITS, || {
            let path = provider_attestation_set_checkpoint_relative_path(operation_id, generation);
            if let Some(bytes) = self
                .checkpoint_root()?
                .load_immutable(&path, MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES)
                .map_err(map_provider_checkpoint_io)?
            {
                let retained: PublicationProviderAttestationSetCheckpointV1 =
                    norito::decode_canonical_with_limits(&bytes, SET_LIMITS)
                        .map_err(|_| invalid_set())?;
                retained.validate()?;
                if retained.operation_id != operation_id
                    || retained.generation != generation
                    || retained.archive_id != request.archive_commitment.archive_id()
                    || retained.replication_order != response.replication_order
                    || encode_attestation_set_checkpoint(&retained)? != bytes
                {
                    return Err(invalid_set());
                }
                validate_original_attestations(request, response, &retained.attestations)?;
                if let Some(checkpoint) = anchored {
                    checkpoint
                        .validate_for(request, generation)
                        .map_err(|_| invalid_set())?;
                    if (
                        checkpoint.archive_id,
                        checkpoint.replication_order,
                        checkpoint.provider_attestation_set_digest,
                    ) != (
                        retained.archive_id,
                        retained.replication_order,
                        retained.set_digest,
                    ) {
                        return Err(invalid_set());
                    }
                    self.validate_anchored_attestation_set_checkpoint(
                        &retained,
                        checkpoint.set_sidecar_hash,
                    )?;
                }
                return Ok(retained);
            }
            if anchored.is_some() {
                return Err(PublicationBackendError::permanent(
                    "PROVIDER_ATTESTATION_SET_CHECKPOINT_MISSING",
                ));
            }
            let MusubiStorageLocationDispositionV1::NeedsRegistration {
                completed_providers,
                ..
            } = &response.disposition
            else {
                return Err(PublicationBackendError::permanent(
                    "ARCHIVE_LOCATION_UNJOURNALED_FINALITY",
                ));
            };
            if completed_providers.len()
                < usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
                || completed_providers.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
                || completed_providers
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || completed_providers
                    .iter()
                    .any(|id| id.as_bytes() == &[0; 32] || !self.provider_gateways.contains_key(id))
            {
                return Err(invalid_set());
            }
            let deadline = Instant::now()
                .checked_add(self.request_timeout)
                .ok_or_else(invalid_set)?;
            let mut attestations = Vec::new();
            norito::core::reserve_decode_allocation(
                completed_providers.len()
                    * std::mem::size_of::<MusubiProviderBundleVerificationAttestationV1>(),
            )
            .map_err(|_| invalid_set())?;
            attestations
                .try_reserve_exact(completed_providers.len())
                .map_err(|_| invalid_set())?;
            let mut total = 0usize;
            for provider in completed_providers {
                let endpoint = &self.provider_gateways[provider].attestation;
                let key = MusubiProviderBundleAttestationKeyV1 {
                    archive_id: request.archive_commitment.archive_id(),
                    replication_order: response.replication_order,
                    provider_id: *provider,
                };
                let attestation = self
                    .signing
                    .provider_attestation_at(endpoint, key, deadline)
                    .map_err(map_registry_error)?
                    .ok_or_else(|| {
                        PublicationBackendError::retryable("PROVIDER_ATTESTATION_INVENTORY_PENDING")
                    })?;
                let length =
                    norito::canonical_frame_len(&attestation).map_err(|_| invalid_set())?;
                total = total.checked_add(length).ok_or_else(invalid_set)?;
                if total > MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES {
                    return Err(invalid_set());
                }
                attestations.push(attestation);
            }
            if Instant::now() >= deadline {
                return Err(PublicationBackendError::retryable(
                    "PROVIDER_ATTESTATION_INVENTORY_DEADLINE",
                ));
            }
            validate_original_attestations(request, response, &attestations)?;
            let retained = PublicationProviderAttestationSetCheckpointV1::new(
                operation_id,
                generation,
                response.archive.archive_id,
                response.replication_order,
                attestations,
            )?;
            // Full original bytes are durable before any registration payload/signature is prepared.
            self.persist_attestation_set_checkpoint(&retained)?;
            Ok(retained)
        })
    }
}
