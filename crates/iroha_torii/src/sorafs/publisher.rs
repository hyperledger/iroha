//! Publisher-authenticated initial source staging under exact native finalized assignments.

use crate::SharedAppState;
use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use iroha_core::query::provider_ingest_source::{
    PublisherSourceBindingV1, authorize_publisher_source_v1,
};
use iroha_core::state::WorldReadOnly;
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    pin_registry::{ManifestDigest, ReplicationOrderId},
};
use mv::storage::StorageReadOnly;
use sorafs_car::publisher::PublisherSourceRequestV1;

fn publication_now() -> Result<u64, StatusCode> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Stage one authenticated metadata reservation or one chunk; never admit or complete a pin.
pub async fn stage_source(
    State(state): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    body: Bytes,
) -> Response {
    let permit = match crate::acquire_query_admission(state.as_ref(), true).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let result = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            let _permit = permit;
            let request =
                PublisherSourceRequestV1::decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            let (binding, manifest) = match &request {
                PublisherSourceRequestV1::Metadata(header) => {
                    let (manifest, _) = header.verify().map_err(|_| StatusCode::BAD_REQUEST)?;
                    let binding = PublisherSourceBindingV1 {
                        provider_id: ProviderId::new(header.provider_id),
                        order_id: ReplicationOrderId::new(header.order_id),
                        assignment_revision: header.assignment_revision,
                        manifest_digest: ManifestDigest::from_manifest(&manifest)
                            .map_err(|_| StatusCode::BAD_REQUEST)?,
                    };
                    (binding, Some(manifest))
                }
                PublisherSourceRequestV1::Chunk(chunk) => (
                    PublisherSourceBindingV1 {
                        provider_id: ProviderId::new(chunk.provider_id),
                        order_id: ReplicationOrderId::new(chunk.order_id),
                        assignment_revision: chunk.assignment_revision,
                        manifest_digest: ManifestDigest::new(chunk.manifest_digest),
                    },
                    None,
                ),
            };
            if state.sorafs_node.capacity_provider_id() != Some(binding.provider_id) {
                return Err(StatusCode::CONFLICT);
            }
            let authorize = || {
                let view = state.state.view();
                let authority = authorize_publisher_source_v1(
                    &view,
                    &verified.account,
                    &binding,
                    publication_now()?,
                )
                .map_err(|_| StatusCode::FORBIDDEN)?;
                if let Some(manifest) = &manifest {
                    let pin = view
                        .world()
                        .pin_manifests()
                        .get(&binding.manifest_digest)
                        .ok_or(StatusCode::NOT_FOUND)?;
                    if pin.root_cid.as_bytes().as_slice() != manifest.root_cid.as_slice()
                        || pin.chunk_digest_sha3_256 != manifest.chunk_digest_sha3_256
                        || pin.por_root != manifest.por_root
                        || pin.content_length != manifest.content_length
                    {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
                Ok::<_, StatusCode>(authority)
            };
            let authority = authorize()?;
            let storage = state
                .sorafs_node
                .storage()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            match &request {
                PublisherSourceRequestV1::Metadata(header) => {
                    storage
                        .stage_publisher_source(
                            header,
                            authority.deadline_epoch,
                            authority.finalized_epoch,
                        )
                        .map_err(|_| StatusCode::CONFLICT)?;
                }
                PublisherSourceRequestV1::Chunk(chunk) => {
                    storage
                        .stage_publisher_source_chunk(chunk, authority.finalized_epoch)
                        .map_err(|_| StatusCode::CONFLICT)?;
                }
            }
            authorize()?;
            Ok::<_, StatusCode>(())
        }),
    )
    .await;
    match result {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(status)) => (status, "publisher source staging rejected").into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "publisher source staging unavailable",
        )
            .into_response(),
    }
}

fn canonical_response<T: norito::NoritoSerialize + norito::NoritoSchema>(
    value: &T,
    maximum: usize,
) -> Result<Response, StatusCode> {
    if norito::core::encoded_frame_len(value).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        > maximum
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let bytes = norito::to_bytes(value).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if bytes.len() > maximum {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-norito"),
            (axum::http::header::CACHE_CONTROL, "private, no-store"),
        ],
        bytes,
    )
        .into_response())
}

/// Return informational exact native rows; the client must challenge them through the assertion.
pub async fn prepare_publication(
    State(state): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    body: Bytes,
) -> Response {
    let permit = match crate::acquire_query_admission(state.as_ref(), true).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let result = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            let _permit = permit;
            let digest: ManifestDigest = norito::decode_canonical_with_limits(
                &body,
                norito::DecodeLimits::new(4096, 4096, 4096, 16384, 16),
            )
            .map_err(|_| StatusCode::BAD_REQUEST)?;
            let view = state.state.view();
            let hash = view
                .latest_block_hash()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            iroha_core::query::signer_finality::verify_signer_finality_v1(
                &view,
                view.height() as u64,
                *hash.as_ref(),
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let pin = view
                .world()
                .pin_manifests()
                .get(&digest)
                .ok_or(StatusCode::NOT_FOUND)?;
            if pin.submitted_by != verified.account {
                return Err(StatusCode::FORBIDDEN);
            }
            let order_id =
                iroha_data_model::sorafs::pin_registry::derive_sorafs_auto_replication_order_id_v1(
                    &digest,
                );
            let order = view
                .world()
                .replication_orders()
                .get(&order_id)
                .ok_or(StatusCode::ACCEPTED)?;
            canonical_response(
                &iroha_data_model::sorafs::publication::SorafsPublicationPreparationV1 {
                    pin: pin.clone(),
                    order: order.clone(),
                },
                2 * 1024 * 1024,
            )
        }),
    )
    .await;
    match result {
        Ok(Ok(response)) => response,
        Ok(Err(status)) => status.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// Serve exact successful assertion carriers without bypassing full-ledger read permissions.
pub async fn publication_proof(
    State(state): State<SharedAppState>,
    Extension(verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
    body: Bytes,
) -> Response {
    use iroha_core::state::{StateReadOnlyWithTransactions, TransactionsReadOnly};
    use iroha_data_model::sorafs::publication::{
        PUBLICATION_PROOF_MAX_BLOCKS_V1, PUBLICATION_PROOF_MAX_BYTES_V1,
        SorafsPublicationProofRequestV1, SorafsPublicationProofV1,
    };

    if crate::require_full_ledger_carrier_permission(&state, &verified.account).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let permit = match crate::acquire_query_admission(state.as_ref(), true).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let response_state = state.clone();
    let result = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            let _permit = permit;
            let request: SorafsPublicationProofRequestV1 = norito::decode_canonical_with_limits(
                &body,
                norito::DecodeLimits::new(4096, 4096, 4096, 16384, 16),
            )
            .map_err(|_| StatusCode::BAD_REQUEST)?;
            if request.floor_height == 0
                || request.floor_block_hash == [0; 32]
                || request.entry_hash == [0; 32]
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            let hash = iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
                request.entry_hash,
            ));
            let view = state.state.view();
            let height = view
                .transactions()
                .get(&hash)
                .ok_or(StatusCode::ACCEPTED)?
                .get() as u64;
            let count = height
                .checked_sub(request.floor_height)
                .and_then(|span| span.checked_add(1))
                .ok_or(StatusCode::CONFLICT)?;
            if count < 2 || count > PUBLICATION_PROOF_MAX_BLOCKS_V1 as u64 {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            let mut lineage = Vec::new();
            let mut total_bytes = 0usize;
            for candidate in request.floor_height..=height {
                let artifact = iroha_core::sumeragi::finality::build_proof(&view, candidate)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if candidate == request.floor_height
                    && *artifact.block_header.hash().as_ref() != request.floor_block_hash
                {
                    return Err(StatusCode::CONFLICT);
                }
                total_bytes = total_bytes
                    .checked_add(
                        norito::canonical_frame_len(&artifact)
                            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                    )
                    .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
                if total_bytes > PUBLICATION_PROOF_MAX_BYTES_V1 {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                lineage.push(artifact);
            }
            canonical_response(
                &SorafsPublicationProofV1 { lineage },
                PUBLICATION_PROOF_MAX_BYTES_V1,
            )
        }),
    )
    .await;
    if crate::require_full_ledger_carrier_permission(&response_state, &verified.account).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    match result {
        Ok(Ok(response)) => response,
        Ok(Err(status)) => status.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
