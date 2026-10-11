//! Torii handlers for DA commitments (DA-3).
//!
//! These endpoints operate on the in-memory commitment index populated during
//! block application. Durable WSV plumbing can replace the backing store once
//! available without changing the handler surface.
use crate::{Error, JsonBody, NoritoJson, SharedAppState};
use axum::extract::State;
use iroha_config::parameters::actual::Nexus;
use iroha_core::da::{
    ActiveLaneProofPolicyContext, active_proof_policy_bundle_at_height, build_da_commitment_proof,
    commitment_store::DaCommitmentStore, verify_da_commitment_proof,
};
use iroha_data_model::da::commitment::{
    DaCommitmentKey, DaCommitmentProof, DaCommitmentWithLocation, DaProofPolicyBundle,
};
use iroha_torii_shared::da::{
    DaCommitmentListCursor, DaCommitmentListRequest, DaCommitmentListResponse,
    DaCommitmentProofRequest, DaCommitmentProofResponse, DaCommitmentVerifyResponse,
    DaListSnapshot, DaQueryValidationError,
};
use std::num::NonZeroUsize;
#[cfg(test)]
const ENDPOINT_DA_COMMITMENTS: &str = "/v1/da/commitments";
#[cfg(test)]
const ENDPOINT_DA_COMMITMENTS_PROVE: &str = "/v1/da/commitments/prove";
#[cfg(test)]
const ENDPOINT_DA_COMMITMENTS_VERIFY: &str = "/v1/da/commitments/verify";
/// HTTP handler for `/v1/da/commitments`.
pub async fn handler_list_commitments(
    State(app): State<SharedAppState>,
    NoritoJson(request): NoritoJson<DaCommitmentListRequest>,
) -> Result<JsonBody<DaCommitmentListResponse>, Error> {
    let snapshot = list_snapshot_for_state(app.state.as_ref());
    let nexus = app.state.nexus_snapshot();
    let page = {
        let store = app
            .state
            .da_commitments()
            .map_err(crate::canonical_history::da_hydration_error)?;
        list_active_from_store(&store, &request, &nexus, snapshot).map_err(commitment_list_error)?
    };
    let policies = active_proof_policy_bundle_for_state(&nexus, app.state.as_ref());
    if list_snapshot_for_state(app.state.as_ref()) != snapshot {
        return Err(Error::AppConflict {
            code: "da_list_snapshot_changed",
            message: "the committed ledger tip changed while the DA commitment page was read; retry from the first page".to_owned(),
        });
    }
    Ok(JsonBody(DaCommitmentListResponse {
        policies,
        commitments: page.commitments,
        next_cursor: page.next_cursor,
    }))
}
/// HTTP handler for `/v1/da/commitments/prove`.
pub async fn handler_prove_commitment(
    State(app): State<SharedAppState>,
    NoritoJson(request): NoritoJson<DaCommitmentProofRequest>,
) -> Result<JsonBody<Option<DaCommitmentProofResponse>>, Error> {
    request
        .validate()
        .map_err(|error| Error::AppQueryValidation {
            code: "invalid_da_commitment_selector",
            message: error.to_string(),
        })?;
    let nexus = app.state.nexus_snapshot();
    let proof = build_active_proof_from_state(&request, &nexus, app.state.as_ref())?;
    proof.map_or_else(
        || Ok(JsonBody(None)),
        |(proof, policies)| {
            Ok(JsonBody(Some(DaCommitmentProofResponse {
                policies,
                proof,
            })))
        },
    )
}
/// HTTP handler for `/v1/da/commitments/verify`.
pub async fn handler_verify_commitment(
    State(app): State<SharedAppState>,
    NoritoJson(proof): NoritoJson<DaCommitmentProof>,
) -> Result<JsonBody<DaCommitmentVerifyResponse>, Error> {
    let response = verify_against_kura_block(&proof, app.state.as_ref())?;
    Ok(JsonBody(response))
}
/// HTTP handler for `/v1/da/proof-policies`.
pub async fn handler_list_proof_policies(
    State(app): State<SharedAppState>,
) -> Result<JsonBody<DaProofPolicyBundle>, Error> {
    let nexus = app.state.nexus_snapshot();
    let policies = active_proof_policy_bundle_for_state(&nexus, app.state.as_ref());
    Ok(JsonBody(policies))
}
fn active_proof_policy_bundle_for_state(
    nexus: &Nexus,
    state: &iroha_core::state::State,
) -> DaProofPolicyBundle {
    let committed_height = u64::try_from(state.committed_height()).unwrap_or(u64::MAX);
    active_proof_policy_bundle_at_height(nexus, committed_height)
}
pub(super) fn list_snapshot_for_state(state: &iroha_core::state::State) -> DaListSnapshot {
    DaListSnapshot {
        block_height: u64::try_from(state.committed_height()).unwrap_or(u64::MAX),
        block_hash: state.latest_block_hash_fast(),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaCommitmentListError {
    InvalidRequest(DaQueryValidationError),
    StaleSnapshot,
    UnknownKey,
}
fn commitment_list_error(error: DaCommitmentListError) -> Error {
    let (code, message) = match error {
        DaCommitmentListError::InvalidRequest(error) => (
            if matches!(error, DaQueryValidationError::LimitOutOfRange { .. }) {
                "invalid_da_commitment_limit"
            } else {
                "invalid_da_commitment_cursor"
            },
            error.to_string(),
        ),
        DaCommitmentListError::StaleSnapshot => (
            "stale_da_commitment_cursor",
            "DA commitment cursor does not target the current committed ledger tip; restart from the first page".to_owned(),
        ),
        DaCommitmentListError::UnknownKey => (
            "invalid_da_commitment_cursor",
            "DA commitment cursor key is absent from the current active query index".to_owned(),
        ),
    };
    Error::AppQueryValidation { code, message }
}
#[derive(Debug)]
struct DaCommitmentPage {
    commitments: Vec<DaCommitmentWithLocation>,
    next_cursor: Option<DaCommitmentListCursor>,
}
fn list_active_from_store(
    store: &DaCommitmentStore,
    request: &DaCommitmentListRequest,
    nexus: &Nexus,
    snapshot: DaListSnapshot,
) -> Result<DaCommitmentPage, DaCommitmentListError> {
    let policy_context = ActiveLaneProofPolicyContext::new(nexus);
    list_page_from_store(store, request, snapshot, |record| {
        commitment_lane_is_active(&policy_context, record)
    })
}
fn list_page_from_store(
    store: &DaCommitmentStore,
    request: &DaCommitmentListRequest,
    snapshot: DaListSnapshot,
    mut is_visible: impl FnMut(&DaCommitmentWithLocation) -> bool,
) -> Result<DaCommitmentPage, DaCommitmentListError> {
    let limit = request
        .page_size()
        .map_err(DaCommitmentListError::InvalidRequest)?;
    let after = request.cursor.map(|cursor| {
        if cursor.snapshot != snapshot {
            return Err(DaCommitmentListError::StaleSnapshot);
        }
        if !store.contains_query_key(cursor.after) {
            return Err(DaCommitmentListError::UnknownKey);
        }
        Ok(cursor.after)
    });
    let after = after.transpose()?;
    let mut ordered = store.all_sorted_after(after);
    let mut commitments = Vec::with_capacity(limit);
    let mut last_examined = None;
    for record in ordered.by_ref().take(limit) {
        last_examined = Some(DaCommitmentKey::from_record(&record.commitment));
        if is_visible(record) {
            commitments.push(record.clone());
        }
    }
    let next_cursor = if ordered.next().is_some() {
        last_examined.map(|after| DaCommitmentListCursor { snapshot, after })
    } else {
        None
    };
    Ok(DaCommitmentPage {
        commitments,
        next_cursor,
    })
}
fn commitment_lane_is_active(
    policy_context: &ActiveLaneProofPolicyContext<'_>,
    target: &DaCommitmentWithLocation,
) -> bool {
    policy_context
        .policy_at_height(target.commitment.lane_id, target.location.block_height)
        .is_ok()
}
fn find_in_store(
    store: &DaCommitmentStore,
    request: &DaCommitmentProofRequest,
) -> Option<DaCommitmentWithLocation> {
    if let Some(manifest) = request.manifest_hash {
        let target = store.get_by_manifest(&manifest)?.clone();
        return request_matches_commitment(&target, request).then_some(target);
    }
    let (Some(lane_id), Some(epoch), Some(sequence)) =
        (request.lane_id, request.epoch, request.sequence)
    else {
        return None;
    };
    store
        .get_by_lane_epoch_sequence(lane_id, epoch, sequence)
        .cloned()
}
fn request_matches_commitment(
    target: &DaCommitmentWithLocation,
    request: &DaCommitmentProofRequest,
) -> bool {
    if request
        .lane_id
        .is_some_and(|lane_id| target.commitment.lane_id.as_u32() != lane_id)
    {
        return false;
    }
    if request
        .epoch
        .is_some_and(|epoch| target.commitment.epoch != epoch)
    {
        return false;
    }
    if request
        .sequence
        .is_some_and(|sequence| target.commitment.sequence != sequence)
    {
        return false;
    }
    true
}
#[cfg(test)]
fn build_proof_from_store(
    store: &DaCommitmentStore,
    request: &DaCommitmentProofRequest,
) -> Option<DaCommitmentProof> {
    let target = find_in_store(store, request)?;
    let bundle = store.bundle_at(target.location.block_height)?;
    let index = usize::try_from(target.location.index_in_bundle).ok()?;
    if bundle.commitments().get(index) != Some(&target.commitment) {
        return None;
    }
    build_da_commitment_proof(bundle, target.location.block_height, index)
}
fn build_active_proof_from_state(
    request: &DaCommitmentProofRequest,
    nexus: &Nexus,
    state: &iroha_core::state::State,
) -> Result<Option<(DaCommitmentProof, DaProofPolicyBundle)>, Error> {
    let policy_context = ActiveLaneProofPolicyContext::new(nexus);
    let target = {
        let store = state
            .da_commitments()
            .map_err(crate::canonical_history::da_hydration_error)?;
        find_in_store(&store, request)
    };
    let Some(target) = target else {
        return Ok(None);
    };
    if !commitment_lane_is_active(&policy_context, &target) {
        return Ok(None);
    }
    let Some(block_height) = usize::try_from(target.location.block_height)
        .ok()
        .and_then(NonZeroUsize::new)
    else {
        return Ok(None);
    };
    let Some(block) = state
        .block_by_height(block_height)
        .map_err(crate::canonical_history::canonical_attempt_error)?
    else {
        return Ok(None);
    };
    Ok((|| {
        let bundle = block.as_ref().da_commitments()?;
        let index = usize::try_from(target.location.index_in_bundle).ok()?;
        if bundle.commitments().get(index) != Some(&target.commitment) {
            return None;
        }
        let policies = block.as_ref().da_proof_policies()?.clone();
        let proof = build_da_commitment_proof(bundle, target.location.block_height, index)?;
        Some((proof, policies))
    })())
}
fn verify_against_kura_block(
    proof: &DaCommitmentProof,
    state: &iroha_core::state::State,
) -> Result<DaCommitmentVerifyResponse, Error> {
    let Ok(block_height) = usize::try_from(proof.location.block_height) else {
        return Ok(DaCommitmentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block height {} does not fit into usize for lookup",
                proof.location.block_height
            )),
        });
    };
    let Some(nonzero_height) = NonZeroUsize::new(block_height) else {
        return Ok(DaCommitmentVerifyResponse {
            valid: false,
            error: Some("proof references block height 0".to_string()),
        });
    };
    let Some(block) = state
        .block_by_height(nonzero_height)
        .map_err(crate::canonical_history::canonical_attempt_error)?
    else {
        return Ok(DaCommitmentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block {} not available in Kura",
                proof.location.block_height
            )),
        });
    };
    if block.as_ref().da_commitments().is_none() {
        return Ok(DaCommitmentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block {} does not contain a DA commitment bundle",
                proof.location.block_height
            )),
        });
    }
    let Some(policies) = block.as_ref().da_proof_policies() else {
        return Ok(DaCommitmentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block {} does not contain a DA proof-policy bundle",
                proof.location.block_height
            )),
        });
    };
    Ok(
        match verify_da_commitment_proof(proof, &block.header(), policies) {
            Ok(()) => DaCommitmentVerifyResponse {
                valid: true,
                error: None,
            },
            Err(err) => DaCommitmentVerifyResponse {
                valid: false,
                error: Some(err.to_string()),
            },
        },
    )
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    use super::*;
    use crate::{NoritoJson, mk_app_state_for_tests};
    use iroha_config::parameters::actual::LaneConfig as ConfigLaneConfig;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::nexus::{AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED};
    use iroha_data_model::{
        block::{BlockHeader, builder::BlockBuilder},
        da::{
            commitment::{DaCommitmentBundle, DaCommitmentRecord, DaProofScheme, RetentionClass},
            types::{BlobDigest, StorageTicketId},
        },
        nexus::{LaneCatalog, LaneConfig as ModelLaneConfig},
        sorafs::pin_registry::ManifestDigest,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_torii_shared::da::{DA_QUERY_REQUEST_MAX_BYTES, MAX_DA_QUERY_PAGE_SIZE};
    use std::{
        collections::BTreeMap,
        num::{NonZeroU32, NonZeroU64},
    };
    fn checked_random_keypair_with_algorithm(algorithm: Algorithm, context: &str) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm).unwrap_or_else(|err| {
            panic!("{context}: checked random {algorithm:?} key generation failed: {err}")
        })
    }
    fn sample_record(lane: u32, epoch: u64, sequence: u64) -> DaCommitmentRecord {
        let mut storage_ticket = [0x22; 32];
        storage_ticket[..4].copy_from_slice(&lane.to_be_bytes());
        storage_ticket[4..12].copy_from_slice(&epoch.to_be_bytes());
        storage_ticket[12..20].copy_from_slice(&sequence.to_be_bytes());
        DaCommitmentRecord::new(
            LaneId::new(lane),
            epoch,
            sequence,
            BlobDigest::new([lane as u8; 32]),
            ManifestDigest::new([epoch as u8; 32]),
            DaProofScheme::MerkleSha256,
            Hash::prehashed([sequence as u8; 32]),
            None,
            RetentionClass::default(),
            StorageTicketId::new(storage_ticket),
            Signature::try_from_bytes(&[0x33; 64])
                .expect("checked Torii DA commitment acknowledgement signature fixture"),
        )
    }
    fn lane_config_with_entries(entries: &[(LaneId, DaProofScheme)]) -> ConfigLaneConfig {
        ConfigLaneConfig::from_catalog(&lane_catalog_with_entries(entries))
    }
    fn lane_catalog_with_entries(entries: &[(LaneId, DaProofScheme)]) -> LaneCatalog {
        let max_lane = entries
            .iter()
            .map(|(lane, _)| lane.as_u32())
            .max()
            .unwrap_or(0);
        let lane_count = NonZeroU32::new(max_lane.saturating_add(1)).expect("lane count");
        let lanes: Vec<ModelLaneConfig> = entries
            .iter()
            .map(|(lane_id, scheme)| ModelLaneConfig {
                id: *lane_id,
                dataspace_id: DataSpaceId::UNIVERSAL,
                alias: format!("lane-{}", lane_id.as_u32()),
                proof_scheme: *scheme,
                ..ModelLaneConfig::default()
            })
            .collect();
        LaneCatalog::new(lane_count, lanes).expect("lane catalog")
    }
    fn store_with_records() -> DaCommitmentStore {
        let records = vec![
            sample_record(1, 1, 1),
            sample_record(1, 2, 0),
            sample_record(2, 3, 5),
        ];
        DaCommitmentStore::from_bundle_at_height(&records, 9)
    }
    fn list_request(limit: Option<u64>) -> DaCommitmentListRequest {
        DaCommitmentListRequest {
            limit: limit.and_then(NonZeroU64::new),
            cursor: None,
        }
    }
    fn install_stale_runtime_lane_geometry(app: &crate::SharedAppState, stale_lane: LaneId) {
        assert!(
            app.state
                .nexus_snapshot()
                .lane_config
                .entry(stale_lane)
                .is_none(),
            "the removed lane must be absent from authoritative runtime state"
        );
        let stale_geometry_catalog = lane_catalog_with_entries(&[
            (LaneId::new(0), DaProofScheme::MerkleSha256),
            (stale_lane, DaProofScheme::MerkleSha256),
        ]);
        let mut nexus = app.state.nexus.write();
        nexus.lane_config = ConfigLaneConfig::from_catalog(&stale_geometry_catalog);
        assert!(
            nexus.lane_config.entry(stale_lane).is_some(),
            "fixture must keep stale runtime geometry for the removed lane"
        );
        drop(nexus);
        let canonical = app.state.nexus_snapshot();
        assert!(canonical.lane_config.entry(stale_lane).is_none());
        assert!(
            !canonical
                .lane_catalog
                .lanes()
                .iter()
                .any(|lane| lane.id == stale_lane)
        );
    }
    fn future_created_autoscale_nexus(lane_id: LaneId, created_height: u64) -> Nexus {
        let mut elastic_lane = ModelLaneConfig {
            id: lane_id,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: format!("elastic-lane-{}", lane_id.as_u32()),
            proof_scheme: DaProofScheme::MerkleSha256,
            ..ModelLaneConfig::default()
        };
        elastic_lane
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        elastic_lane.metadata.insert(
            AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
            created_height.to_string(),
        );
        let lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane count"),
            vec![ModelLaneConfig::default(), elastic_lane],
        )
        .expect("future-created autoscale lane catalog");
        // A synthetic policy input, never admitted as committed State: real
        // lifecycle admission rejects a future creation height at the current tip.
        let mut nexus = Nexus::default();
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
        nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(3).expect("nonzero max lanes");
        nexus.lane_config = ConfigLaneConfig::from_catalog(&lane_catalog);
        nexus.lane_catalog = lane_catalog;
        nexus
    }
    fn install_uncommitted_autoscale_overlay(app: &crate::SharedAppState, lane_id: LaneId) {
        let overlay = future_created_autoscale_nexus(lane_id, 7);
        {
            let mut nexus = app.state.nexus.write();
            nexus.autoscale = overlay.autoscale;
            nexus.lane_config = overlay.lane_config;
            nexus.lane_catalog = overlay.lane_catalog;
            assert!(
                nexus.lane_catalog.lanes().iter().any(|lane| {
                    lane.id == lane_id && lane.autoscale_created_height() == Some(7)
                })
            );
        }
        let canonical = app.state.nexus_snapshot();
        assert!(!canonical.autoscale.enabled);
        assert!(canonical.lane_config.entry(lane_id).is_none());
        assert!(
            !canonical
                .lane_catalog
                .lanes()
                .iter()
                .any(|lane| lane.id == lane_id)
        );
    }
    fn nexus_for_records(records: &[DaCommitmentRecord]) -> Nexus {
        let mut lane_entries = BTreeMap::from([(LaneId::new(0), DaProofScheme::MerkleSha256)]);
        lane_entries.extend(
            records
                .iter()
                .map(|record| (record.lane_id, record.proof_scheme)),
        );
        let lane_entries = lane_entries.into_iter().collect::<Vec<_>>();
        let lane_catalog = lane_catalog_with_entries(&lane_entries);
        Nexus {
            lane_config: ConfigLaneConfig::from_catalog(&lane_catalog),
            configured_lane_catalog: lane_catalog.clone(),
            lane_catalog,
            ..Nexus::default()
        }
    }
    fn app_with_da_commitment_bundle(records: Vec<DaCommitmentRecord>) -> crate::SharedAppState {
        let current_nexus = nexus_for_records(&records);
        app_with_historical_commitments(records, current_nexus)
    }
    fn app_with_historical_commitments(
        records: Vec<DaCommitmentRecord>,
        current_nexus: Nexus,
    ) -> crate::SharedAppState {
        // Historical policy sidecars belong to their signed block, independently
        // of whether a lane still exists in the current authoritative catalog.
        let committed_policies =
            active_proof_policy_bundle_at_height(&nexus_for_records(&records), 1);
        for record in &records {
            assert!(
                committed_policies
                    .policies()
                    .iter()
                    .any(|policy| policy.lane_id == record.lane_id)
            );
        }
        // Kura and State must authenticate the intended catalog before any DA
        // block is seeded; the configured baseline is immutable after startup.
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
            iroha_core::state::World::default(),
            current_nexus,
        );
        let bundle = DaCommitmentBundle::new(records);
        let bundle_for_store = bundle.clone();
        let keypair = checked_random_keypair_with_algorithm(
            Algorithm::BlsNormal,
            "DA commitment block fixture",
        );
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        let mut builder = BlockBuilder::new(header);
        builder.set_da_proof_policies(Some(committed_policies));
        builder.set_da_commitments(Some(bundle));
        let block = builder.build_with_signature(0, keypair.private_key());
        let header = block.header();
        let block_height = header.height().get();
        let block_hash = block.hash();
        app.kura
            .store_block(
                iroha_data_model::block::SharedSignedBlock::try_new(
                    block,
                    &app.state.ivm_execution_budget(),
                )
                .expect("fund DA fixture block"),
            )
            .expect("store DA commitment block");
        let mut block_hashes = app.state.block_hashes.block();
        block_hashes.push_for_tests(block_hash);
        block_hashes.commit_for_tests();
        app.state.update_latest_block_header_cache_for_tests(header);
        drop(
            app.state
                .da_commitments()
                .expect("hydrate original DA fixture index"),
        );
        {
            let mut store = app.state.da_commitments.write();
            store.insert_bundle(block_height, bundle_for_store);
            assert!(
                store.bundle_at(block_height).is_some(),
                "DA commitment fixture must seed handler store"
            );
        }
        app
    }
    async fn prove_for_manifest(
        app: crate::SharedAppState,
        manifest: ManifestDigest,
    ) -> DaCommitmentProof {
        let JsonBody(response) = super::handler_prove_commitment(
            State(app),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        response.expect("proof should be returned").proof
    }
    async fn verify_invalid(
        app: crate::SharedAppState,
        proof: DaCommitmentProof,
        expected_error: &str,
    ) {
        let JsonBody(verification) =
            super::handler_verify_commitment(State(app), NoritoJson(proof))
                .await
                .expect("verify handler should succeed");
        assert!(!verification.valid);
        assert!(
            verification
                .error
                .as_deref()
                .is_some_and(|message| message.contains(expected_error)),
            "unexpected verification error: {verification:?}"
        );
    }
    #[test]
    fn list_uses_forward_only_keyset_cursor() {
        let store = store_with_records();
        let snapshot = DaListSnapshot {
            block_height: 0,
            block_hash: None,
        };
        let first = list_page_from_store(&store, &list_request(Some(2)), snapshot, |_| true)
            .expect("first page");
        assert_eq!(first.commitments.len(), 2);
        assert_eq!(first.commitments[0].location.index_in_bundle, 0);
        assert_eq!(first.commitments[1].location.index_in_bundle, 1);
        let cursor = first.next_cursor.expect("third row requires continuation");
        assert_eq!(
            cursor.after,
            DaCommitmentKey::from_record(&first.commitments[1].commitment)
        );
        let second = list_page_from_store(
            &store,
            &DaCommitmentListRequest {
                limit: NonZeroU64::new(2),
                cursor: Some(cursor),
            },
            snapshot,
            |_| true,
        )
        .expect("second page");
        assert_eq!(second.commitments.len(), 1);
        assert_eq!(second.commitments[0].location.index_in_bundle, 2);
        assert!(second.next_cursor.is_none());
    }
    #[test]
    fn list_overlarge_limit_is_rejected_before_scan() {
        use std::cell::Cell;

        let store = store_with_records();
        let snapshot = DaListSnapshot {
            block_height: 0,
            block_hash: None,
        };
        let examined = Cell::new(0_usize);
        let provided = u64::try_from(MAX_DA_QUERY_PAGE_SIZE).expect("page limit fits u64") + 1;
        let error = list_page_from_store(&store, &list_request(Some(provided)), snapshot, |_| {
            examined.set(examined.get() + 1);
            true
        })
        .expect_err("limit above the exact maximum must be rejected");
        assert_eq!(
            error,
            DaCommitmentListError::InvalidRequest(DaQueryValidationError::LimitOutOfRange {
                provided
            })
        );
        assert_eq!(
            examined.get(),
            0,
            "invalid limits must fail before scanning"
        );

        assert_eq!(
            list_page_from_store(&store, &list_request(Some(u64::MAX)), snapshot, |_| true)
                .expect_err("unrepresentable or overlarge limits must be rejected"),
            DaCommitmentListError::InvalidRequest(DaQueryValidationError::LimitOutOfRange {
                provided: u64::MAX
            })
        );
    }
    #[test]
    fn list_cursor_rejects_unknown_key_and_stale_snapshot() {
        let store = store_with_records();
        let snapshot = DaListSnapshot {
            block_height: 0,
            block_hash: None,
        };
        let unknown_key = DaCommitmentKey {
            lane_id: LaneId::new(9),
            epoch: 9,
            sequence: 9,
        };
        let unknown = DaCommitmentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaCommitmentListCursor {
                snapshot,
                after: unknown_key,
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &unknown, snapshot, |_| true)
                .expect_err("foreign key must fail closed"),
            DaCommitmentListError::UnknownKey
        );
        let valid_key = DaCommitmentKey::from_record(
            &store
                .all_sorted()
                .next()
                .expect("fixture has a first row")
                .commitment,
        );
        let stale = DaCommitmentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaCommitmentListCursor {
                snapshot: DaListSnapshot {
                    block_height: 1,
                    block_hash: Some(HashOf::from_untyped_unchecked(Hash::prehashed([7; 32]))),
                },
                after: valid_key,
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &stale, snapshot, |_| true)
                .expect_err("stale tip must fail closed"),
            DaCommitmentListError::StaleSnapshot
        );
    }
    #[test]
    fn list_cursor_rejects_noncanonical_snapshot() {
        let store = store_with_records();
        let snapshot = DaListSnapshot {
            block_height: 0,
            block_hash: None,
        };
        let after = DaCommitmentKey::from_record(
            &store
                .all_sorted()
                .next()
                .expect("fixture has a first row")
                .commitment,
        );
        let request = DaCommitmentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaCommitmentListCursor {
                snapshot: DaListSnapshot {
                    block_height: 1,
                    block_hash: None,
                },
                after,
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &request, snapshot, |_| true)
                .expect_err("malformed snapshot must fail closed"),
            DaCommitmentListError::InvalidRequest(DaQueryValidationError::NonCanonicalSnapshot)
        );
    }
    #[test]
    fn inactive_rows_cannot_amplify_the_raw_scan_budget() {
        use std::cell::Cell;
        let store = store_with_records();
        let snapshot = DaListSnapshot {
            block_height: 0,
            block_hash: None,
        };
        let examined = Cell::new(0_usize);
        let page = list_page_from_store(&store, &list_request(Some(2)), snapshot, |_| {
            examined.set(examined.get() + 1);
            false
        })
        .expect("bounded filtered page");
        assert!(page.commitments.is_empty());
        assert_eq!(examined.get(), 2, "visibility work is bounded by limit");
        assert!(
            page.next_cursor.is_some(),
            "an empty visible page must still permit deterministic traversal"
        );
    }
    #[test]
    fn prove_builds_merkle_proof() {
        let store = store_with_records();
        let request = DaCommitmentProofRequest {
            lane_id: Some(2),
            epoch: Some(3),
            sequence: Some(5),
            ..DaCommitmentProofRequest::default()
        };
        let proof = build_proof_from_store(&store, &request).expect("proof should exist");
        let bundle = store
            .bundle_at(proof.location.block_height)
            .expect("bundle present");
        let mut header = BlockHeader::new(
            NonZeroU64::new(proof.location.block_height).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        header.set_da_commitments_hash(bundle.merkle_commitment());
        let config = lane_config_with_entries(&[
            (LaneId::new(1), DaProofScheme::MerkleSha256),
            (LaneId::new(2), DaProofScheme::MerkleSha256),
        ]);
        let policies = iroha_core::da::proof_policy_bundle(&config);
        header.set_da_proof_policies_hash(Some(iroha_crypto::HashOf::new(&policies)));
        assert!(verify_da_commitment_proof(&proof, &header, &policies).is_ok());
    }
    #[test]
    fn prove_builds_merkle_proof_when_stale_duplicate_is_filtered_from_index() {
        let mut store = DaCommitmentStore::default();
        let first = sample_record(1, 1, 1);
        let mut stale_duplicate = first.clone();
        stale_duplicate.manifest_hash = ManifestDigest::new([0x55; 32]);
        stale_duplicate.storage_ticket = StorageTicketId::new([0x66; 32]);
        let later = sample_record(2, 3, 4);
        store.insert_bundle(7, DaCommitmentBundle::new(vec![first]));
        store.insert_bundle(
            8,
            DaCommitmentBundle::new(vec![stale_duplicate.clone(), later.clone()]),
        );
        let request = DaCommitmentProofRequest {
            lane_id: Some(2),
            epoch: Some(3),
            sequence: Some(4),
            ..DaCommitmentProofRequest::default()
        };
        let proof = build_proof_from_store(&store, &request)
            .expect("proof should use the raw committed bundle");
        assert_eq!(proof.location.block_height, 8);
        assert_eq!(proof.location.index_in_bundle, 1);
        assert_eq!(proof.commitment, later);
        let bundle = store
            .bundle_at(proof.location.block_height)
            .expect("committed bundle present");
        assert_eq!(bundle.commitments(), &[stale_duplicate, later]);
        let mut header = BlockHeader::new(
            NonZeroU64::new(proof.location.block_height).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        header.set_da_commitments_hash(bundle.merkle_commitment());
        let config = lane_config_with_entries(&[(LaneId::new(2), DaProofScheme::MerkleSha256)]);
        let policies = iroha_core::da::proof_policy_bundle(&config);
        header.set_da_proof_policies_hash(Some(iroha_crypto::HashOf::new(&policies)));
        assert!(verify_da_commitment_proof(&proof, &header, &policies).is_ok());
    }
    #[test]
    fn prove_returns_none_for_absent_and_partial_lookup_keys() {
        let store = store_with_records();
        let absent_manifest = DaCommitmentProofRequest {
            manifest_hash: Some(ManifestDigest::new([0x99; 32])),
            ..DaCommitmentProofRequest::default()
        };
        assert!(build_proof_from_store(&store, &absent_manifest).is_none());
        let partial_lane_tuple = DaCommitmentProofRequest {
            lane_id: Some(1),
            epoch: Some(1),
            sequence: None,
            ..DaCommitmentProofRequest::default()
        };
        assert!(build_proof_from_store(&store, &partial_lane_tuple).is_none());
        let wrong_sequence = DaCommitmentProofRequest {
            lane_id: Some(1),
            epoch: Some(1),
            sequence: Some(999),
            ..DaCommitmentProofRequest::default()
        };
        assert!(build_proof_from_store(&store, &wrong_sequence).is_none());
    }

    #[tokio::test]
    async fn proof_handler_rejects_missing_or_partial_selectors() {
        for request in [
            DaCommitmentProofRequest::default(),
            DaCommitmentProofRequest {
                lane_id: Some(4),
                epoch: Some(9),
                ..DaCommitmentProofRequest::default()
            },
        ] {
            let error = super::handler_prove_commitment(
                State(crate::mk_app_state_for_tests()),
                NoritoJson(request),
            )
            .await
            .expect_err("incomplete selector must fail before index lookup");
            assert!(matches!(
                error,
                Error::AppQueryValidation {
                    code: "invalid_da_commitment_selector",
                    ..
                }
            ));
        }
    }
    #[tokio::test]
    async fn list_handler_includes_policy_bundle() {
        let app = mk_app_state_for_tests();
        let request = DaCommitmentListRequest::default();
        let JsonBody(response) =
            super::handler_list_commitments(State(app.clone()), NoritoJson(request))
                .await
                .expect("handler should succeed");
        assert_eq!(response.policies.version(), DaProofPolicyBundle::VERSION_V1);
    }
    #[tokio::test]
    async fn list_handler_enforces_exact_limit_maximum() {
        let app = mk_app_state_for_tests();
        let accepted = u64::try_from(MAX_DA_QUERY_PAGE_SIZE).expect("page limit fits u64");
        let JsonBody(page) = super::handler_list_commitments(
            State(app.clone()),
            NoritoJson(list_request(Some(accepted))),
        )
        .await
        .expect("the exact page-limit maximum must be accepted");
        assert!(page.commitments.is_empty());

        let rejected = accepted + 1;
        let error =
            super::handler_list_commitments(State(app), NoritoJson(list_request(Some(rejected))))
                .await
                .expect_err("a page limit above the maximum must be rejected");
        assert!(matches!(
            &error,
            Error::AppQueryValidation {
                code: "invalid_da_commitment_limit",
                ..
            }
        ));
        let response = axum::response::IntoResponse::into_response(error);
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn list_handler_rejects_cursor_bound_to_another_tip() {
        let app =
            app_with_da_commitment_bundle(vec![sample_record(1, 1, 1), sample_record(1, 2, 2)]);
        let JsonBody(first) =
            super::handler_list_commitments(State(app.clone()), NoritoJson(list_request(Some(1))))
                .await
                .expect("first page");
        let mut cursor = first.next_cursor.expect("second row requires continuation");
        cursor.snapshot.block_hash =
            Some(HashOf::from_untyped_unchecked(Hash::prehashed([0xAA; 32])));
        let error = super::handler_list_commitments(
            State(app),
            NoritoJson(DaCommitmentListRequest {
                limit: NonZeroU64::new(1),
                cursor: Some(cursor),
            }),
        )
        .await
        .expect_err("cursor from another ledger tip must fail closed");
        assert!(matches!(
            error,
            Error::AppQueryValidation {
                code: "stale_da_commitment_cursor",
                ..
            }
        ));
    }
    #[tokio::test]
    async fn proof_policy_handler_reports_lane_metadata() {
        let app = mk_app_state_for_tests();
        let JsonBody(bundle) = super::handler_list_proof_policies(State(app.clone()))
            .await
            .expect("handler should succeed");
        assert_eq!(bundle.version(), DaProofPolicyBundle::VERSION_V1);
        assert!(
            !bundle.policies().is_empty(),
            "expected policies derived from lane configuration"
        );
        let nexus_snapshot = app.state.nexus_snapshot();
        let primary = nexus_snapshot.lane_config.primary();
        let first = &bundle.policies()[0];
        assert_eq!(first.lane_id, primary.lane_id);
        assert_eq!(first.dataspace_id, primary.dataspace_id);
        assert_eq!(first.alias, primary.alias);
        assert_eq!(first.proof_scheme, primary.proof_scheme);
    }
    #[tokio::test]
    async fn proof_policy_handler_exposes_hash() {
        let app = mk_app_state_for_tests();
        let JsonBody(bundle) = super::handler_list_proof_policies(State(app.clone()))
            .await
            .expect("handler should succeed");
        assert!(
            !bundle.policies().is_empty(),
            "expected proof policies in bundle response"
        );
        assert_eq!(bundle.version(), DaProofPolicyBundle::VERSION_V1);
        assert_ne!(bundle.policy_hash(), Hash::prehashed([0; 32]));
    }
    #[tokio::test]
    async fn proof_policy_handler_ignores_stale_runtime_lane_geometry() {
        let app = mk_app_state_for_tests();
        let stale_lane = LaneId::new(1);
        install_stale_runtime_lane_geometry(&app, stale_lane);
        let JsonBody(bundle) = super::handler_list_proof_policies(State(app.clone()))
            .await
            .expect("handler should succeed");
        assert!(
            bundle
                .policies()
                .iter()
                .any(|policy| policy.lane_id == LaneId::new(0)),
            "default lane policy must remain visible"
        );
        assert!(
            !bundle
                .policies()
                .iter()
                .any(|policy| policy.lane_id == stale_lane),
            "stale runtime-only lane must not appear in active proof policies"
        );
    }
    #[tokio::test]
    async fn list_and_prove_handlers_ignore_stale_runtime_lane_geometry() {
        let stale_lane = LaneId::new(1);
        let records = vec![sample_record(stale_lane.as_u32(), 1, 1)];
        let manifest = records[0].manifest_hash;
        let app = app_with_historical_commitments(records, nexus_for_records(&[]));
        install_stale_runtime_lane_geometry(&app, stale_lane);
        let JsonBody(list_response) = super::handler_list_commitments(
            State(app.clone()),
            NoritoJson(DaCommitmentListRequest::default()),
        )
        .await
        .expect("list handler should succeed");
        assert!(
            list_response.commitments.is_empty(),
            "stale runtime-only lane commitments must not be listed"
        );
        let JsonBody(proof_response) = super::handler_prove_commitment(
            State(app),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(
            proof_response.is_none(),
            "stale runtime-only lane commitments must not produce proofs"
        );
    }
    #[tokio::test]
    async fn proof_policy_handler_ignores_uncommitted_autoscale_overlay() {
        let lane = LaneId::new(1);
        let app = app_with_da_commitment_bundle(vec![sample_record(0, 1, 1)]);
        install_uncommitted_autoscale_overlay(&app, lane);
        let JsonBody(bundle) = super::handler_list_proof_policies(State(app.clone()))
            .await
            .expect("handler should succeed");
        assert!(
            bundle
                .policies()
                .iter()
                .any(|policy| policy.lane_id == LaneId::new(0)),
            "default lane policy must remain visible"
        );
        assert!(
            !bundle
                .policies()
                .iter()
                .any(|policy| policy.lane_id == lane),
            "an uncommitted autoscale overlay must not introduce an authoritative policy"
        );
    }
    #[tokio::test]
    async fn commitment_handlers_ignore_uncommitted_autoscale_overlay() {
        let lane = LaneId::new(1);
        let records = vec![sample_record(lane.as_u32(), 1, 1)];
        let manifest = records[0].manifest_hash;
        // An external holder retains the historical proof independently of the
        // active-lane index, which intentionally drops removed lanes.
        let historical_proof =
            build_da_commitment_proof(&DaCommitmentBundle::new(records.clone()), 1, 0)
                .expect("proof of the exact historical signed bundle");
        let app = app_with_historical_commitments(records, nexus_for_records(&[]));
        install_uncommitted_autoscale_overlay(&app, lane);
        let JsonBody(list_response) = super::handler_list_commitments(
            State(app.clone()),
            NoritoJson(DaCommitmentListRequest::default()),
        )
        .await
        .expect("list handler should succeed");
        assert!(
            list_response.commitments.is_empty(),
            "an uncommitted overlay must not expose a historical lane's commitments"
        );
        assert!(
            !list_response
                .policies
                .policies()
                .iter()
                .any(|policy| policy.lane_id == lane),
            "list response policies must also ignore the uncommitted lane"
        );
        let request = DaCommitmentProofRequest {
            manifest_hash: Some(manifest),
            ..DaCommitmentProofRequest::default()
        };
        let JsonBody(proof_response) =
            super::handler_prove_commitment(State(app.clone()), NoritoJson(request))
                .await
                .expect("proof handler should succeed");
        assert!(
            proof_response.is_none(),
            "an uncommitted overlay must not authorize public proofs for a historical lane"
        );
        let proof = historical_proof;
        let JsonBody(verification) =
            super::handler_verify_commitment(State(app), NoritoJson(proof))
                .await
                .expect("verify handler should succeed");
        assert!(
            verification.valid,
            "verification must use the block's signed policy snapshot, not mutable current lane geometry: {verification:?}"
        );
        assert!(verification.error.is_none());
    }
    #[tokio::test]
    async fn prove_and_verify_handlers_roundtrip_merkle_proof_from_committed_block() {
        let records = vec![
            sample_record(1, 1, 1),
            sample_record(1, 2, 0),
            sample_record(2, 3, 5),
        ];
        let manifest = records[2].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let JsonBody(response) = super::handler_prove_commitment(
            State(app.clone()),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        let proof_response = response.expect("proof should be returned for committed bundle");
        assert_eq!(proof_response.proof.location.block_height, 1);
        assert_eq!(proof_response.proof.location.index_in_bundle, 2);
        assert!(
            !proof_response.proof.path.is_empty(),
            "multi-record bundle should return a non-empty Merkle path"
        );
        let JsonBody(verification) =
            super::handler_verify_commitment(State(app), NoritoJson(proof_response.proof))
                .await
                .expect("verify handler should succeed");
        assert!(verification.valid, "proof should verify: {verification:?}");
        assert!(verification.error.is_none());
    }
    #[tokio::test]
    async fn original_commitment_history_capacity_is_retryable_for_prove_and_verify() {
        use axum::response::IntoResponse as _;
        let record = sample_record(1, 1, 1);
        let request = DaCommitmentProofRequest {
            manifest_hash: Some(record.manifest_hash),
            ..DaCommitmentProofRequest::default()
        };
        let app = app_with_da_commitment_bundle(vec![record]);
        let proof = prove_for_manifest(app.clone(), request.manifest_hash.unwrap()).await;
        app.kura
            .forget_cached_block_for_testing(NonZeroUsize::new(1).unwrap())
            .unwrap();
        let pool = app.state.ivm_execution_budget();
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        for error in [
            handler_prove_commitment(State(app.clone()), NoritoJson(request.clone()))
                .await
                .unwrap_err(),
            handler_verify_commitment(State(app.clone()), NoritoJson(proof.clone()))
                .await
                .unwrap_err(),
        ] {
            assert_eq!(
                error.into_response().status(),
                axum::http::StatusCode::TOO_MANY_REQUESTS
            );
        }
        drop(held);
        let JsonBody(retried) = handler_prove_commitment(State(app.clone()), NoritoJson(request))
            .await
            .unwrap();
        assert_eq!(retried.unwrap().proof, proof);
        let JsonBody(verified) = handler_verify_commitment(State(app), NoritoJson(proof))
            .await
            .unwrap();
        assert!(verified.valid);
    }
    #[tokio::test]
    async fn prove_handler_returns_none_for_unknown_commitment_keys() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 0)];
        let app = app_with_da_commitment_bundle(records);
        let JsonBody(response) = super::handler_prove_commitment(
            State(app.clone()),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(ManifestDigest::new([0xFA; 32])),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(response.is_none());
        let JsonBody(response) = super::handler_prove_commitment(
            State(app),
            NoritoJson(DaCommitmentProofRequest {
                lane_id: Some(1),
                epoch: Some(1),
                sequence: Some(999),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(response.is_none());
    }
    #[tokio::test]
    async fn prove_handler_returns_none_for_conflicting_commitment_selectors() {
        let records = vec![sample_record(1, 1, 1), sample_record(2, 2, 2)];
        let manifest = records[0].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let JsonBody(response) = super::handler_prove_commitment(
            State(app.clone()),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                lane_id: Some(2),
                epoch: Some(1),
                sequence: Some(1),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(
            response.is_none(),
            "manifest must not override a conflicting lane selector"
        );
        let JsonBody(response) = super::handler_prove_commitment(
            State(app),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                lane_id: Some(1),
                epoch: Some(9),
                sequence: Some(1),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(
            response.is_none(),
            "manifest must not override a conflicting epoch selector"
        );
    }
    #[tokio::test]
    async fn prove_handler_rejects_projection_location_drift_from_kura() {
        let record = sample_record(1, 1, 1);
        let manifest = record.manifest_hash;
        let app = app_with_da_commitment_bundle(vec![record.clone()]);
        {
            let mut store = app.state.da_commitments.write();
            *store = DaCommitmentStore::default();
            assert!(store.insert(
                &record,
                iroha_data_model::da::commitment::DaCommitmentLocation {
                    block_height: 1,
                    index_in_bundle: 1,
                },
            ));
        }
        let JsonBody(response) = super::handler_prove_commitment(
            State(app),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        assert!(
            response.is_none(),
            "an index projection may select a record but cannot redefine its Kura position"
        );
    }
    #[tokio::test]
    async fn verify_handler_rejects_tampered_merkle_root() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let JsonBody(response) = super::handler_prove_commitment(
            State(app.clone()),
            NoritoJson(DaCommitmentProofRequest {
                manifest_hash: Some(manifest),
                ..DaCommitmentProofRequest::default()
            }),
        )
        .await
        .expect("proof handler should succeed");
        let mut proof = response.expect("proof should be returned").proof;
        proof.root = Hash::prehashed([0xEE; 32]);
        let JsonBody(verification) =
            super::handler_verify_commitment(State(app), NoritoJson(proof))
                .await
                .expect("verify handler should succeed");
        assert!(!verification.valid);
        assert!(
            verification
                .error
                .as_deref()
                .is_some_and(|message| message.contains("Merkle path")),
            "unexpected verification error: {verification:?}"
        );
    }
    #[tokio::test]
    async fn verify_handler_rejects_missing_bundle_reference() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let mut proof = prove_for_manifest(app.clone(), manifest).await;
        proof.location.block_height = 2;
        verify_invalid(app, proof, "block 2 not available in Kura").await;
    }
    #[tokio::test]
    async fn verify_handler_rejects_bundle_without_backing_kura_block() {
        let app = app_with_da_commitment_bundle(vec![sample_record(1, 1, 1)]);
        let missing_block_bundle =
            DaCommitmentBundle::new(vec![sample_record(1, 2, 2), sample_record(1, 3, 3)]);
        let proof = build_da_commitment_proof(&missing_block_bundle, 2, 1)
            .expect("proof for bundle without Kura block");
        app.state
            .da_commitments
            .write()
            .insert_bundle(2, missing_block_bundle);
        verify_invalid(app, proof, "block 2 not available in Kura").await;
    }
    #[tokio::test]
    async fn verify_handler_rejects_out_of_bounds_index() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let mut proof = prove_for_manifest(app.clone(), manifest).await;
        proof.location.index_in_bundle = u32::MAX;
        verify_invalid(app, proof, "out of bounds").await;
    }
    #[tokio::test]
    async fn verify_handler_rejects_bundle_len_mismatch() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let mut proof = prove_for_manifest(app.clone(), manifest).await;
        proof.bundle_len = proof.bundle_len.saturating_add(1);
        verify_invalid(app, proof, "Merkle path is not valid").await;
    }
    #[tokio::test]
    async fn verify_handler_rejects_commitment_payload_mismatch() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let mut proof = prove_for_manifest(app.clone(), manifest).await;
        proof.commitment = sample_record(1, 9, 9);
        verify_invalid(app, proof, "Merkle path does not fold").await;
    }
    #[tokio::test]
    async fn verify_handler_rejects_tampered_bundle_hash() {
        let records = vec![sample_record(1, 1, 1), sample_record(1, 2, 2)];
        let manifest = records[1].manifest_hash;
        let app = app_with_da_commitment_bundle(records);
        let mut proof = prove_for_manifest(app.clone(), manifest).await;
        proof.bundle_hash =
            HashOf::<DaCommitmentBundle>::from_untyped_unchecked(Hash::prehashed([0xAB; 32]));
        verify_invalid(app, proof, "DA commitment tree descriptor mismatch").await;
    }
    #[tokio::test]
    async fn verify_handler_uses_historical_policy_after_lane_removal() {
        let stale_lane = LaneId::new(1);
        let records = vec![sample_record(stale_lane.as_u32(), 1, 1)];
        // An external holder retains the historical proof independently of the
        // active-lane index, which intentionally drops removed lanes.
        let historical_proof =
            build_da_commitment_proof(&DaCommitmentBundle::new(records.clone()), 1, 0)
                .expect("proof of the exact historical signed bundle");
        let app = app_with_historical_commitments(records, nexus_for_records(&[]));
        let proof = historical_proof;
        install_stale_runtime_lane_geometry(&app, stale_lane);
        let JsonBody(verification) =
            super::handler_verify_commitment(State(app), NoritoJson(proof))
                .await
                .expect("verify handler should succeed");
        assert!(
            verification.valid,
            "a proof authenticated by the historical block policy must survive current lane removal: {verification:?}"
        );
        assert!(verification.error.is_none());
    }
    #[tokio::test]
    async fn commitment_post_routes_reject_oversized_bodies() {
        crate::frame_test_support::assert_current_frame(
            &DaCommitmentListRequest {
                limit: std::num::NonZeroU64::new(7),
                ..Default::default()
            },
            "iroha_torii::da::commitments::DaCommitmentListRequest",
        );
        crate::frame_test_support::assert_current_frame(
            &DaCommitmentProofRequest {
                lane_id: Some(3),
                epoch: Some(7),
                sequence: Some(11),
                ..Default::default()
            },
            "iroha_torii::da::commitments::DaCommitmentProofRequest",
        );
        use axum::{
            Router,
            body::Body,
            extract::DefaultBodyLimit,
            http::{Method, Request, StatusCode, header},
            routing::post,
        };
        use tower::ServiceExt as _;
        let app = mk_app_state_for_tests();
        let router = Router::new()
            .route(
                ENDPOINT_DA_COMMITMENTS,
                post(super::handler_list_commitments)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .route(
                ENDPOINT_DA_COMMITMENTS_PROVE,
                post(super::handler_prove_commitment)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .route(
                ENDPOINT_DA_COMMITMENTS_VERIFY,
                post(super::handler_verify_commitment)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .with_state(app);
        for path in [
            ENDPOINT_DA_COMMITMENTS,
            ENDPOINT_DA_COMMITMENTS_PROVE,
            ENDPOINT_DA_COMMITMENTS_VERIFY,
        ] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b' '; DA_QUERY_REQUEST_MAX_BYTES + 1]))
                .expect("oversized request");
            let response = router.clone().oneshot(request).await.expect("response");
            assert_eq!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "path={path}"
            );
        }
    }
}
