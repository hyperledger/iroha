//! Torii handlers for DA pin intents.
//!
//! These endpoints operate on the in-memory pin intent index populated during
//! block application. Durable WSV plumbing can replace the backing store once
//! available without changing the handler surface.
use super::commitments::list_snapshot_for_state;
use crate::{Error, JsonBody, NoritoJson, SharedAppState};
use axum::extract::State;
use iroha_config::parameters::actual::Nexus;
use iroha_core::da::{
    ActiveLaneProofPolicyContext, build_da_pin_intent_proof, pin_store::DaPinStore,
    verify_da_pin_intent_proof,
};
use iroha_data_model::da::pin_intent::{DaPinIntentProof, DaPinIntentWithLocation};
use iroha_torii_shared::da::{
    DaListSnapshot, DaPinIntentListCursor, DaPinIntentListRequest, DaPinIntentListResponse,
    DaPinIntentQueryRequest, DaPinIntentVerifyResponse, DaQueryValidationError,
};
use std::num::NonZeroUsize;
#[cfg(test)]
const ENDPOINT_DA_PIN_INTENTS: &str = "/v1/da/pin-intents";
#[cfg(test)]
const ENDPOINT_DA_PIN_INTENTS_PROVE: &str = "/v1/da/pin-intents/prove";
#[cfg(test)]
const ENDPOINT_DA_PIN_INTENTS_VERIFY: &str = "/v1/da/pin-intents/verify";
/// HTTP handler for `/v1/da/pin-intents`.
pub async fn handler_list_pin_intents(
    State(app): State<SharedAppState>,
    NoritoJson(request): NoritoJson<DaPinIntentListRequest>,
) -> Result<JsonBody<DaPinIntentListResponse>, Error> {
    let snapshot = list_snapshot_for_state(app.state.as_ref());
    let nexus = app.state.nexus_snapshot();
    let page = {
        let store = app
            .state
            .da_pin_intents()
            .map_err(crate::canonical_history::da_hydration_error)?;
        list_active_from_store(&store, &request, &nexus, snapshot).map_err(pin_list_error)?
    };
    if list_snapshot_for_state(app.state.as_ref()) != snapshot {
        return Err(Error::AppConflict {
            code: "da_list_snapshot_changed",
            message: "the committed ledger tip changed while the DA pin-intent page was read; retry from the first page".to_owned(),
        });
    }
    Ok(JsonBody(DaPinIntentListResponse {
        intents: page.intents,
        next_cursor: page.next_cursor,
    }))
}
/// HTTP handler for `/v1/da/pin-intents/prove`.
pub async fn handler_prove_pin_intent(
    State(app): State<SharedAppState>,
    NoritoJson(request): NoritoJson<DaPinIntentQueryRequest>,
) -> Result<JsonBody<Option<DaPinIntentProof>>, Error> {
    request.validate().map_err(pin_query_error)?;
    let nexus = app.state.nexus_snapshot();
    let proof = build_active_proof_from_state(&request, &nexus, app.state.as_ref())?;
    Ok(JsonBody(proof))
}
/// HTTP handler for `/v1/da/pin-intents/verify`.
pub async fn handler_verify_pin_intent(
    State(app): State<SharedAppState>,
    NoritoJson(proof): NoritoJson<DaPinIntentProof>,
) -> Result<JsonBody<DaPinIntentVerifyResponse>, Error> {
    let response = verify_against_kura_block(&proof, app.state.as_ref())?;
    Ok(JsonBody(response))
}
fn list_active_from_store(
    store: &DaPinStore,
    request: &DaPinIntentListRequest,
    nexus: &Nexus,
    snapshot: DaListSnapshot,
) -> Result<DaPinIntentPage, DaPinIntentListError> {
    let policy_context = ActiveLaneProofPolicyContext::new(nexus);
    list_page_from_store(store, request, snapshot, |entry| {
        pin_intent_lane_is_active(&policy_context, entry)
    })
}
fn pin_query_error(error: DaQueryValidationError) -> Error {
    Error::AppQueryValidation {
        code: if matches!(error, DaQueryValidationError::AliasTooLong { .. }) {
            "invalid_da_pin_intent_alias"
        } else {
            "invalid_da_pin_intent_selector"
        },
        message: error.to_string(),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaPinIntentListError {
    InvalidRequest(DaQueryValidationError),
    StaleSnapshot,
    UnknownLocation,
}
fn pin_list_error(error: DaPinIntentListError) -> Error {
    let (code, message) = match error {
        DaPinIntentListError::InvalidRequest(error) => (
            if matches!(error, DaQueryValidationError::LimitOutOfRange { .. }) {
                "invalid_da_pin_intent_limit"
            } else {
                "invalid_da_pin_intent_cursor"
            },
            error.to_string(),
        ),
        DaPinIntentListError::StaleSnapshot => (
            "stale_da_pin_intent_cursor",
            "DA pin-intent cursor does not target the current committed ledger tip; restart from the first page".to_owned(),
        ),
        DaPinIntentListError::UnknownLocation => (
            "invalid_da_pin_intent_cursor",
            "DA pin-intent cursor location is absent from the current active query index".to_owned(),
        ),
    };
    Error::AppQueryValidation { code, message }
}
#[derive(Debug)]
struct DaPinIntentPage {
    intents: Vec<DaPinIntentWithLocation>,
    next_cursor: Option<DaPinIntentListCursor>,
}
fn list_page_from_store(
    store: &DaPinStore,
    request: &DaPinIntentListRequest,
    snapshot: DaListSnapshot,
    mut is_visible: impl FnMut(&DaPinIntentWithLocation) -> bool,
) -> Result<DaPinIntentPage, DaPinIntentListError> {
    let limit = request
        .page_size()
        .map_err(DaPinIntentListError::InvalidRequest)?;
    let after = request.cursor.map(|cursor| {
        if cursor.snapshot != snapshot {
            return Err(DaPinIntentListError::StaleSnapshot);
        }
        if !store.contains_query_location(cursor.after) {
            return Err(DaPinIntentListError::UnknownLocation);
        }
        Ok(cursor.after)
    });
    let after = after.transpose()?;
    let mut ordered = store.all_sorted_after(after);
    let mut intents = Vec::with_capacity(limit);
    let mut last_examined = None;
    for entry in ordered.by_ref().take(limit) {
        last_examined = Some(entry.location);
        if is_visible(entry) {
            intents.push(entry.clone());
        }
    }
    let next_cursor = if ordered.next().is_some() {
        last_examined.map(|after| DaPinIntentListCursor { snapshot, after })
    } else {
        None
    };
    Ok(DaPinIntentPage {
        intents,
        next_cursor,
    })
}
fn find_active_in_store(
    store: &DaPinStore,
    request: &DaPinIntentQueryRequest,
    policy_context: &ActiveLaneProofPolicyContext<'_>,
) -> Option<DaPinIntentWithLocation> {
    find_in_store(store, request).filter(|entry| pin_intent_lane_is_active(policy_context, entry))
}
fn find_in_store(
    store: &DaPinStore,
    request: &DaPinIntentQueryRequest,
) -> Option<DaPinIntentWithLocation> {
    if let Some(ticket) = request.storage_ticket {
        let target = store.get_by_ticket(&ticket)?.clone();
        return request_matches_pin_intent(&target, request).then_some(target);
    }
    if let Some(alias) = &request.alias {
        let target = store
            .get_by_alias(alias)
            .map(|(_, record)| record.clone())?;
        return request_matches_pin_intent(&target, request).then_some(target);
    }
    if let Some(manifest) = request.manifest_hash {
        let target = store.get_by_manifest(&manifest)?.clone();
        return request_matches_pin_intent(&target, request).then_some(target);
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
fn request_matches_pin_intent(
    target: &DaPinIntentWithLocation,
    request: &DaPinIntentQueryRequest,
) -> bool {
    if request
        .storage_ticket
        .is_some_and(|ticket| target.intent.storage_ticket != ticket)
    {
        return false;
    }
    if request
        .alias
        .as_ref()
        .is_some_and(|alias| target.intent.alias.as_deref() != Some(alias.as_str()))
    {
        return false;
    }
    if request
        .manifest_hash
        .is_some_and(|manifest| target.intent.manifest_hash != manifest)
    {
        return false;
    }
    if request
        .lane_id
        .is_some_and(|lane_id| target.intent.lane_id.as_u32() != lane_id)
    {
        return false;
    }
    if request
        .epoch
        .is_some_and(|epoch| target.intent.epoch != epoch)
    {
        return false;
    }
    if request
        .sequence
        .is_some_and(|sequence| target.intent.sequence != sequence)
    {
        return false;
    }
    true
}
fn pin_intent_lane_is_active(
    policy_context: &ActiveLaneProofPolicyContext<'_>,
    proof: &DaPinIntentWithLocation,
) -> bool {
    policy_context
        .policy_at_height(proof.intent.lane_id, proof.location.block_height)
        .is_ok()
}
fn build_active_proof_from_state(
    request: &DaPinIntentQueryRequest,
    nexus: &Nexus,
    state: &iroha_core::state::State,
) -> Result<Option<DaPinIntentProof>, Error> {
    let policy_context = ActiveLaneProofPolicyContext::new(nexus);
    let target = {
        let store = state
            .da_pin_intents()
            .map_err(crate::canonical_history::da_hydration_error)?;
        find_active_in_store(&store, request, &policy_context)
    };
    let Some(target) = target else {
        return Ok(None);
    };
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
        let bundle = block.as_ref().da_pin_intents()?;
        let index = usize::try_from(target.location.index_in_bundle).ok()?;
        if bundle.intents.get(index) != Some(&target.intent) {
            return None;
        }
        build_da_pin_intent_proof(bundle, target.location.block_height, index)
    })())
}
fn verify_against_kura_block(
    proof: &DaPinIntentProof,
    state: &iroha_core::state::State,
) -> Result<DaPinIntentVerifyResponse, Error> {
    let Ok(block_height) = usize::try_from(proof.location.block_height) else {
        return Ok(DaPinIntentVerifyResponse {
            valid: false,
            error: Some("DA pin-intent proof block height does not fit usize".to_owned()),
        });
    };
    let Some(block_height) = NonZeroUsize::new(block_height) else {
        return Ok(DaPinIntentVerifyResponse {
            valid: false,
            error: Some("DA pin-intent proof cannot reference block height 0".to_owned()),
        });
    };
    let Some(block) = state
        .block_by_height(block_height)
        .map_err(crate::canonical_history::canonical_attempt_error)?
    else {
        return Ok(DaPinIntentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block {} is not available in Kura",
                proof.location.block_height
            )),
        });
    };
    if block.as_ref().da_pin_intents().is_none() {
        return Ok(DaPinIntentVerifyResponse {
            valid: false,
            error: Some(format!(
                "block {} does not contain a DA pin-intent bundle",
                proof.location.block_height
            )),
        });
    }
    Ok(match verify_da_pin_intent_proof(proof, &block.header()) {
        Ok(()) => DaPinIntentVerifyResponse {
            valid: true,
            error: None,
        },
        Err(err) => DaPinIntentVerifyResponse {
            valid: false,
            error: Some(err.to_string()),
        },
    })
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::sorafs::pin_registry::ManifestDigest;
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::{BlockHeader, builder::BlockBuilder},
        da::{
            commitment::DaCommitmentLocation,
            ingest::{
                DaIngestAuthorizationV1, DaIngestSignatureV1, DaPinScopeAuthorizationV1,
                DaPinScopeV1,
            },
            pin_intent::{DaPinIntent, DaPinIntentBundle, MAX_DA_PIN_INTENT_ALIAS_BYTES},
            types::{BlobDigest, StorageTicketId},
        },
        nexus::{
            AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, LaneCatalog,
            LaneConfig as ModelLaneConfig,
        },
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_torii_shared::da::{DA_QUERY_REQUEST_MAX_BYTES, MAX_DA_QUERY_PAGE_SIZE};
    use std::num::{NonZeroU32, NonZeroU64};
    fn sample_authorization(lane: LaneId, epoch: u64, sequence: u64) -> DaIngestAuthorizationV1 {
        let key_pair = KeyPair::try_from_seed(vec![0xD5; 32], Algorithm::Ed25519)
            .expect("valid deterministic DA query key");
        let mut authorization = DaIngestAuthorizationV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xD6; 32])),
            ),
            owner: AccountId::new(key_pair.public_key().clone()),
            lane_id: lane,
            epoch,
            sequence,
            payload_hash: BlobDigest::new([0xD7; 32]),
            payload_bytes: 1,
            request_content_hash: Hash::prehashed([0xD8; 32]),
            signatures: Vec::new(),
        };
        authorization.signatures.push(DaIngestSignatureV1 {
            signer: key_pair.public_key().clone(),
            signature: Signature::try_new(key_pair.private_key(), &authorization.signing_digest())
                .expect("sign deterministic DA query authorization"),
        });
        authorization
    }
    fn sample_intent(lane: u32, epoch: u64, sequence: u64) -> DaPinIntent {
        let key_pair = KeyPair::try_from_seed(vec![0xD5; 32], Algorithm::Ed25519)
            .expect("valid deterministic DA query key");
        let authorization = sample_authorization(LaneId::new(lane), epoch, sequence);
        let scope = DaPinScopeV1::new(
            &authorization,
            StorageTicketId::new([lane as u8; 32]),
            ManifestDigest::new([sequence as u8; 32]),
            None,
        );
        let scope_authorization = DaPinScopeAuthorizationV1::try_sign(scope, &key_pair)
            .expect("sign deterministic DA query pin scope");
        DaPinIntent::new(authorization, scope_authorization)
    }
    fn store_with_records() -> DaPinStore {
        let intents = vec![
            DaPinIntentWithLocation {
                intent: sample_intent(1, 1, 1),
                location: DaCommitmentLocation {
                    block_height: 5,
                    index_in_bundle: 0,
                },
            },
            DaPinIntentWithLocation {
                intent: sample_intent(2, 2, 0),
                location: DaCommitmentLocation {
                    block_height: 6,
                    index_in_bundle: 1,
                },
            },
            DaPinIntentWithLocation {
                intent: sample_intent(3, 1, 5),
                location: DaCommitmentLocation {
                    block_height: 7,
                    index_in_bundle: 2,
                },
            },
        ];
        DaPinStore::from_intents(&intents)
    }
    fn pin_store_snapshot() -> DaListSnapshot {
        DaListSnapshot {
            block_height: 100,
            block_hash: Some(HashOf::from_untyped_unchecked(Hash::new(
                b"DA pin store snapshot at height 100",
            ))),
        }
    }
    fn list_request(limit: Option<u64>) -> DaPinIntentListRequest {
        DaPinIntentListRequest {
            limit: limit.and_then(NonZeroU64::new),
            cursor: None,
        }
    }
    #[test]
    fn pin_intent_query_rejects_alias_over_utf8_byte_bound() {
        let accepted = DaPinIntentQueryRequest {
            alias: Some("é".repeat(MAX_DA_PIN_INTENT_ALIAS_BYTES / 2)),
            ..DaPinIntentQueryRequest::default()
        };
        accepted
            .validate()
            .expect("alias at the exact UTF-8 byte bound must be accepted");
        let rejected = DaPinIntentQueryRequest {
            alias: Some("é".repeat(MAX_DA_PIN_INTENT_ALIAS_BYTES / 2 + 1)),
            ..DaPinIntentQueryRequest::default()
        };
        let error = rejected
            .validate()
            .map_err(pin_query_error)
            .expect_err("alias above the UTF-8 byte bound must fail closed");
        assert!(matches!(
            error,
            Error::AppQueryValidation {
                code: "invalid_da_pin_intent_alias",
                ..
            }
        ));
    }
    fn lane_catalog_with_lane_ids(lane_ids: &[u32]) -> LaneCatalog {
        let max_lane = lane_ids.iter().copied().max().unwrap_or(0);
        let lane_count = NonZeroU32::new(max_lane.saturating_add(1)).expect("lane count");
        let mut lanes = lane_ids
            .iter()
            .copied()
            .map(|lane_id| ModelLaneConfig {
                id: LaneId::new(lane_id),
                alias: format!("lane-{lane_id}"),
                ..ModelLaneConfig::default()
            })
            .collect::<Vec<_>>();
        lanes.sort_by_key(|lane| lane.id.as_u32());
        lanes.dedup_by_key(|lane| lane.id.as_u32());
        LaneCatalog::new(lane_count, lanes).expect("lane catalog")
    }
    fn nexus_with_lane_ids(lane_ids: &[u32]) -> Nexus {
        let lane_catalog = lane_catalog_with_lane_ids(lane_ids);
        Nexus {
            lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
            configured_lane_catalog: lane_catalog.clone(),
            lane_catalog,
            ..Nexus::default()
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
        let stale_geometry_catalog = lane_catalog_with_lane_ids(&[0, stale_lane.as_u32()]);
        let mut nexus = app.state.nexus.write();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&stale_geometry_catalog);
        assert!(
            nexus.lane_config.entry(stale_lane).is_some(),
            "fixture must retain stale runtime geometry for the removed lane"
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
            NonZeroU32::new(lane_id.as_u32().saturating_add(1)).expect("nonzero lane count"),
            vec![ModelLaneConfig::default(), elastic_lane],
        )
        .expect("future-created autoscale lane catalog");
        // A synthetic policy input, never admitted as committed State: real
        // lifecycle admission rejects a future creation height at the current tip.
        let mut nexus = Nexus::default();
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
        nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(3).expect("nonzero max lanes");
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog);
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
    fn seed_pin_store(app: &mut crate::SharedAppState, store: DaPinStore) {
        let app = std::sync::Arc::get_mut(app).expect("unique app state");
        let state = std::sync::Arc::get_mut(&mut app.state).expect("unique core state");
        drop(
            state
                .da_pin_intents()
                .expect("hydrate original DA fixture index"),
        );
        *state.da_pin_intents.write() = store;
    }
    fn app_with_pin_intent_bundle(intents: Vec<DaPinIntent>) -> crate::SharedAppState {
        let lane_ids = intents
            .iter()
            .map(|intent| intent.lane_id.as_u32())
            .chain(core::iter::once(0))
            .collect::<Vec<_>>();
        app_with_historical_pin_intents(intents, nexus_with_lane_ids(&lane_ids))
    }
    fn app_with_historical_pin_intents(
        intents: Vec<DaPinIntent>,
        current_nexus: Nexus,
    ) -> crate::SharedAppState {
        // The signed historical bundle remains available even when its lane is
        // absent from the current authoritative catalog.
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
            iroha_core::state::World::default(),
            current_nexus,
        );
        let bundle = DaPinIntentBundle::new(intents);
        let bundle_for_store = bundle.clone();
        let keypair = KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
            .expect("generate DA pin-intent block fixture key");
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        let mut builder = BlockBuilder::new(header);
        builder.set_da_pin_intents(Some(bundle));
        let block = builder.build_with_signature(0, keypair.private_key());
        let header = block.header();
        let block_hash = block.hash();
        app.kura
            .store_block(
                iroha_data_model::block::SharedSignedBlock::try_new(
                    block,
                    &app.state.ivm_execution_budget(),
                )
                .expect("fund DA fixture block"),
            )
            .expect("store DA pin-intent block");
        let mut block_hashes = app.state.block_hashes.block();
        block_hashes.push_for_tests(block_hash);
        block_hashes.commit_for_tests();
        app.state.update_latest_block_header_cache_for_tests(header);
        let entries = bundle_for_store
            .intents
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, intent)| DaPinIntentWithLocation {
                intent,
                location: DaCommitmentLocation {
                    block_height: 1,
                    index_in_bundle: u32::try_from(index).expect("fixture index fits u32"),
                },
            })
            .collect::<Vec<_>>();
        seed_pin_store(&mut app, DaPinStore::from_intents(&entries));
        app
    }
    fn historical_pin_proof(app: &crate::SharedAppState) -> DaPinIntentProof {
        let block = app
            .state
            .block_by_height(NonZeroUsize::new(1).expect("nonzero height"))
            .expect("funded canonical history read")
            .expect("historical signed block must remain available");
        build_da_pin_intent_proof(
            block
                .as_ref()
                .da_pin_intents()
                .expect("historical pin bundle"),
            1,
            0,
        )
        .expect("historical pin proof")
    }
    #[test]
    fn list_uses_forward_only_keyset_cursor() {
        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        let first = list_page_from_store(&store, &list_request(Some(2)), snapshot, |_| true)
            .expect("first page");
        assert_eq!(first.intents.len(), 2);
        assert_eq!(first.intents[0].location.block_height, 5);
        assert_eq!(first.intents[1].location.block_height, 6);
        let cursor = first.next_cursor.expect("third row requires continuation");
        assert_eq!(cursor.after, first.intents[1].location);
        let second = list_page_from_store(
            &store,
            &DaPinIntentListRequest {
                limit: NonZeroU64::new(2),
                cursor: Some(cursor),
            },
            snapshot,
            |_| true,
        )
        .expect("second page");
        assert_eq!(second.intents.len(), 1);
        assert_eq!(second.intents[0].location.block_height, 7);
        assert!(second.next_cursor.is_none());
    }
    #[test]
    fn list_overlarge_limit_is_rejected_before_scan() {
        use std::cell::Cell;

        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        let examined = Cell::new(0_usize);
        let provided = u64::try_from(MAX_DA_QUERY_PAGE_SIZE).expect("page limit fits u64") + 1;
        let error = list_page_from_store(&store, &list_request(Some(provided)), snapshot, |_| {
            examined.set(examined.get() + 1);
            true
        })
        .expect_err("limit above the exact maximum must be rejected");
        assert_eq!(
            error,
            DaPinIntentListError::InvalidRequest(DaQueryValidationError::LimitOutOfRange {
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
            DaPinIntentListError::InvalidRequest(DaQueryValidationError::LimitOutOfRange {
                provided: u64::MAX
            })
        );
    }
    #[test]
    fn list_cursor_rejects_unknown_location_and_stale_snapshot() {
        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        let unknown = DaPinIntentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaPinIntentListCursor {
                snapshot,
                after: DaCommitmentLocation {
                    block_height: 99,
                    index_in_bundle: 99,
                },
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &unknown, snapshot, |_| true)
                .expect_err("foreign location must fail closed"),
            DaPinIntentListError::UnknownLocation
        );
        let stale = DaPinIntentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaPinIntentListCursor {
                snapshot: DaListSnapshot {
                    block_height: 101,
                    block_hash: Some(HashOf::from_untyped_unchecked(Hash::prehashed([7; 32]))),
                },
                after: store
                    .all_sorted()
                    .next()
                    .expect("fixture has a first row")
                    .location,
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &stale, snapshot, |_| true)
                .expect_err("stale tip must fail closed"),
            DaPinIntentListError::StaleSnapshot
        );
    }
    #[test]
    fn list_cursor_rejects_location_outside_snapshot_before_index_lookup() {
        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        for block_height in [0, snapshot.block_height + 1] {
            let request = DaPinIntentListRequest {
                limit: NonZeroU64::new(1),
                cursor: Some(DaPinIntentListCursor {
                    snapshot,
                    after: DaCommitmentLocation {
                        block_height,
                        index_in_bundle: 0,
                    },
                }),
            };
            assert_eq!(
                list_page_from_store(&store, &request, snapshot, |_| {
                    panic!("invalid cursor must fail before visibility scanning")
                })
                .expect_err("cursor location must belong to its committed snapshot"),
                DaPinIntentListError::InvalidRequest(DaQueryValidationError::CursorOutsideSnapshot)
            );
        }
    }
    #[test]
    fn list_cursor_rejects_noncanonical_snapshot() {
        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        let request = DaPinIntentListRequest {
            limit: NonZeroU64::new(1),
            cursor: Some(DaPinIntentListCursor {
                snapshot: DaListSnapshot {
                    block_height: 1,
                    block_hash: None,
                },
                after: store
                    .all_sorted()
                    .next()
                    .expect("fixture has a first row")
                    .location,
            }),
        };
        assert_eq!(
            list_page_from_store(&store, &request, snapshot, |_| true)
                .expect_err("malformed snapshot must fail closed"),
            DaPinIntentListError::InvalidRequest(DaQueryValidationError::NonCanonicalSnapshot)
        );
    }
    #[test]
    fn inactive_rows_cannot_amplify_the_raw_scan_budget() {
        use std::cell::Cell;
        let store = store_with_records();
        let snapshot = pin_store_snapshot();
        let examined = Cell::new(0_usize);
        let page = list_page_from_store(&store, &list_request(Some(2)), snapshot, |_| {
            examined.set(examined.get() + 1);
            false
        })
        .expect("bounded filtered page");
        assert!(page.intents.is_empty());
        assert_eq!(examined.get(), 2, "visibility work is bounded by limit");
        let cursor = page
            .next_cursor
            .expect("an empty visible page must still permit deterministic traversal");
        cursor
            .validate()
            .expect("filtered continuation must remain within the committed snapshot");
    }
    #[test]
    fn prove_uses_lane_epoch_sequence() {
        let store = store_with_records();
        let request = DaPinIntentQueryRequest {
            lane_id: Some(3),
            epoch: Some(1),
            sequence: Some(5),
            ..DaPinIntentQueryRequest::default()
        };
        let proof = find_in_store(&store, &request).expect("proof should exist");
        assert_eq!(proof.location.index_in_bundle, 2);
        assert_eq!(proof.location.block_height, 7);
    }
    #[test]
    fn prove_rejects_conflicting_ticket_and_tuple_selectors() {
        let store = store_with_records();
        let request = DaPinIntentQueryRequest {
            storage_ticket: Some(StorageTicketId::new([3; 32])),
            lane_id: Some(2),
            epoch: Some(1),
            sequence: Some(5),
            ..DaPinIntentQueryRequest::default()
        };
        assert!(find_in_store(&store, &request).is_none());
    }
    #[test]
    fn verify_rejects_mismatched_ticket() {
        let bundle = DaPinIntentBundle::new(vec![sample_intent(1, 1, 1)]);
        let mut proof =
            build_da_pin_intent_proof(&bundle, 1, 0).expect("proof should be constructed");
        proof.intent.storage_ticket = StorageTicketId::new([9; 32]);
        let mut header = BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        header.set_da_pin_intents_hash(bundle.merkle_commitment());
        assert!(matches!(
            verify_da_pin_intent_proof(&proof, &header),
            Err(iroha_core::da::DaPinIntentProofVerificationError::PathMismatch)
        ));
    }

    #[tokio::test]
    async fn proof_handler_rejects_missing_or_partial_selectors() {
        for request in [
            DaPinIntentQueryRequest::default(),
            DaPinIntentQueryRequest {
                lane_id: Some(4),
                epoch: Some(9),
                ..DaPinIntentQueryRequest::default()
            },
        ] {
            let error = super::handler_prove_pin_intent(
                State(crate::mk_app_state_for_tests()),
                NoritoJson(request),
            )
            .await
            .expect_err("incomplete selector must fail before index lookup");
            assert!(matches!(
                error,
                Error::AppQueryValidation {
                    code: "invalid_da_pin_intent_selector",
                    ..
                }
            ));
        }
    }
    #[tokio::test]
    async fn handler_succeeds_with_current_lane_catalog() {
        let app = crate::mk_app_state_for_tests();
        let JsonBody(page) = super::handler_list_pin_intents(
            State(app),
            NoritoJson(DaPinIntentListRequest::default()),
        )
        .await
        .expect("handler should succeed");
        assert!(page.intents.is_empty());
        assert!(page.next_cursor.is_none());
    }
    #[tokio::test]
    async fn list_handler_enforces_exact_limit_maximum() {
        let app = crate::mk_app_state_for_tests();
        let accepted = u64::try_from(MAX_DA_QUERY_PAGE_SIZE).expect("page limit fits u64");
        let JsonBody(page) = super::handler_list_pin_intents(
            State(app.clone()),
            NoritoJson(list_request(Some(accepted))),
        )
        .await
        .expect("the exact page-limit maximum must be accepted");
        assert!(page.intents.is_empty());

        let rejected = accepted + 1;
        let error =
            super::handler_list_pin_intents(State(app), NoritoJson(list_request(Some(rejected))))
                .await
                .expect_err("a page limit above the maximum must be rejected");
        assert!(matches!(
            &error,
            Error::AppQueryValidation {
                code: "invalid_da_pin_intent_limit",
                ..
            }
        ));
        let response = axum::response::IntoResponse::into_response(error);
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn list_handler_rejects_cursor_bound_to_another_tip() {
        let app = app_with_pin_intent_bundle(vec![sample_intent(1, 1, 1), sample_intent(2, 1, 2)]);
        let JsonBody(first) =
            super::handler_list_pin_intents(State(app.clone()), NoritoJson(list_request(Some(1))))
                .await
                .expect("first page");
        let mut cursor = first.next_cursor.expect("second row requires continuation");
        cursor.snapshot.block_hash =
            Some(HashOf::from_untyped_unchecked(Hash::prehashed([0xAA; 32])));
        let error = super::handler_list_pin_intents(
            State(app),
            NoritoJson(DaPinIntentListRequest {
                limit: NonZeroU64::new(1),
                cursor: Some(cursor),
            }),
        )
        .await
        .expect_err("cursor from another ledger tip must fail closed");
        assert!(matches!(
            error,
            Error::AppQueryValidation {
                code: "stale_da_pin_intent_cursor",
                ..
            }
        ));
    }
    #[tokio::test]
    async fn handler_prove_and_verify_roundtrip_indexed_pin_intent() {
        let app = app_with_pin_intent_bundle(vec![
            sample_intent(1, 1, 1),
            sample_intent(2, 2, 0),
            sample_intent(3, 1, 5),
        ]);
        let JsonBody(proof) = super::handler_prove_pin_intent(
            State(app.clone()),
            NoritoJson(DaPinIntentQueryRequest {
                lane_id: Some(3),
                epoch: Some(1),
                sequence: Some(5),
                ..DaPinIntentQueryRequest::default()
            }),
        )
        .await
        .expect("pin intent proof lookup should succeed");
        let proof = proof.expect("indexed pin intent should be present");
        assert_eq!(proof.intent.manifest_hash, ManifestDigest::new([5; 32]));
        assert_eq!(proof.location.block_height, 1);
        let JsonBody(response) = super::handler_verify_pin_intent(State(app), NoritoJson(proof))
            .await
            .expect("pin intent verification should succeed");
        assert!(response.valid);
    }
    #[tokio::test]
    async fn original_pin_history_capacity_is_retryable_for_prove_and_verify() {
        use axum::response::IntoResponse as _;
        let app = app_with_pin_intent_bundle(vec![sample_intent(1, 1, 1)]);
        let request = DaPinIntentQueryRequest {
            lane_id: Some(1),
            epoch: Some(1),
            sequence: Some(1),
            ..DaPinIntentQueryRequest::default()
        };
        let proof = historical_pin_proof(&app);
        app.kura
            .forget_cached_block_for_testing(NonZeroUsize::new(1).unwrap())
            .unwrap();
        let pool = app.state.ivm_execution_budget();
        let held = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        for error in [
            handler_prove_pin_intent(State(app.clone()), NoritoJson(request.clone()))
                .await
                .unwrap_err(),
            handler_verify_pin_intent(State(app.clone()), NoritoJson(proof.clone()))
                .await
                .unwrap_err(),
        ] {
            assert_eq!(
                error.into_response().status(),
                axum::http::StatusCode::TOO_MANY_REQUESTS
            );
        }
        drop(held);
        let JsonBody(retried) = handler_prove_pin_intent(State(app.clone()), NoritoJson(request))
            .await
            .unwrap();
        assert_eq!(retried.unwrap(), proof);
        let JsonBody(verified) = handler_verify_pin_intent(State(app), NoritoJson(proof))
            .await
            .unwrap();
        assert!(verified.valid);
    }
    #[tokio::test]
    async fn handler_verify_rejects_tampered_indexed_pin_intent() {
        let app = app_with_pin_intent_bundle(vec![
            sample_intent(1, 1, 1),
            sample_intent(2, 2, 0),
            sample_intent(3, 1, 5),
        ]);
        let JsonBody(proof) = super::handler_prove_pin_intent(
            State(app.clone()),
            NoritoJson(DaPinIntentQueryRequest {
                manifest_hash: Some(ManifestDigest::new([5; 32])),
                ..DaPinIntentQueryRequest::default()
            }),
        )
        .await
        .expect("pin intent proof lookup should succeed");
        let mut proof = proof.expect("indexed pin intent should be present");
        proof.location.index_in_bundle += 1;
        let JsonBody(response) = super::handler_verify_pin_intent(State(app), NoritoJson(proof))
            .await
            .expect("pin intent verification should succeed");
        assert!(!response.valid);
    }
    #[tokio::test]
    async fn handler_prove_rejects_projection_location_drift_from_kura() {
        let intent = sample_intent(1, 1, 1);
        let ticket = intent.storage_ticket;
        let app = app_with_pin_intent_bundle(vec![intent.clone()]);
        {
            let mut store = app.state.da_pin_intents.write();
            *store = DaPinStore::from_intents(&[DaPinIntentWithLocation {
                intent,
                location: DaCommitmentLocation {
                    block_height: 1,
                    index_in_bundle: 1,
                },
            }]);
        }
        let JsonBody(proof) = super::handler_prove_pin_intent(
            State(app),
            NoritoJson(DaPinIntentQueryRequest {
                storage_ticket: Some(ticket),
                ..DaPinIntentQueryRequest::default()
            }),
        )
        .await
        .expect("pin intent proof lookup should succeed");
        assert!(
            proof.is_none(),
            "an index projection may select an intent but cannot redefine its Kura position"
        );
    }
    #[tokio::test]
    async fn handler_verify_uses_historical_header_after_lane_removal() {
        let intent = sample_intent(1, 3, 7);
        let app = app_with_historical_pin_intents(vec![intent.clone()], nexus_with_lane_ids(&[0]));
        let proof = historical_pin_proof(&app);
        install_stale_runtime_lane_geometry(&app, intent.lane_id);
        let JsonBody(response) = super::handler_verify_pin_intent(State(app), NoritoJson(proof))
            .await
            .expect("pin intent verification should succeed");
        assert!(
            response.valid,
            "a proof authenticated by the historical header must survive current lane removal: {response:?}"
        );
        assert!(response.error.is_none());
    }
    #[tokio::test]
    async fn handler_list_and_prove_ignore_stale_runtime_lane_geometry() {
        let stale = sample_intent(1, 4, 8);
        let app = app_with_historical_pin_intents(vec![stale.clone()], nexus_with_lane_ids(&[0]));
        assert_eq!(historical_pin_proof(&app).intent, stale);
        install_stale_runtime_lane_geometry(&app, stale.lane_id);
        let JsonBody(page) = super::handler_list_pin_intents(
            State(app.clone()),
            NoritoJson(DaPinIntentListRequest::default()),
        )
        .await
        .expect("pin intent list should succeed");
        assert!(
            page.intents.is_empty(),
            "stale runtime-only lane pin intents must not be listed"
        );
        let JsonBody(proof) = super::handler_prove_pin_intent(
            State(app),
            NoritoJson(DaPinIntentQueryRequest {
                storage_ticket: Some(stale.storage_ticket),
                ..DaPinIntentQueryRequest::default()
            }),
        )
        .await
        .expect("pin intent proof lookup should succeed");
        assert!(
            proof.is_none(),
            "stale runtime-only lane pin intents must not produce proofs"
        );
    }
    #[tokio::test]
    async fn handlers_ignore_uncommitted_autoscale_overlay_but_verify_historical_proof() {
        let intent = sample_intent(1, 5, 9);
        let app = app_with_historical_pin_intents(vec![intent.clone()], nexus_with_lane_ids(&[0]));
        let historical_proof = historical_pin_proof(&app);
        install_uncommitted_autoscale_overlay(&app, intent.lane_id);
        let JsonBody(page) = super::handler_list_pin_intents(
            State(app.clone()),
            NoritoJson(DaPinIntentListRequest::default()),
        )
        .await
        .expect("pin intent list should succeed");
        assert!(
            page.intents.is_empty(),
            "an uncommitted overlay must not expose a historical lane's pin intents"
        );
        let JsonBody(proof) = super::handler_prove_pin_intent(
            State(app.clone()),
            NoritoJson(DaPinIntentQueryRequest {
                storage_ticket: Some(intent.storage_ticket),
                ..DaPinIntentQueryRequest::default()
            }),
        )
        .await
        .expect("pin intent proof lookup should succeed");
        assert!(
            proof.is_none(),
            "an uncommitted overlay must not authorize public proofs for a historical lane"
        );
        let JsonBody(response) =
            super::handler_verify_pin_intent(State(app), NoritoJson(historical_proof))
                .await
                .expect("pin intent verification should succeed");
        assert!(
            response.valid,
            "verification must use the historical canonical header, not mutable current visibility: {response:?}"
        );
        assert!(response.error.is_none());
    }
    #[tokio::test]
    async fn pin_intent_post_routes_reject_oversized_bodies() {
        crate::frame_test_support::assert_current_frame(
            &DaPinIntentListRequest {
                limit: std::num::NonZeroU64::new(7),
                ..Default::default()
            },
            "iroha_torii::da::pin_intents::DaPinIntentListRequest",
        );
        crate::frame_test_support::assert_current_frame(
            &DaPinIntentQueryRequest {
                lane_id: Some(3),
                epoch: Some(7),
                sequence: Some(11),
                ..Default::default()
            },
            "iroha_torii::da::pin_intents::DaPinIntentQueryRequest",
        );
        use axum::{
            Router,
            body::Body,
            extract::DefaultBodyLimit,
            http::{Method, Request, StatusCode, header},
            routing::post,
        };
        use tower::ServiceExt as _;
        let app = crate::mk_app_state_for_tests();
        let router = Router::new()
            .route(
                ENDPOINT_DA_PIN_INTENTS,
                post(super::handler_list_pin_intents)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .route(
                ENDPOINT_DA_PIN_INTENTS_PROVE,
                post(super::handler_prove_pin_intent)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .route(
                ENDPOINT_DA_PIN_INTENTS_VERIFY,
                post(super::handler_verify_pin_intent)
                    .layer(DefaultBodyLimit::max(DA_QUERY_REQUEST_MAX_BYTES)),
            )
            .with_state(app);
        for path in [
            ENDPOINT_DA_PIN_INTENTS,
            ENDPOINT_DA_PIN_INTENTS_PROVE,
            ENDPOINT_DA_PIN_INTENTS_VERIFY,
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
