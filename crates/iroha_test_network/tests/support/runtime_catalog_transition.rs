//! A committed catalog expansion must survive full Kura replay before signed-snapshot recovery.
//! The native beacon-custody scenario supplies all four peers with their retained
//! startup lane configuration, keys, genesis and block history.
//! Snapshot writes begin only after the retained replay, before geometry compaction is permitted.
use super::*;

#[path = "catalog_native_execution.rs"]
mod native_execution;
use native_execution::authenticated_native_execution;

#[path = "catalog_recovery.rs"]
pub(super) mod real_custody;
use iroha_core::queue::RoutingDecision;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, SignedBlock, decode_framed_signed_block},
    isi::{Grant, Register, Revoke, SetParameter},
    nexus::{
        DataSpaceCatalog, DataSpaceMetadata, LaneConfig, LaneLifecycleStatusV1, LaneVisibility,
        NexusCatalogTransitionV1, NexusRuntimeCatalogV1, RuntimeDataSpaceAdditionV1,
        RuntimeLaneManifestV1, dataspace_catalog_hash,
    },
    parameter::Parameter,
    permission::Permission,
    role::Role,
    sumeragi_finality::{
        FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanDelegateAccountAliasResolution, CanResolveAccountAlias,
};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::json::Json;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct AppliedEvidence {
    transaction: SignedTransaction,
    height: u64,
    lane: LaneId,
    dataspace: DataSpaceId,
    canonical_block: Vec<u8>,
}

#[derive(Clone)]
struct FixtureFinality {
    network_id: NetworkId,
    genesis_hash: HashOf<BlockHeader>,
    trusted_genesis: SignedBlock,
    chain_id: String,
    validators: Vec<FinalityValidator>,
    peers: BTreeMap<PeerId, Arc<Mutex<VerifiedPeerFinality>>>,
}

struct VerifiedPeerFinality {
    network_id: NetworkId,
    genesis_hash: HashOf<BlockHeader>,
    peer: PeerId,
    verifier: Option<SumeragiFinalityVerifier>,
    verified: BTreeMap<u64, VerifiedSumeragiBlock>,
}

impl FixtureFinality {
    fn validate_fixture_roster(&self, proof: &SumeragiFinalityProof) -> Result<()> {
        ensure!(
            proof.committee == self.validators,
            "finality proof differs from the exact signed-genesis fixture committee and PoPs"
        );
        Ok(())
    }

    fn verified_block(
        &self,
        peer: &PeerId,
        client: &iroha::client::Client,
        height: u64,
        expected_block_hash: HashOf<BlockHeader>,
    ) -> Result<VerifiedSumeragiBlock> {
        ensure!(
            (1..=128).contains(&height),
            "catalog fixture exceeded its bounded finality history"
        );
        let cache = self
            .peers
            .get(peer)
            .ok_or_else(|| eyre!("finality reader is not a fixture peer"))?;
        // Each dedicated blocking reader owns one peer's bounded authenticated prefix.
        let mut cache = cache
            .lock()
            .map_err(|_| eyre!("fixture finality cache was poisoned"))?;
        ensure!(
            cache.network_id == self.network_id
                && cache.genesis_hash == self.genesis_hash
                && cache.peer == *peer,
            "finality cache belongs to another network, genesis or peer"
        );
        if cache.verifier.is_none() {
            ensure!(
                cache.verified.is_empty(),
                "unanchored cache contains finality evidence"
            );
            let mut verifier = SumeragiFinalityVerifier::new(
                &self.trusted_genesis,
                &self.chain_id,
                self.validators.clone(),
            )?;
            let proof = client.get_sumeragi_finality_proof(
                NonZeroU64::new(1).expect("genesis height"),
                iroha_data_model::sumeragi_finality::CertifiedResultScope::from_root_scope(
                    verifier.root_scope(),
                ),
            )?;
            ensure!(
                proof.block_header.hash() == self.genesis_hash,
                "finality anchor is not the fixture's exact signed genesis"
            );
            self.validate_fixture_roster(&proof)?;

            let verified = verifier.verify(&proof)?;
            cache.verified.insert(1, verified);
            cache.verifier = Some(verifier);
        }
        while cache
            .verified
            .last_key_value()
            .map_or(0, |(height, _)| *height)
            < height
        {
            let next = cache
                .verified
                .last_key_value()
                .expect("anchored proof cache")
                .0
                + 1;
            let proof = client.get_sumeragi_finality_proof(
                NonZeroU64::new(next).expect("successor height"),
                iroha_data_model::sumeragi_finality::CertifiedResultScope::from_root_scope(
                    cache
                        .verifier
                        .as_ref()
                        .expect("anchored current verifier")
                        .root_scope(),
                ),
            )?;
            self.validate_fixture_roster(&proof)?;
            // A failed successor must not advance the retained authenticated frontier.
            let mut verifier = cache.verifier.clone().expect("anchored current verifier");
            let verified = verifier.verify(&proof)?;
            cache.verified.insert(next, verified);
            cache.verifier = Some(verifier);
        }
        let verified = cache
            .verified
            .get(&height)
            .ok_or_else(|| eyre!("verified finality history has a gap"))?;
        ensure!(
            verified.header().hash() == expected_block_hash,
            "transaction carrier differs from the independently verified finality chain"
        );
        Ok(verified.clone())
    }
}

const PERMISSION_FIXTURE_LIMIT: u32 = 500;

fn complete_permission_page(
    response: &iroha::http::Response<Vec<u8>>,
) -> Result<BTreeSet<Permission>> {
    ensure!(
        response.status().as_u16() == 200,
        "permission first page read failed, limit {PERMISSION_FIXTURE_LIMIT}: {}; body: {}",
        response.status(),
        String::from_utf8_lossy(&response.body()[..response.body().len().min(2048)])
    );
    let header = |name: &str| {
        let mut values = response.headers().get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        values.next().is_none().then_some(value)
    };
    ensure!(
        header("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        }) && header("x-iroha-account-permission-semantics") == Some("effective-v1"),
        "permission response omitted its canonical media type or effective semantics"
    );
    let page: iroha::collections::Page<Permission> = json::from_slice(response.body())?;
    ensure!(
        !page.has_more(),
        "permission fixture cannot prove exhaustion with a continuation cursor"
    );
    ensure!(
        page.items.len() <= PERMISSION_FIXTURE_LIMIT as usize,
        "permission page exceeds requested bound"
    );
    let count = page.items.len();
    let permissions: BTreeSet<_> = page.items.into_iter().collect();
    ensure!(
        permissions.len() == count,
        "permission collection returned duplicate items"
    );
    Ok(permissions)
}

fn effective_permissions(
    client: &iroha::client::Client,
    account_id: &AccountId,
) -> Result<BTreeSet<Permission>> {
    let response = client.query_account_permissions_response(
        account_id,
        &iroha::collections::ListQuery::new().limit(PERMISSION_FIXTURE_LIMIT),
    )?;
    complete_permission_page(&response)
}

#[cfg(test)]
mod permission_page_tests {
    use super::*;
    use iroha::http::Response;

    const ADDED_DATASPACE: DataSpaceId = DataSpaceId::new(3);

    fn resolution_permission() -> Permission {
        CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(ADDED_DATASPACE),
        }
        .into()
    }

    fn resolution_delegation_permission() -> Permission {
        CanDelegateAccountAliasResolution {
            scope: AccountAliasPermissionScope::Dataspace(ADDED_DATASPACE),
        }
        .into()
    }

    fn response(items: Vec<Permission>) -> Response<Vec<u8>> {
        let body = json::to_vec(&iroha::collections::Page::last(items)).unwrap();
        Response::builder()
            .status(200)
            .header("content-type", "application/json; charset=utf-8")
            .header("x-iroha-account-permission-semantics", "effective-v1")
            .body(body)
            .unwrap()
    }

    #[test]
    fn permission_page_requires_cursor_exhaustion() {
        let items = vec![resolution_permission(), resolution_delegation_permission()];
        assert_eq!(
            complete_permission_page(&response(items.clone())).unwrap(),
            items.into_iter().collect()
        );
        assert!(
            complete_permission_page(&response(Vec::new()))
                .unwrap()
                .is_empty()
        );
        let mut continued = response(vec![resolution_permission()]);
        *continued.body_mut() = json::to_vec(&iroha::collections::Page {
            items: vec![resolution_permission()],
            next_cursor: Some("remaining-permissions".to_owned()),
            total: None,
        })
        .unwrap();
        assert!(complete_permission_page(&continued).is_err());
    }

    #[test]
    fn permission_page_accepts_exhausted_limit_and_rejects_oversized_or_duplicate_items() {
        let items = |size| {
            (0..size)
                .map(|value| Permission::new(format!("fixture{value}"), Json::default()))
                .collect()
        };
        assert_eq!(
            complete_permission_page(&response(items(500)))
                .unwrap()
                .len(),
            500
        );
        assert!(
            complete_permission_page(&response(items(501)))
                .unwrap_err()
                .to_string()
                .contains("exceeds requested bound")
        );
        let duplicate = response(vec![resolution_permission(), resolution_permission()]);
        assert!(
            complete_permission_page(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn permission_page_preserves_failure_context_and_rejects_invalid_metadata() {
        let failed = Response::builder()
            .status(400)
            .body(b"invalid_pagination: fetch budget exceeded".to_vec())
            .unwrap();
        let error = complete_permission_page(&failed).unwrap_err().to_string();
        assert!(error.contains("first page read failed, limit 500"));
        assert!(error.contains("400 Bad Request"));
        assert!(error.contains("invalid_pagination"));
        for name in ["content-type", "x-iroha-account-permission-semantics"] {
            let mut page = response(Vec::new());
            let value = page.headers().get(name).unwrap().clone();
            page.headers_mut().append(name, value);
            assert!(complete_permission_page(&page).is_err());
            page.headers_mut().remove(name);
            assert!(complete_permission_page(&page).is_err());
        }
        let mut mismatch = response(vec![resolution_permission()]);
        *mismatch.body_mut() = br#"{"items":[],"total":1}"#.to_vec();
        assert!(
            complete_permission_page(&mismatch)
                .unwrap_err()
                .to_string()
                .contains("next_cursor")
        );
    }
}
