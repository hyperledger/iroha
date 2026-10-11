//! Read-side assembly of SCCP views from committed state (`specs/sccp.md` §6). Owner: ws35.
//!
//! Every honest peer derives identical bytes from committed state; wallets and destinations
//! never trust them and verify everything themselves. Torii, the CLI and tests share these
//! functions. The record views (message status union, pages, light-client detail, governance
//! detail, history paths) live in [`views`]; history paths go through the validated `O(log n)`
//! node cache of `history`.
//!
//! No message or control proof bundle is assembled here: destinations verify Taira's Sumeragi
//! `CommitQC`, and the finality header and certificate a bundle needs are not produced yet.
//!
//! TODO: Torii work package (TT-A2): assemble the message and control proof bundles of §6 on
//! certificates (`?at=record|latest|<H>`): the leaf's block path, the history proof of an older
//! block, the block reference and the certificate.

mod history;
mod views;

pub use views::*;

use super::{light_clients, store};
use crate::state::{StateReadOnly, WorldReadOnly};
/// The §6 wire types and page limits, re-exported for Torii and other readers.
pub use iroha_sccp::api::{self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES};
use iroha_sccp::{
    api::{SccpCapabilitiesV1, SccpLcProfileStatusV1, SccpReadLimitsV1},
    light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1},
    v1::eip712::domain_separator,
};

/// Why a read cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SccpReadError {
    /// The named record does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The data existed but was pruned by retention (`sccp_pruned`, HTTP 410).
    #[error("sccp_pruned: {0}")]
    Pruned(String),
    /// The query is invalid against state.
    #[error("invalid query: {0}")]
    Invalid(String),
}

/// Assemble `GET /v1/sccp/capabilities` (§6).
///
/// TODO: Torii work package (TT-A1): the finality constants, the current committee generation
/// with its deadline, the liability clock, the forgery-hold summary, the seated panel ids and
/// the launch-gate state of §6. The `domain_separator` field is a revision 4 encoding that
/// WP-S1 phase 2 deletes with `iroha_sccp::v1::eip712`.
#[must_use]
pub fn capabilities(view: &(impl StateReadOnly + ?Sized)) -> SccpCapabilitiesV1 {
    let world = view.world();
    let network_id = *view.network_id().as_bytes();
    let committed_height = u64::try_from(view.height()).unwrap_or(u64::MAX);
    SccpCapabilitiesV1 {
        network_id,
        domain_separator: domain_separator(&network_id),
        parameters: *store::parameters::get(world),
        committed_height,
        light_client_profiles: light_client_profiles(world, committed_height.saturating_add(1)),
        chain_id: view.chain_id().to_string(),
        profiles: compiled_profiles(),
        profiles_policy_hash: light_clients::active_profiles_at(
            world,
            committed_height.saturating_add(1),
            &SccpLcProfileCatalogV1::compiled(),
        )
        .policy_hash(),
        limits: SccpReadLimitsV1::v1(),
        path_templates: Vec::new(),
    }
}

/// Return the light-client profile every external source chain runs under at Taira height
/// `height`, in network order (§4.13.2; capabilities report the next block's).
///
/// `supported_until_ms` comes from the compiled profile of the active version, which every peer
/// that applies the state compiles with the recorded hash; it is `None` only on a peer that does
/// not (and therefore applies no further block).
#[must_use]
pub fn light_client_profiles(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
) -> Vec<SccpLcProfileStatusV1> {
    let catalog = SccpLcProfileCatalogV1::compiled();
    let active = light_clients::active_profiles_at(world, height, &catalog);
    SCCP_LC_PROFILE_NETWORKS_V1
        .into_iter()
        .filter_map(|network| {
            let profile = active.get(network)?;
            let record = store::light_client_profiles::get(world, &(network, profile.version));
            let supported_until_ms = catalog
                .resolve(&catalog.genesis().with(network, profile))
                .ok()
                .and_then(|profiles| profiles.supported_until_ms(network));
            Some(SccpLcProfileStatusV1 {
                network,
                version: profile.version,
                profile_hash: profile.profile_hash,
                activation_height: record.map(|record| record.activation_height),
                proposal_id: record.map(|record| record.proposal_id),
                supported_until_ms,
            })
        })
        .collect()
}

/// Return every installed light client (`GET /v1/sccp/light-clients`, §4.13); each record
/// names its network in `params.network`.
#[must_use]
pub fn light_clients(
    world: &(impl WorldReadOnly + ?Sized),
) -> Vec<iroha_data_model::sccp::light_client::SccpLightClientV1> {
    store::light_clients::iter(world)
        .map(|(_, light_client)| *light_client)
        .collect()
}

/// Return the stored consensus sets of `network`'s light client, ascending by set id
/// (`GET /v1/sccp/light-clients/{network}/sets`, §4.13.1). Wallets pick the set covering a proof
/// and its successor from them.
#[must_use]
pub fn light_client_sets(
    world: &(impl WorldReadOnly + ?Sized),
    network: iroha_data_model::bridge::SccpNetworkV1,
) -> Vec<iroha_data_model::sccp::light_client::SccpLcConsensusSetV1> {
    store::light_client_sets::iter(world)
        .filter(|((set_network, _), _)| *set_network == network)
        .map(|(_, set)| set.clone())
        .collect()
}

/// Return every open SCCP governance proposal, oldest first, with its admissibility and newest
/// Parliament attempt (`GET /v1/sccp/governance/proposals`, §4.14.5 item 4).
#[must_use]
pub fn governance_proposals(
    world: &(impl WorldReadOnly + ?Sized),
) -> Vec<iroha_sccp::api::SccpGovernanceProposalStatusV1> {
    use iroha_data_model::governance::types::{ProposalContentId, ProposalKind};
    use mv::storage::StorageReadOnly as _;
    let mut proposals: Vec<_> = world
        .governance_proposals()
        .iter()
        .filter_map(|(content_id, record)| {
            let ProposalKind::SccpRouteGovernance(sccp) = &record.kind else {
                return None;
            };
            if record.status != crate::state::GovernanceProposalStatus::Proposed {
                return None;
            }
            let content_id = ProposalContentId::new(*content_id);
            let latest_attempt =
                crate::governance::parliament::canonical_governance_attempt_ids_v1(content_id)
                    .map_while(|attempt_id| world.parliament_attempts().get(&attempt_id))
                    .last()
                    .map(|attempt| *attempt.attempt());
            Some(iroha_sccp::api::SccpGovernanceProposalStatusV1 {
                content_id,
                created_height: record.created_height,
                proposal: (*sccp.proposal).clone(),
                admissible: super::governance::preflight_attempt_in(world, &sccp.proposal).is_ok(),
                latest_attempt,
            })
        })
        .collect();
    proposals.sort_by_key(|proposal| (proposal.created_height, *proposal.content_id.as_bytes()));
    proposals
}

/// Return every nonzero SCCP governance revision (`GET /v1/sccp/governance`, §4.14.3); an
/// absent subject is at revision 0.
#[must_use]
pub fn governance_revisions(
    world: &(impl WorldReadOnly + ?Sized),
) -> Vec<iroha_data_model::sccp::governance::SccpGovernanceBaseRevisionV1> {
    store::governance_revisions::iter(world)
        .map(|(subject, revision)| (*subject, *revision).into())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
    use iroha_data_model::sccp::params::SccpParametersV1;

    #[test]
    fn capabilities_report_identity_parameters_and_limits() {
        let state = blank_state();
        let mut block = state.block(header(30));
        let mut stx = block.transaction();
        let empty = capabilities(&stx);
        assert_eq!(empty.parameters, None);
        assert_eq!(empty.network_id, *stx.network_id().as_bytes());
        assert_eq!(empty.domain_separator, domain_separator(&empty.network_id));
        assert_eq!(empty.limits, SccpReadLimitsV1::v1());
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let reported = capabilities(&stx);
        assert_eq!(reported.parameters, Some(SccpParametersV1::taira_default()));
        assert_eq!(
            reported.committed_height,
            u64::try_from(stx.height()).expect("height")
        );
        assert_eq!(
            reported.profiles.len(),
            SCCP_LC_PROFILE_NETWORKS_V1.len(),
            "one compiled profile per external network"
        );
    }

    #[test]
    fn light_client_profiles_report_the_active_version_per_network() {
        use iroha_data_model::{
            bridge::SccpNetworkV1, sccp::light_client::SccpLcProfileActivationV1,
        };
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let genesis = light_client_profiles(&*stx.world, 4);
        let networks: Vec<_> = genesis.iter().map(|status| status.network).collect();
        assert_eq!(networks, SCCP_LC_PROFILE_NETWORKS_V1.to_vec());
        let catalog = SccpLcProfileCatalogV1::compiled();
        for status in &genesis {
            assert_eq!(status.version, 1);
            assert_eq!(
                Some(status.profile_hash),
                catalog.profile_hash(status.network, 1)
            );
            assert_eq!(status.activation_height, None);
            assert_eq!(status.proposal_id, None);
            assert!(status.supported_until_ms.is_some());
        }
        assert_eq!(
            capabilities(&stx).profiles_policy_hash,
            catalog.genesis().policy_hash(),
            "without activations the policy hash commits to version 1 of every network"
        );
        let activation = SccpLcProfileActivationV1 {
            profile_hash: [7; 32],
            activation_height: 4,
            proposal_id: [8; 32],
        };
        store::light_client_profiles::insert(&mut stx, (SccpNetworkV1::BscMainnet, 2), activation)
            .expect("activation");
        assert_eq!(light_client_profiles(&*stx.world, 3), genesis);
        let activated = light_client_profiles(&*stx.world, 4);
        let bsc = activated
            .iter()
            .find(|status| status.network == SccpNetworkV1::BscMainnet)
            .expect("bsc");
        assert_eq!(bsc.version, 2);
        assert_eq!(bsc.profile_hash, [7; 32]);
        assert_eq!(bsc.activation_height, Some(4));
        assert_eq!(bsc.proposal_id, Some([8; 32]));
        assert_eq!(bsc.supported_until_ms, None, "this release lacks version 2");
        // Capabilities report the profiles of the next block, and the policy hash commits to
        // the same active versions (the SCCP input of the confidential policy digest).
        let reported = capabilities(&stx);
        let next = reported.committed_height + 1;
        assert_eq!(
            reported.light_client_profiles,
            light_client_profiles(&*stx.world, next)
        );
        let active = light_clients::active_profiles_at(&*stx.world, next, &catalog);
        assert_eq!(reported.profiles_policy_hash, active.policy_hash());
        assert_eq!(
            reported.profiles_policy_hash == catalog.genesis().policy_hash(),
            next < 4,
            "the activation changes the hash from its activation height"
        );
    }

    #[test]
    fn governance_revisions_list_nonzero_subjects() {
        use iroha_data_model::sccp::governance::SccpGovernanceSubjectV1;
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        assert!(governance_revisions(&*stx.world).is_empty());
        store::set_governance_revision(&mut stx, SccpGovernanceSubjectV1::Parameters, 2);
        let listed = governance_revisions(&*stx.world);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].subject, SccpGovernanceSubjectV1::Parameters);
        assert_eq!(listed[0].revision, 2);
    }

    #[test]
    fn light_client_sets_are_listed_per_network() {
        use iroha_data_model::{bridge::SccpNetworkV1, sccp::light_client::SccpLcConsensusSetV1};
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let set = |set_id| SccpLcConsensusSetV1 {
            set_id,
            valid_from_source_height: set_id,
            superseded_at_source_ms: None,
            set_bytes: vec![1],
        };
        for (network, set_id) in [
            (SccpNetworkV1::BscMainnet, 7_000),
            (SccpNetworkV1::EthereumMainnet, 1),
            (SccpNetworkV1::BscMainnet, 5_000),
        ] {
            store::light_client_sets::insert(&mut stx, (network, set_id), set(set_id))
                .expect("set");
        }
        let listed = light_client_sets(&*stx.world, SccpNetworkV1::BscMainnet);
        assert_eq!(
            listed.iter().map(|set| set.set_id).collect::<Vec<_>>(),
            vec![5_000, 7_000]
        );
        assert!(light_client_sets(&*stx.world, SccpNetworkV1::TonMainnet).is_empty());
    }
}
