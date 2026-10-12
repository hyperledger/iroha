//! Read-side SCCP record views and inclusion paths from committed state (`specs/sccp.md`
//! §6). Owner: ws35.
//!
//! Every honest peer derives identical bytes from committed state. Record views and inclusion
//! paths alone establish no finality; callers need an authenticated native certificate.
//! Torii, the CLI and tests share these functions. Stored record views (message status union,
//! pages, light-client detail, governance detail, history paths) live in [`views`]; history
//! paths go through the validated `O(log n)` node cache of `history`.
//!
//! Native certificates, message proofs and rotation DATA live in [`native`], using the
//! original committed source and caller-owned allocation/deadline controls. Its bounded
//! history scan is separate from the record-view cache; see its O(size) TODO.
//! Native control proofs require the complete native control-record producer in this batch.

mod history;
/// Original committed native SCCP certificate and proof DATA.
pub mod native;
mod views;

pub use views::*;

use super::{light_clients, store};
use crate::{
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::crypto::BlsCrypto,
};
use iroha_data_model::block::consensus::SumeragiRootScope;
/// The §6 wire types and page limits, re-exported for Torii and other readers.
pub use iroha_sccp::api::{self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES};
use iroha_sccp::{
    api::{SccpCapabilitiesV1, SccpFinalityConstantsV1, SccpLcProfileStatusV1, SccpReadLimitsV1},
    light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1},
};

/// Why a read cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SccpReadError {
    /// The original committed native identity is unavailable or inconsistent with this view.
    #[error("SCCP committed source unavailable: {0}")]
    Unavailable(String),
    /// SCCP capabilities belong to the independently authenticated Global root only.
    #[error("SCCP is unavailable for this authenticated non-Global root")]
    UnsupportedScope,
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

/// Assemble `GET /v1/sccp/capabilities` (§6) from one immutable committed view.
///
/// The native instance comes from the original opaque execution tip, not mutable World
/// metadata or a scope offered by the caller. This endpoint grants no certificate authority.
///
/// # Errors
/// Returns [`SccpReadError::Unavailable`] without a matching original committed tip and
/// journal, or [`SccpReadError::UnsupportedScope`] for an authenticated non-Global root.
/// No history read, re-authentication, or resource-failure conversion occurs here.
pub fn capabilities(
    view: &(impl StateReadOnly + ?Sized),
) -> Result<SccpCapabilitiesV1, SccpReadError> {
    let world = view.world();
    let network_id = *view.network_id().as_bytes();
    let tip = view.native_execution_tip().ok_or_else(|| {
        SccpReadError::Unavailable("original committed execution tip is absent".into())
    })?;
    let committed_height = u64::try_from(view.height())
        .map_err(|_| SccpReadError::Unavailable("committed journal height exceeds u64".into()))?;
    if tip.height() != committed_height
        || view
            .height()
            .checked_sub(1)
            .and_then(|index| view.block_hashes().get(index))
            != Some(&tip.iroha_hash())
        || view
            .block_hashes()
            .get(0)
            .map(|hash| iroha_data_model::NetworkId::from_genesis_hash(*hash))
            != Some(*view.network_id())
    {
        return Err(SccpReadError::Unavailable(
            "original tip, journal and network identity do not match".into(),
        ));
    }
    let scope = tip.root_scope();
    if scope != SumeragiRootScope::Global {
        return Err(SccpReadError::UnsupportedScope);
    }
    let chain_id = view.chain_id().to_string();
    let consensus_instance = scope
        .instance_id(&BlsCrypto::new(), *view.network_id(), &chain_id)
        .map_err(|_| SccpReadError::Unavailable("original root scope is invalid".into()))?
        .0;
    Ok(SccpCapabilitiesV1 {
        network_id,
        consensus_instance,
        finality: SccpFinalityConstantsV1::current(),
        parameters: store::parameters::get(world).clone(),
        committed_height,
        light_client_profiles: light_client_profiles(world, committed_height.saturating_add(1)),
        chain_id,
        profiles: compiled_profiles(),
        profiles_policy_hash: light_clients::active_profiles_at(
            world,
            committed_height.saturating_add(1),
            &SccpLcProfileCatalogV1::compiled(),
        )
        .policy_hash(),
        limits: SccpReadLimitsV1::v1(),
        path_templates: Vec::new(),
    })
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
        .map(|(subject, revision)| (subject.clone(), *revision).into())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::{
            commitment, leaves,
            test_support::{authority, blank_state, header},
        },
        state::{StateTransaction, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            control::{SccpLeafRefV1, SccpTransferLeafRefV1},
            outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        },
    };
    use iroha_sccp::v1::{
        history::{history_root, verify_history_inclusion},
        merkle::{PromoteOddTree, verify_block_inclusion},
    };

    /// Return the leaf hashes of block `height` in commitment order.
    fn block_leaf_hashes(
        world: &(impl WorldReadOnly + ?Sized),
        height: u64,
    ) -> Result<Vec<[u8; 32]>, SccpReadError> {
        leaves::leaves_at(world, height)
            .into_iter()
            .map(|leaf| {
                match leaf {
                    SccpLeafRefV1::Transfer(transfer) => {
                        store::outbound_messages::get(world, &transfer.message_id)
                            .map(|record| record.leaf)
                    }
                    SccpLeafRefV1::Control(control) => store::control_messages::get(
                        world,
                        &(control.network, control.revision, control.control_nonce),
                    )
                    .map(|record| record.leaf),
                }
                .ok_or_else(|| SccpReadError::NotFound(format!("a leaf record of block {height}")))
            })
            .collect()
    }

    fn record_message(stx: &mut StateTransaction<'_, '_>, seed: u8) -> [u8; 32] {
        let message_id = [seed; 32];
        let height = stx._curr_block.height().get();
        let index = leaves::allocate_leaf(
            stx,
            SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
        )
        .expect("leaf");
        store::outbound_messages::insert(
            stx,
            message_id,
            SccpOutboundMessageRecordV1 {
                network: SccpNetworkV1::EthereumMainnet,
                revision: 1,
                nonce: u64::from(seed),
                height,
                commitment_index: index,
                deadline_ms: 99,
                sender: authority(1),
                amount: 1,
                payload: vec![seed],
                leaf: [seed.wrapping_add(100); 32],
                status: SccpOutboundStatusV1::Recorded,
            },
        )
        .expect("record");
        message_id
    }

    #[test]
    fn capabilities_report_current_identity_and_parameters() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine Global genesis");
        let mut block = chain.state().block(header(2));
        let mut stx = block.transaction();
        let empty = capabilities(&stx).expect("original Global identity");
        assert_eq!(empty.parameters, None);
        assert_eq!(empty.network_id, *stx.network_id().as_bytes());
        assert_eq!(empty.consensus_instance, chain.instance().0);
        assert_eq!(empty.finality, SccpFinalityConstantsV1::current());
        let parameters = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
        store::parameters::set(&mut stx, Some(parameters.clone()));
        let reported = capabilities(&stx).expect("original Global identity");
        assert_eq!(reported.parameters, Some(parameters));
        assert_eq!(reported.network_id, empty.network_id);
        assert_eq!(reported.chain_id, stx.chain_id().to_string());
        assert_eq!(
            reported.committed_height,
            u64::try_from(stx.height()).expect("height")
        );
        assert_eq!(reported.limits, SccpReadLimitsV1::v1());
        assert!(
            reported.path_templates.is_empty(),
            "no unauthenticated proof route advertised"
        );
    }

    #[test]
    fn capabilities_refuse_without_original_execution() {
        let state = blank_state();
        assert!(matches!(
            capabilities(&state.view()),
            Err(SccpReadError::Unavailable(_))
        ));
    }

    #[test]
    fn capabilities_refuse_a_journal_without_matching_executed_tip() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine Global genesis");
        let mut block = chain.state().block(header(2));
        assert!(capabilities(&block).is_ok());
        block.block_hashes.push(chain.genesis().hash());
        assert!(matches!(
            capabilities(&block),
            Err(SccpReadError::Unavailable(_))
        ));
        drop(block);
        assert_eq!(
            capabilities(&chain.state().view())
                .unwrap()
                .consensus_instance,
            chain.instance().0
        );
    }

    #[test]
    fn capabilities_refuse_an_original_dataspace_root() {
        crate::state::native_capture_fixture::with_native_capture_dataspace_source(
            |state, _block, _guard, _source, _hash| {
                let view = state.view();
                assert!(matches!(
                    view.native_execution_tip()
                        .expect("genuine committed genesis")
                        .root_scope(),
                    SumeragiRootScope::Dataspace { .. }
                ));
                assert_eq!(capabilities(&view), Err(SccpReadError::UnsupportedScope));
            },
        );
    }

    #[test]
    fn light_client_profiles_report_the_active_version_per_network() {
        use iroha_data_model::{
            bridge::SccpNetworkV1, sccp::light_client::SccpLcProfileActivationV1,
        };
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine Global genesis");
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let mut block = chain.state().block(header(4));
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
            capabilities(&stx)
                .expect("original Global identity")
                .profiles_policy_hash,
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
        let reported = capabilities(&stx).expect("original Global identity");
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

    #[test]
    fn block_and_history_paths_verify() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        for seed in 1..=3 {
            record_message(&mut stx, seed);
        }
        let commitment = commitment::commit_block(&mut stx, 3)
            .expect("commit")
            .expect("commitment");
        let leaves = block_leaf_hashes(&*stx.world, 3).expect("leaves");
        assert_eq!(leaves.len(), 3);
        let tree = PromoteOddTree::block(&leaves).expect("block tree");
        for (index, leaf) in leaves.iter().enumerate() {
            let index = u32::try_from(index).expect("index");
            let path = tree
                .path(usize::try_from(index).expect("index"))
                .expect("path");
            let count = u32::try_from(leaves.len()).expect("count");
            assert_eq!(count, 3);
            verify_block_inclusion(leaf, index, count, &path, &commitment.root)
                .expect("block inclusion");
        }
        // The shared history reader proves block 3 against its stored history root.
        // These inclusion checks do not authenticate either root as native finality.
        let size = commitment::history_root_and_size(&*stx.world).1;
        let history: Vec<[u8; 32]> = store::history_leaves::range(&*stx.world, 0..size)
            .map(|(_, (_, leaf))| *leaf)
            .collect();
        let root = history_root(&history).expect("root");
        let (stored_root, history_proof) = history_proof(&*stx.world, 3, size).expect("history");
        assert_eq!(stored_root, root);
        assert_eq!(history_proof.sccp_root, commitment.root);
        let leaf = store::history_leaves::get(&*stx.world, &history_proof.leaf_index)
            .expect("history leaf")
            .1;
        verify_history_inclusion(
            &leaf,
            history_proof.leaf_index,
            size,
            &history_proof.path,
            &root,
        )
        .expect("history inclusion");
    }
}
