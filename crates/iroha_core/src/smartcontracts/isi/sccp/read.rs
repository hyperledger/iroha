//! Native SCCP read assembly over one committed State cut (`specs/sccp.md` §6).
//!
//! Certificates come only from verified canonical Kura carriers. No decoded DTO or caller
//! supplied committee establishes authority. History and monetary views share the same cut.

mod history;
#[cfg(test)]
#[path = "read/native_finality_tests.rs"]
mod native_finality_tests;
mod views;
use super::{leaves, light_clients, store};
use crate::{
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::certified_chain::CertifiedChain,
};
use iroha_data_model::{bridge::SccpNetworkV1, sccp::control::SccpLeafRefV1};
pub use iroha_sccp::api::{
    self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES, MAX_ROTATION_STEPS,
};
use iroha_sccp::{
    api::{
        SccpBlockRefV1, SccpCapabilitiesV1, SccpCertificateV1, SccpControlProofBundleV1,
        SccpGenerationV1, SccpLcProfileStatusV1, SccpMessageProofBundleV1, SccpReadLimitsV1,
        SccpRotationV1, finality::verify_native_certificate,
    },
    light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1},
    v1::{
        finality::{QcFixedV1, SccpFinalityHeaderV1, X_LEN, body_digest, signers_from_bitmap},
        merkle::{PromoteOddTree, verify_block_inclusion},
        proof::DestinationV1,
    },
};
use mv::storage::StorageReadOnly as _;
pub use views::*;

/// Why a read cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SccpReadError {
    /// The named record does not exist in this committed view.
    #[error("not found: {0}")]
    NotFound(String),
    /// Required native source custody is unavailable, not an invalid user payload.
    #[error("sccp_unavailable: {0}")]
    Unavailable(String),
    /// Retention removed a record that existed.
    #[error("sccp_pruned: {0}")]
    Pruned(String),
    /// The retained rotation window no longer covers the requested generation.
    #[error("sccp_rotation_pruned: {0}")]
    RotationPruned(String),
    /// The requested coordinates or source claims are inconsistent.
    #[error("invalid query: {0}")]
    Invalid(String),
}

/// Which committed certificate covers a proof (`?at=record|latest|<height>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpCertificateChoiceV1 {
    /// The block containing the leaf.
    Record,
    /// The durable committed tip of this view.
    Latest,
    /// An explicit committed height at or above the leaf.
    At(u64),
}
impl SccpCertificateChoiceV1 {
    /// Parse the native selector; retired selectors and zero heights are refused.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "record" => Some(Self::Record),
            "latest" => Some(Self::Latest),
            height if !height.is_empty() && height.bytes().all(|b| b.is_ascii_digit()) => {
                height.parse::<u64>().ok().filter(|h| *h > 0).map(Self::At)
            }
            _ => None,
        }
    }
}

/// Assemble identity and actual retained native generation state.
///
/// # Errors
/// Refuses an active SCCP instance without authenticated signed-genesis custody.
pub fn capabilities(
    view: &(impl StateReadOnly + ?Sized),
) -> Result<SccpCapabilitiesV1, SccpReadError> {
    let world = view.world();
    let parameters = store::parameters::get(world).clone();
    let consensus_instance = if parameters.is_some() {
        Some(
            CertifiedChain::new(view)
                .map_err(|e| SccpReadError::Unavailable(e.to_string()))?
                .instance()
                .0,
        )
    } else {
        None
    };
    let current = world.sccp_committee_current();
    let committed_height = view.height() as u64;
    let current_generation = generation_view(world, current);
    if parameters.is_some() && current_generation.is_none() {
        return Err(SccpReadError::Unavailable(
            "current native generation is not retained".into(),
        ));
    }
    Ok(SccpCapabilitiesV1 {
        network_id: *view.network_id().as_bytes(),
        consensus_instance,
        parameters,
        committed_height,
        current_generation,
        liability_clock: world.sccp_liability_clock(),
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
    })
}

/// Project one retained generation and its exact liability at this cut.
#[must_use]
pub fn generation_view(
    world: &(impl WorldReadOnly + ?Sized),
    generation: u64,
) -> Option<SccpGenerationV1> {
    let record = world.sccp_committee_generations().get(&generation)?;
    Some(SccpGenerationV1::from_record(
        record.record(),
        world.sccp_committee_current(),
        world.sccp_liability_clock(),
    ))
}

/// Read and independently verify a native SCCP certificate from canonical Kura custody.
///
/// # Errors
/// Refuses uncommitted heights, unavailable local carrier custody, pruned generations and
/// inconsistent certificates. Genesis has no CommitQC and cannot be fabricated into one.
pub fn finality_certificate(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
) -> Result<SccpCertificateV1, SccpReadError> {
    if height == 0 || height > view.height() as u64 {
        return Err(SccpReadError::NotFound(format!(
            "height {height} is not committed"
        )));
    }
    let chain = CertifiedChain::new(view).map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let block = chain
        .certified(height)
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let qc = block
        .commit_qc()
        .ok_or_else(|| SccpReadError::Unavailable("genesis has no native CommitQC".into()))?;
    let carrier = block
        .certificate()
        .ok_or_else(|| SccpReadError::Unavailable("native certificate carrier".into()))?;
    let preimage = carrier.result_preimage();
    let header = preimage
        .get(..X_LEN)
        .ok_or_else(|| SccpReadError::Unavailable("native finality header".into()))?;
    let header = SccpFinalityHeaderV1::parse(header)
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    if !header.is_active() {
        return Err(SccpReadError::Unavailable(
            "SCCP was inactive at the requested height".into(),
        ));
    }
    let world = view.world();
    let generation = world
        .sccp_committee_generations()
        .get(&header.generation())
        .ok_or_else(|| {
            if header.generation() < world.sccp_committee_current() {
                SccpReadError::Pruned(format!("native generation {}", header.generation()))
            } else {
                SccpReadError::Unavailable(
                    "certified generation is absent from the original cut".into(),
                )
            }
        })?;
    let signers =
        signers_from_bitmap(qc.signers.as_bytes(), generation.keys.len()).ok_or_else(|| {
            SccpReadError::Unavailable("native signer bitmap differs from generation".into())
        })?;
    let certificate = SccpCertificateV1 {
        height,
        header: *header.as_bytes(),
        aggregate_signature: qc.agg_sig.0,
        committee: generation.keys.clone(),
        qc: QcFixedV1 {
            epoch: qc.epoch.epoch,
            epoch_context: qc.epoch.context.0,
            view: qc.view,
            block_hash: qc.block_hash.0,
            result_body: body_digest(&preimage[X_LEN..]),
            signers,
        }
        .encode(),
    };
    let verified = verify_native_certificate(
        &certificate,
        view.network_id().as_bytes(),
        &chain.instance().0,
        generation.record(),
    )
    .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    if verified.result != qc.result.0 || verified.header.timestamp_ms() != block.block_time_ms() {
        return Err(SccpReadError::Unavailable(
            "certified source coordinates disagree".into(),
        ));
    }
    Ok(certificate)
}

fn certificate_height(
    committed_height: u64,
    record_height: u64,
    choice: SccpCertificateChoiceV1,
) -> Result<u64, SccpReadError> {
    let at = match choice {
        SccpCertificateChoiceV1::Record => record_height,
        SccpCertificateChoiceV1::Latest => committed_height,
        SccpCertificateChoiceV1::At(at) => at,
    };
    if at < record_height || at == 0 {
        return Err(SccpReadError::Invalid(
            "certificate height precedes the record".into(),
        ));
    }
    if at > committed_height {
        return Err(SccpReadError::NotFound(
            "certificate height is not committed".into(),
        ));
    }
    Ok(at)
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

/// Build and verify a block path and, when necessary, its certified history path.
fn leaf_paths(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    index: u32,
    certified: &SccpFinalityHeaderV1,
) -> Result<(Vec<[u8; 32]>, SccpBlockRefV1), SccpReadError> {
    if height > certified.height() {
        return Err(SccpReadError::Invalid("leaf is above certificate".into()));
    }
    let hashes = block_leaf_hashes(world, height)?;
    let tree =
        PromoteOddTree::block(&hashes).map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let path = tree
        .path(index as usize)
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let count =
        u32::try_from(hashes.len()).map_err(|_| SccpReadError::Unavailable("leaf count".into()))?;
    let block = if height == certified.height() {
        if count != certified.message_count() {
            return Err(SccpReadError::Unavailable(
                "recorded leaf count differs from certificate".into(),
            ));
        }
        SccpBlockRefV1 {
            height,
            sccp_root: certified.sccp_root(),
            message_count: count,
            history_index: 0,
            history_path: Vec::new(),
        }
    } else {
        let (root, history) = history_proof(world, height, certified.history_size())?;
        if root != certified.history_root() || count != history.message_count {
            return Err(SccpReadError::Unavailable(
                "retained history differs from certificate".into(),
            ));
        }
        iroha_sccp::v1::history::verify_history_inclusion(
            &iroha_sccp::v1::hashes::history_leaf(height, &history.sccp_root, count),
            history.leaf_index,
            certified.history_size(),
            &history.path,
            &certified.history_root(),
        )
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
        SccpBlockRefV1 {
            height,
            sccp_root: history.sccp_root,
            message_count: count,
            history_index: history.leaf_index,
            history_path: history.path,
        }
    };
    let leaf = hashes
        .get(index as usize)
        .ok_or_else(|| SccpReadError::Unavailable("missing leaf".into()))?;
    verify_block_inclusion(leaf, index, count, &path, &block.sccp_root)
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    Ok((path, block))
}

/// Serve a transfer only after verifying its native certificate, payload and both paths.
///
/// # Errors
/// Returns absence, retention or native-source refusal; never substitutes an attestation.
pub fn message_proof(
    view: &(impl StateReadOnly + ?Sized),
    message_id: &[u8; 32],
    choice: SccpCertificateChoiceV1,
) -> Result<SccpMessageProofBundleV1, SccpReadError> {
    let world = view.world();
    let record = store::outbound_messages::get(world, message_id)
        .ok_or_else(|| SccpReadError::NotFound("outbound message".into()))?;
    let at = certificate_height(view.height() as u64, record.height, choice)?;
    let certificate = finality_certificate(view, at)?;
    let header = SccpFinalityHeaderV1::parse(&certificate.header)
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let (path, block) = leaf_paths(world, record.height, record.commitment_index, &header)?;
    let route = store::routes::get(world, &record.network)
        .and_then(|route| route.revisions.get(&record.revision))
        .ok_or_else(|| SccpReadError::Unavailable("message route revision".into()))?;
    let bundle = SccpMessageProofBundleV1 {
        message_id: *message_id,
        payload: record.payload.clone(),
        deadline_ms: record.deadline_ms,
        leaf_index: record.commitment_index,
        path,
        block,
        certificate,
    };
    bundle
        .check_shape()
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    let verified = bundle
        .message_proof()
        .transfer(
            view.network_id().as_bytes(),
            &DestinationV1 {
                network: record.network,
                route_revision: record.revision,
                destination_word: route.destination_word,
            },
        )
        .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    if verified.message_id != *message_id
        || verified.payload.deadline_ms != record.deadline_ms
        || verified.leaf != record.leaf
        || verified.payload.amount != record.amount
    {
        return Err(SccpReadError::Unavailable(
            "recorded payload fields disagree".into(),
        ));
    }
    // Reverify using the computed payload leaf, not a server-supplied leaf claim.
    verify_block_inclusion(
        &verified.leaf,
        bundle.leaf_index,
        bundle.block.message_count,
        &bundle.path,
        &bundle.block.sccp_root,
    )
    .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
    Ok(bundle)
}

/// Read a native destination control bundle.
///
/// # Errors
/// Refuses missing records and the not-yet-integrated native control owner explicitly.
pub fn control_proof(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    control_nonce: u64,
    choice: SccpCertificateChoiceV1,
) -> Result<SccpControlProofBundleV1, SccpReadError> {
    let record = store::control_messages::get(view.world(), &(network, revision, control_nonce))
        .ok_or_else(|| SccpReadError::NotFound("control message".into()))?;
    certificate_height(view.height() as u64, record.height, choice)?;
    // TODO: migrate the admitted control writer/record to the native track, full pause state,
    // certificate id and effect hash. A retired paused-only leaf cannot be reinterpreted as one.
    Err(SccpReadError::Unavailable(
        "native control record owner is not integrated".into(),
    ))
}

/// Assemble retained native rotations in generation order, with every certificate verified.
///
/// # Errors
/// Returns a pruned window, missing native archive custody, or inconsistent lifecycle facts.
pub fn rotation_chain(
    view: &(impl StateReadOnly + ?Sized),
    after_generation: u64,
    limit: usize,
) -> Result<Vec<SccpRotationV1>, SccpReadError> {
    let world = view.world();
    let current = world.sccp_committee_current();
    if after_generation == 0
        || after_generation > current
        || !(1..=MAX_ROTATION_STEPS).contains(&limit)
    {
        return Err(SccpReadError::Invalid(
            "generation or rotation limit".into(),
        ));
    }
    if after_generation == current {
        return Ok(Vec::new());
    }
    let tip_time = view
        .authenticated_query_ledger_time_ms()
        .ok_or_else(|| SccpReadError::Unavailable("authenticated committed time".into()))?;
    let mut rotations = Vec::new();
    for id in after_generation..current {
        if rotations.len() == limit {
            break;
        }
        let record = world
            .sccp_committee_generations()
            .get(&id)
            .ok_or_else(|| SccpReadError::RotationPruned(format!("generation {id}")))?;
        if record.deadline_ms < tip_time {
            return Err(SccpReadError::RotationPruned(format!(
                "generation {id} is beyond its catch-up window"
            )));
        }
        let end = record
            .end
            .ok_or_else(|| SccpReadError::Unavailable("generation end".into()))?;
        let successor = world
            .sccp_committee_generations()
            .get(&(id + 1))
            .ok_or_else(|| SccpReadError::RotationPruned(format!("successor of {id}")))?;
        if end.next_committee_root != successor.committee_root
            || end.end_height.checked_add(1) != Some(successor.start_height)
            || end.end_timestamp_ms != successor.start_timestamp_ms
            || end.successor_validity_ms != successor.validity_ms
        {
            return Err(SccpReadError::Unavailable(
                "generation successor differs from handoff".into(),
            ));
        }
        // TODO: persist/backfill the node-local rotation archive so Kura body pruning does not
        // remove an otherwise retained destination catch-up window (§6).
        let certificate = finality_certificate(view, end.end_height)?;
        let header = SccpFinalityHeaderV1::parse(&certificate.header)
            .map_err(|e| SccpReadError::Unavailable(e.to_string()))?;
        if !header.is_rotation() || header.generation() != id {
            return Err(SccpReadError::Unavailable(
                "no certified handoff across this boundary".into(),
            ));
        }
        rotations.push(SccpRotationV1 {
            certificate,
            next_committee: successor.keys.clone(),
        });
    }
    Ok(rotations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::{
            commitment,
            test_support::{authority, blank_state, header},
        },
        state::StateTransaction,
    };
    use iroha_data_model::sccp::{
        control::SccpTransferLeafRefV1,
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
    };
    use iroha_sccp::v1::finality::{FLAG_ACTIVE, SccpFinalityHeaderFieldsV1};
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
            capabilities(&stx).unwrap().profiles_policy_hash,
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
        let reported = capabilities(&stx).unwrap();
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
    fn selectors_only_accept_native_committed_coordinates() {
        assert_eq!(
            SccpCertificateChoiceV1::parse("record"),
            Some(SccpCertificateChoiceV1::Record)
        );
        assert_eq!(
            SccpCertificateChoiceV1::parse("latest"),
            Some(SccpCertificateChoiceV1::Latest)
        );
        assert_eq!(
            SccpCertificateChoiceV1::parse("42"),
            Some(SccpCertificateChoiceV1::At(42))
        );
        for invalid in ["own", "0", "-1", "+1", " 1", "", "18446744073709551616"] {
            assert_eq!(SccpCertificateChoiceV1::parse(invalid), None);
        }
        assert_eq!(
            certificate_height(9, 3, SccpCertificateChoiceV1::Record),
            Ok(3)
        );
        assert_eq!(
            certificate_height(9, 3, SccpCertificateChoiceV1::Latest),
            Ok(9)
        );
        assert!(matches!(
            certificate_height(9, 3, SccpCertificateChoiceV1::At(2)),
            Err(SccpReadError::Invalid(_))
        ));
        assert!(matches!(
            certificate_height(9, 3, SccpCertificateChoiceV1::At(10)),
            Err(SccpReadError::NotFound(_))
        ));
    }
    #[test]
    fn absent_native_authority_never_yields_a_certificate() {
        let state = blank_state();
        let view = state.view();
        assert!(matches!(
            finality_certificate(&view, 0),
            Err(SccpReadError::NotFound(_))
        ));
        assert!(matches!(
            finality_certificate(&view, 1),
            Err(SccpReadError::NotFound(_))
        ));
        let caps = capabilities(&view).unwrap();
        assert_eq!(caps.consensus_instance, None);
        assert_eq!(caps.current_generation, None);
        assert_eq!(caps.liability_clock, 0);
        assert!(generation_view(view.world(), 1).is_none());
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
    fn block_and_history_paths_bind_to_native_certified_roots() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        for seed in 1..=3 {
            record_message(&mut stx, seed);
        }
        let commitment = commitment::commit_block(&mut stx, 3).unwrap().unwrap();
        let hashes = block_leaf_hashes(&*stx.world, 3).unwrap();
        let (history_root, history_size) = commitment::history_root_and_size(&*stx.world);
        let fields = SccpFinalityHeaderFieldsV1 {
            network_id: [1; 32],
            height: 3,
            timestamp_ms: 12_000,
            flags: FLAG_ACTIVE,
            generation: 1,
            committee_root: [2; 32],
            message_count: 3,
            sccp_root: commitment.root,
            history_root,
            history_size,
            ..SccpFinalityHeaderFieldsV1::default()
        };
        let direct = SccpFinalityHeaderV1::from_fields(&fields).unwrap();
        for (index, leaf) in hashes.iter().enumerate() {
            let (path, block) = leaf_paths(&*stx.world, 3, index as u32, &direct).unwrap();
            assert_eq!(block.message_count, 3);
            assert!(block.history_path.is_empty());
            verify_block_inclusion(leaf, index as u32, 3, &path, &block.sccp_root).unwrap();
        }
        let later = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            height: 9,
            ..fields
        })
        .unwrap();
        let (_, historical) = leaf_paths(&*stx.world, 3, 1, &later).unwrap();
        assert_eq!(historical.sccp_root, commitment.root);
        let leaf = store::history_leaves::get(&*stx.world, &historical.history_index)
            .unwrap()
            .1;
        iroha_sccp::v1::history::verify_history_inclusion(
            &leaf,
            historical.history_index,
            history_size,
            &historical.history_path,
            &history_root,
        )
        .unwrap();
        let altered = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            sccp_root: [9; 32],
            ..fields
        })
        .unwrap();
        assert!(leaf_paths(&*stx.world, 3, 1, &altered).is_err());
        let altered = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            height: 9,
            history_root: [9; 32],
            ..fields
        })
        .unwrap();
        assert!(leaf_paths(&*stx.world, 3, 1, &altered).is_err());
        assert!(leaf_paths(&*stx.world, 3, 3, &direct).is_err());
    }

    #[test]
    fn unknown_or_uncommitted_records_cannot_yield_native_bundles() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        assert!(matches!(
            message_proof(&stx, &[1; 32], SccpCertificateChoiceV1::Record),
            Err(SccpReadError::NotFound(_))
        ));
        let id = record_message(&mut stx, 7);
        assert!(matches!(
            message_proof(&stx, &id, SccpCertificateChoiceV1::Record),
            Err(SccpReadError::NotFound(_))
        ));
        assert!(matches!(
            control_proof(
                &stx,
                SccpNetworkV1::EthereumMainnet,
                1,
                99,
                SccpCertificateChoiceV1::Record
            ),
            Err(SccpReadError::NotFound(_))
        ));
        assert!(matches!(
            rotation_chain(&stx, 1, 16),
            Err(SccpReadError::Invalid(_))
        ));
    }
}
