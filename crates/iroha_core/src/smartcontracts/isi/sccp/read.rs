//! Read-side assembly of SCCP views and proof bundles from committed state (`specs/sccp.md`
//! §6). Owner: ws35.
//!
//! Every honest peer derives identical bytes from committed state; wallets and destinations
//! never trust them and verify every bundle themselves. Torii, the CLI and tests share these
//! functions. The views that do not depend on the attestation format (message status union,
//! pages, light-client detail, governance detail, history paths) live in [`views`]; history
//! paths go through the validated `O(log n)` node cache of `history`.
//!
//! TODO(ws35): serve signatures pruned from state (`attestation_retention_ms`, §4.10) from the
//! recorded `SubmitSccpAttestationsV1` transactions in Kura; until then they are `Pruned` (HTTP
//! 410).

mod history;
mod views;

pub use views::*;

use super::{leaves, light_clients, store, subjects};
use crate::state::{StateReadOnly, WorldReadOnly};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{attestation::SccpAttestationStatementV1, control::SccpLeafRefV1},
};
/// The §6 wire types and page limits, re-exported for Torii and other readers.
pub use iroha_sccp::api::{
    self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES, MAX_ROTATION_STEPS,
};
use iroha_sccp::{
    api::{
        SccpCapabilitiesV1, SccpControlProofBundleV1, SccpHistoryProofV1, SccpLcProfileStatusV1,
        SccpMemberLivenessV1, SccpMessageProofBundleV1, SccpPendingHandoffV1, SccpReadLimitsV1,
        SccpRosterViewV1, SccpRotationChainV1, SccpRotationStepV1, SccpSignatureSetV1,
    },
    light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1},
    v1::{eip712::domain_separator, merkle::PromoteOddTree, roster::RosterV1},
};

/// Why a read cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SccpReadError {
    /// The named record does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The record exists but is not attested yet (`sccp_attestation_pending`).
    #[error("sccp_attestation_pending: {0}")]
    Pending(String),
    /// The data existed but was pruned by retention (`sccp_pruned`, HTTP 410).
    #[error("sccp_pruned: {0}")]
    Pruned(String),
    /// The query is invalid against state.
    #[error("invalid query: {0}")]
    Invalid(String),
}

/// Which attestation a proof bundle uses (`?attestation=own|latest|<height>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpAttestationChoiceV1 {
    /// The subject of the block that holds the leaf (direct mode).
    Own,
    /// The newest attested subject at or above the leaf's block.
    Latest,
    /// The subject at this height, at or above the leaf's block.
    At(u64),
}

impl SccpAttestationChoiceV1 {
    /// Parse `own`, `latest` or a decimal height.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "own" => Some(Self::Own),
            "latest" => Some(Self::Latest),
            height => height.parse().ok().map(Self::At),
        }
    }
}

/// Assemble `GET /v1/sccp/capabilities` (§6).
#[must_use]
pub fn capabilities(view: &(impl StateReadOnly + ?Sized)) -> SccpCapabilitiesV1 {
    let world = view.world();
    let network_id = *view.network_id().as_bytes();
    let current_generation = *store::roster_current::get(world);
    let members = store::rosters::get(world, &current_generation)
        .map(|roster| {
            roster
                .members
                .iter()
                .enumerate()
                .filter_map(|(index, member)| {
                    Some(SccpMemberLivenessV1 {
                        index: u8::try_from(index).ok()?,
                        address: member.address,
                        last_signed_height: store::member_last_signed::get(world, &member.address)
                            .copied(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let pending_handoffs = store::rosters::iter(world)
        .filter_map(|(generation, roster)| {
            let height = roster.handoff_height?;
            let attested = store::attestation_status::get(world, &height)
                .is_some_and(|status| status.attested_at_height.is_some());
            (!attested).then(|| SccpPendingHandoffV1 {
                height,
                generation: *generation,
                stalled: store::handoff_stalled::contains(world, &height),
            })
        })
        .collect();
    let committed_height = u64::try_from(view.height()).unwrap_or(u64::MAX);
    SccpCapabilitiesV1 {
        network_id,
        domain_separator: domain_separator(&network_id),
        parameters: store::parameters::get(world).clone(),
        committed_height,
        latest_attested_height: store::attestation_status::iter(world)
            .rev()
            .find(|(_, status)| status.attested_at_height.is_some())
            .map(|(height, _)| *height),
        current_generation,
        members,
        pending_handoffs,
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
        .map(|(subject, revision)| (subject.clone(), *revision).into())
        .collect()
}

/// Return the view of generation `generation` under the live `NetworkId`.
#[must_use]
pub fn roster_view(
    world: &(impl WorldReadOnly + ?Sized),
    network_id: &[u8; 32],
    generation: u64,
) -> Option<SccpRosterViewV1> {
    let roster = store::rosters::get(world, &generation)?;
    SccpRosterViewV1::from_roster(
        &RosterV1 {
            generation,
            valid_from_ms: roster.valid_from_ms,
            valid_until_ms: roster.valid_until_ms,
            members: roster.members.iter().map(|member| member.address).collect(),
        },
        network_id,
    )
    .ok()
}

/// Return every signature stored for subject `height`, ascending by member index.
#[must_use]
pub fn signature_set(world: &(impl WorldReadOnly + ?Sized), height: u64) -> SccpSignatureSetV1 {
    let mut set = SccpSignatureSetV1::default();
    for ((_, index), signature) in
        store::attestation_signatures::range(world, (height, 0)..=(height, u8::MAX))
    {
        if *index < 32 {
            set.signer_bitmap |= 1 << index;
            set.signatures.push(*signature);
        }
    }
    set
}

/// An attested statement with everything a destination verifies it with.
struct Attested {
    statement: SccpAttestationStatementV1,
    digest: [u8; 32],
    roster: SccpRosterViewV1,
    signatures: SccpSignatureSetV1,
}

/// An attested subject `height` whose stored `signatures` are fewer than `threshold` had them
/// pruned by retention (§4.10): `Pruned` (HTTP 410), never `Pending`.
fn require_retained(
    height: u64,
    signatures: &SccpSignatureSetV1,
    threshold: u8,
) -> Result<(), SccpReadError> {
    if signatures.popcount() < u32::from(threshold) {
        return Err(SccpReadError::Pruned(format!(
            "the signatures of subject {height} were pruned from state; use a later attestation"
        )));
    }
    Ok(())
}

fn attested(view: &(impl StateReadOnly + ?Sized), height: u64) -> Result<Attested, SccpReadError> {
    let world = view.world();
    let statement = subjects::statement(view, height)
        .ok_or_else(|| SccpReadError::NotFound(format!("no attestation subject at {height}")))?;
    if !store::attestation_status::get(world, &height)
        .is_some_and(|status| status.attested_at_height.is_some())
    {
        return Err(SccpReadError::Pending(format!(
            "subject {height} is not attested"
        )));
    }
    let network_id = *view.network_id().as_bytes();
    let generation = store::attestation_subjects::get(world, &height)
        .map(|subject| subject.generation)
        .ok_or_else(|| SccpReadError::NotFound(format!("no attestation subject at {height}")))?;
    let roster = roster_view(world, &network_id, generation)
        .ok_or_else(|| SccpReadError::NotFound(format!("generation {generation} is unknown")))?;
    let signatures = signature_set(world, height);
    require_retained(height, &signatures, roster.threshold)?;
    Ok(Attested {
        digest: subjects::fields(&statement).digest(&network_id),
        statement,
        roster,
        signatures,
    })
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

/// Pick the attesting height for a leaf in block `height`.
fn attesting_height(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    choice: SccpAttestationChoiceV1,
) -> Result<u64, SccpReadError> {
    match choice {
        SccpAttestationChoiceV1::Own => Ok(height),
        SccpAttestationChoiceV1::At(at) if at >= height => Ok(at),
        SccpAttestationChoiceV1::At(at) => Err(SccpReadError::Invalid(format!(
            "attestation height {at} is below the leaf's block {height}"
        ))),
        SccpAttestationChoiceV1::Latest => store::attestation_subjects::range(world, height..)
            .rev()
            .map(|(subject_height, _)| *subject_height)
            .find(|subject_height| {
                store::attestation_status::get(world, subject_height)
                    .is_some_and(|status| status.attested_at_height.is_some())
            })
            .ok_or_else(|| {
                SccpReadError::Pending(format!("no attested subject at or above {height}"))
            }),
    }
}

/// Block path, leaf count and (for a later statement) history proof of leaf `index` of block
/// `height` under `attested`.
fn leaf_paths(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    index: u32,
    attested: &Attested,
) -> Result<(Vec<[u8; 32]>, u32, Option<SccpHistoryProofV1>), SccpReadError> {
    let leaves = block_leaf_hashes(world, height)?;
    let tree = PromoteOddTree::block(&leaves)
        .map_err(|error| SccpReadError::Invalid(format!("block {height} tree: {error}")))?;
    let path = tree
        .path(usize::try_from(index).unwrap_or(usize::MAX))
        .map_err(|error| SccpReadError::Invalid(format!("leaf {index}: {error}")))?;
    let message_count = u32::try_from(leaves.len())
        .map_err(|_| SccpReadError::Invalid("leaf count overflows".into()))?;
    if attested.statement.height == height {
        return Ok((path, message_count, None));
    }
    // O(log n) through the shared history cache, never a rebuild of the whole history.
    let (root, history) = history_proof(world, height, attested.statement.history_size)?;
    if root != attested.statement.history_root {
        return Err(SccpReadError::Invalid(format!(
            "the stored history disagrees with the history root of subject {}",
            attested.statement.height
        )));
    }
    Ok((path, message_count, Some(history)))
}

/// Assemble the proof bundle of outbound message `message_id` (`GET
/// /v1/sccp/messages/{message_id}/proof`, §6).
///
/// # Errors
///
/// [`SccpReadError::NotFound`] for an unknown message, [`SccpReadError::Pending`] until the
/// chosen subject is attested.
pub fn message_proof(
    view: &(impl StateReadOnly + ?Sized),
    message_id: &[u8; 32],
    choice: SccpAttestationChoiceV1,
) -> Result<SccpMessageProofBundleV1, SccpReadError> {
    let world = view.world();
    let record = store::outbound_messages::get(world, message_id)
        .ok_or_else(|| SccpReadError::NotFound("outbound message".into()))?;
    let at = attesting_height(world, record.height, choice)?;
    let attested = attested(view, at)?;
    let (path, message_count, history) =
        leaf_paths(world, record.height, record.commitment_index, &attested)?;
    Ok(SccpMessageProofBundleV1 {
        message_id: *message_id,
        payload: record.payload.clone(),
        deadline_ms: record.deadline_ms,
        leaf_index: record.commitment_index,
        message_count,
        path,
        statement: attested.statement,
        digest: attested.digest,
        roster: attested.roster,
        signatures: attested.signatures,
        history,
    })
}

/// Assemble the proof bundle of destination control `(network, revision, control_nonce)`
/// (`GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof`, §6).
///
/// # Errors
///
/// As [`message_proof`].
pub fn control_proof(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    control_nonce: u64,
    choice: SccpAttestationChoiceV1,
) -> Result<SccpControlProofBundleV1, SccpReadError> {
    let world = view.world();
    let record = store::control_messages::get(world, &(network, revision, control_nonce))
        .ok_or_else(|| SccpReadError::NotFound("control message".into()))?;
    let at = attesting_height(world, record.height, choice)?;
    let attested = attested(view, at)?;
    let (path, message_count, history) =
        leaf_paths(world, record.height, record.commitment_index, &attested)?;
    Ok(SccpControlProofBundleV1 {
        network,
        revision,
        control_nonce,
        paused: record.paused,
        leaf_index: record.commitment_index,
        message_count,
        path,
        statement: attested.statement,
        digest: attested.digest,
        roster: attested.roster,
        signatures: attested.signatures,
        history,
    })
}

/// Assemble the catch-up rotation chain from generation `after_generation` (`GET
/// /v1/sccp/rosters/rotations`, §6), at most `limit` (≤ 16) steps, reporting the first
/// unattested handoff.
#[must_use]
pub fn rotation_chain(
    view: &(impl StateReadOnly + ?Sized),
    after_generation: u64,
    limit: usize,
) -> SccpRotationChainV1 {
    let world = view.world();
    let network_id = *view.network_id().as_bytes();
    let mut chain = SccpRotationChainV1 {
        steps: Vec::new(),
        first_unattested_handoff: None,
    };
    let limit = limit.clamp(1, MAX_ROTATION_STEPS);
    let mut generation = after_generation;
    while chain.steps.len() < limit {
        let Some(handoff) =
            store::rosters::get(world, &generation).and_then(|roster| roster.handoff_height)
        else {
            break;
        };
        let (Ok(attested), Some(next_roster)) = (
            attested(view, handoff),
            roster_view(world, &network_id, generation.saturating_add(1)),
        ) else {
            chain.first_unattested_handoff = Some(handoff);
            break;
        };
        chain.steps.push(SccpRotationStepV1 {
            statement: attested.statement,
            digest: attested.digest,
            signatures: attested.signatures,
            current_roster: attested.roster,
            next_roster,
        });
        generation = generation.saturating_add(1);
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::{
            commitment,
            test_support::{authority, blank_state, header, sample_roster},
        },
        state::StateTransaction,
    };
    use iroha_data_model::sccp::{
        attestation::SccpAttestationSubjectV1,
        control::SccpTransferLeafRefV1,
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
    };
    use iroha_sccp::v1::{
        history::{history_root, verify_history_inclusion},
        merkle::verify_block_inclusion,
    };

    fn subject(height: u64, history_root: [u8; 32], history_size: u64) -> SccpAttestationSubjectV1 {
        SccpAttestationSubjectV1 {
            height,
            epoch: 0,
            timestamp_ms: height * 4_000,
            sccp_root: [0; 32],
            message_count: 0,
            history_root,
            history_size,
            generation: 1,
            roster_digest: [5; 32],
            next_roster_digest: [0; 32],
        }
    }

    fn attested_at(statement: SccpAttestationStatementV1) -> Attested {
        Attested {
            statement,
            digest: [0; 32],
            roster: SccpRosterViewV1 {
                generation: 1,
                valid_from_ms: 0,
                valid_until_ms: 1,
                threshold: 1,
                members: Vec::new(),
                digest: [0; 32],
            },
            signatures: SccpSignatureSetV1::default(),
        }
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
    fn attestation_choices_parse() {
        assert_eq!(
            SccpAttestationChoiceV1::parse("own"),
            Some(SccpAttestationChoiceV1::Own)
        );
        assert_eq!(
            SccpAttestationChoiceV1::parse("latest"),
            Some(SccpAttestationChoiceV1::Latest)
        );
        assert_eq!(
            SccpAttestationChoiceV1::parse("42"),
            Some(SccpAttestationChoiceV1::At(42))
        );
        assert_eq!(SccpAttestationChoiceV1::parse("-1"), None);
    }

    #[test]
    fn capabilities_report_identity_generation_and_pending_handoffs() {
        let state = blank_state();
        let mut block = state.block(header(30));
        let mut stx = block.transaction();
        let empty = capabilities(&stx);
        assert_eq!(empty.parameters, None);
        assert_eq!(empty.domain_separator, domain_separator(&empty.network_id));
        let mut first = sample_roster(1, 1);
        first.handoff_height = Some(10);
        store::rosters::insert(&mut stx, 1, first).expect("roster");
        store::rosters::insert(&mut stx, 2, sample_roster(2, 11)).expect("roster");
        store::roster_current::set(&mut stx, 2);
        store::member_last_signed::insert(&mut stx, [1; 20], 9).expect("liveness");
        store::handoff_stalled::insert(&mut stx, 10, 1).expect("stalled");
        let reported = capabilities(&stx);
        assert_eq!(reported.current_generation, 2);
        assert_eq!(reported.members.len(), 4);
        assert_eq!(reported.members[0].last_signed_height, Some(9));
        assert_eq!(
            reported.pending_handoffs,
            vec![SccpPendingHandoffV1 {
                height: 10,
                generation: 1,
                stalled: true
            }]
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

    #[test]
    fn signature_sets_follow_member_order() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        store::attestation_signatures::insert(&mut stx, (2, 3), [3; 65]).expect("sig");
        store::attestation_signatures::insert(&mut stx, (2, 0), [1; 65]).expect("sig");
        store::attestation_signatures::insert(&mut stx, (4, 1), [9; 65]).expect("sig");
        let set = signature_set(&*stx.world, 2);
        assert_eq!(set.signer_bitmap, 0b1001);
        assert_eq!(set.signatures, vec![[1; 65], [3; 65]]);
    }

    #[test]
    fn signatures_below_the_threshold_of_an_attested_subject_are_pruned() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        for index in [0_u8, 2] {
            store::attestation_signatures::insert(&mut stx, (2, index), [index; 65]).expect("sig");
        }
        let two = signature_set(&*stx.world, 2);
        assert!(matches!(
            require_retained(2, &two, 3),
            Err(SccpReadError::Pruned(message)) if message.contains("subject 2")
        ));
        assert_eq!(require_retained(2, &two, 2), Ok(()));
        // Fully pruned: no signature is left at all.
        assert!(matches!(
            require_retained(5, &signature_set(&*stx.world, 5), 1),
            Err(SccpReadError::Pruned(_))
        ));
    }

    #[test]
    fn unknown_and_unattested_messages_have_no_bundle() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        assert!(matches!(
            message_proof(&stx, &[1; 32], SccpAttestationChoiceV1::Own),
            Err(SccpReadError::NotFound(_))
        ));
        let id = record_message(&mut stx, 7);
        commitment::commit_block(&mut stx, 3).expect("commit");
        store::attestation_subjects::insert(&mut stx, 3, subject(3, [0; 32], 1)).expect("subject");
        assert!(matches!(
            message_proof(&stx, &id, SccpAttestationChoiceV1::Latest),
            Err(SccpReadError::Pending(_))
        ));
        assert!(matches!(
            message_proof(&stx, &id, SccpAttestationChoiceV1::At(2)),
            Err(SccpReadError::Invalid(_))
        ));
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
        let direct = attested_at(subject(3, [0; 32], 1).statement([0; 32]));
        for (index, leaf) in leaves.iter().enumerate() {
            let index = u32::try_from(index).expect("index");
            let (path, count, history) = leaf_paths(&*stx.world, 3, index, &direct).expect("paths");
            assert_eq!((count, history), (3, None));
            verify_block_inclusion(leaf, index, count, &path, &commitment.root)
                .expect("block inclusion");
        }
        // A later statement proves block 3 through its history root.
        let size = commitment::history_root_and_size(&*stx.world).1;
        let history: Vec<[u8; 32]> = store::history_leaves::range(&*stx.world, 0..size)
            .map(|(_, (_, leaf))| *leaf)
            .collect();
        let root = history_root(&history).expect("root");
        let later = attested_at(subject(9, root, size).statement([0; 32]));
        let (_, _, history_proof) = leaf_paths(&*stx.world, 3, 1, &later).expect("paths");
        let history_proof = history_proof.expect("historical mode");
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

    #[test]
    fn rotation_chains_stop_at_the_first_unattested_handoff() {
        let state = blank_state();
        let mut block = state.block(header(30));
        let mut stx = block.transaction();
        let mut first = sample_roster(1, 1);
        first.handoff_height = Some(10);
        store::rosters::insert(&mut stx, 1, first).expect("roster");
        store::rosters::insert(&mut stx, 2, sample_roster(2, 11)).expect("roster");
        let chain = rotation_chain(&stx, 1, 16);
        assert!(chain.steps.is_empty());
        assert_eq!(chain.first_unattested_handoff, Some(10));
        let current = rotation_chain(&stx, 2, 16);
        assert!(current.steps.is_empty());
        assert_eq!(current.first_unattested_handoff, None);
    }
}
