//! Read-side views of SCCP records (`specs/sccp.md` §6): the message status union, outbound
//! and control pages, recent messages, light-client detail and checkpoint cover, governance
//! proposal detail and history paths.
//!
//! TODO: Torii work package (TT-A2): report `provable` on a recorded outbound state and on a
//! control once a covering active certificate exists (§6).

use super::{
    SccpReadError,
    history::funded::{SccpHistoryNodeCache, SccpHistoryReadError},
    store,
};
use crate::state::{StateReadOnly, WorldReadOnly};
use core::{cmp::Reverse, ops::Bound};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{control::SccpLeafRefV1, outbound::SccpOutboundMessageRecordV1},
};
use iroha_sccp::{
    api::{
        MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES, SccpBlockRefV1,
        SccpChainProfileViewV1, SccpControlPageV1, SccpControlViewV1,
        SccpGovernanceProposalDetailV1, SccpGovernanceProposalPhaseV1, SccpHistoryPathViewV1,
        SccpInboundMessageViewV1, SccpLcCheckpointCoverV1, SccpLcCheckpointEntryV1,
        SccpLcCheckpointsSummaryV1, SccpLcSetsSummaryV1, SccpLightClientDetailV1,
        SccpMessageStatusV1, SccpOutboundMessageViewV1, SccpOutboundPageV1, SccpOutboundStateV1,
        SccpRecentMessagesV1, SccpRecordedStateV1,
    },
    light_client::{
        profile::{SccpChainProfilesV1, SccpLcProfileCatalogV1},
        state::is_permanent_checkpoint,
    },
};
use std::collections::BinaryHeap;

/// Most leaves one `recent` page scans (the network filter may skip most of them).
pub const MAX_RECENT_SCAN: usize = 4_096;

/// Most retained checkpoints a checkpoint cover scans for a Parliament-installed permanent one
/// below the nearest stride-permanent one (which the stride index names directly).
pub const MAX_CHECKPOINT_SCAN: usize = 4_096;

/// Direction filter of `GET /v1/sccp/messages/recent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpDirectionV1 {
    /// Taira → external records.
    Outbound,
    /// External → Taira records.
    Inbound,
}

impl SccpDirectionV1 {
    /// Parse `outbound` or `inbound`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "outbound" => Some(Self::Outbound),
            "inbound" => Some(Self::Inbound),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Outbound state
// ---------------------------------------------------------------------------------------------

/// Wallet-facing state of `record`: its stored status, with the deadline of a recorded message.
fn outbound_state(record: &SccpOutboundMessageRecordV1) -> SccpOutboundStateV1 {
    use iroha_data_model::sccp::outbound::SccpOutboundStatusV1 as Stored;
    match record.status {
        Stored::Voided(void) => SccpOutboundStateV1::Voided(void),
        Stored::Refunded(height) => SccpOutboundStateV1::Refunded(height),
        Stored::Stranded(height) => SccpOutboundStateV1::Stranded(height),
        Stored::Recorded => SccpOutboundStateV1::Recorded(SccpRecordedStateV1 {
            deadline_ms: record.deadline_ms,
        }),
    }
}

fn outbound_view(
    message_id: [u8; 32],
    record: &SccpOutboundMessageRecordV1,
) -> SccpOutboundMessageViewV1 {
    SccpOutboundMessageViewV1 {
        message_id,
        record: record.clone(),
        state: outbound_state(record),
    }
}

// ---------------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------------

/// Assemble `GET /v1/sccp/messages/{message_id}` (§6): the outbound or inbound record with its
/// state, or `unknown`.
#[must_use]
pub fn message_status(
    world: &(impl WorldReadOnly + ?Sized),
    message_id: &[u8; 32],
) -> SccpMessageStatusV1 {
    if let Some(record) = store::outbound_messages::get(world, message_id) {
        return SccpMessageStatusV1::Outbound(outbound_view(*message_id, record));
    }
    store::inbound_messages::get(world, message_id).map_or(SccpMessageStatusV1::Unknown, |record| {
        SccpMessageStatusV1::Inbound(SccpInboundMessageViewV1 {
            message_id: *message_id,
            record: record.clone(),
        })
    })
}

/// Assemble `GET /v1/sccp/outbound/{network}/{revision}?from_nonce&limit` (§6): records of the
/// revision by nonce, ascending, at most `limit` (≤ 256).
///
/// # Errors
///
/// [`SccpReadError::NotFound`] when the route revision does not exist.
pub fn outbound_page(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    from_nonce: u64,
    limit: usize,
) -> Result<SccpOutboundPageV1, SccpReadError> {
    let next_outbound_nonce = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .map(|record| record.next_outbound_nonce)
        .ok_or_else(|| {
            SccpReadError::NotFound(format!("{} revision {revision}", network.profile_key()))
        })?;
    let limit = limit.clamp(1, MAX_OUTBOUND_PAGE);
    let mut records = Vec::new();
    let mut next_from_nonce = None;
    for ((_, _, nonce), message_id) in store::outbound_by_nonce::range(
        world,
        (network, revision, from_nonce)..=(network, revision, u64::MAX),
    ) {
        if records.len() == limit {
            next_from_nonce = Some(*nonce);
            break;
        }
        let record = store::outbound_messages::get(world, message_id).ok_or_else(|| {
            SccpReadError::NotFound(format!("the record of outbound nonce {nonce}"))
        })?;
        records.push(outbound_view(*message_id, record));
    }
    Ok(SccpOutboundPageV1 {
        network,
        revision,
        next_outbound_nonce,
        records,
        next_from_nonce,
    })
}

fn parse_cursor(text: &str) -> Option<(u64, &str)> {
    let (height, rest) = text.split_once(':')?;
    Some((height.parse().ok()?, rest))
}

fn invalid_cursor() -> SccpReadError {
    SccpReadError::Invalid(
        "`before` is `<height>:<index>` (outbound) or `<height>:<message id hex>` (inbound)".into(),
    )
}

/// Newest outbound records strictly before the `(height, commitment_index)` cursor.
fn recent_outbound(
    world: &(impl WorldReadOnly + ?Sized),
    network: Option<SccpNetworkV1>,
    before: Option<(u64, u32)>,
    limit: usize,
) -> SccpRecentMessagesV1 {
    let upper = before.map_or(Bound::Unbounded, Bound::Excluded);
    let leaves = store::block_leaves::range(world, (Bound::Unbounded, upper));
    let mut messages = Vec::new();
    let mut next_before = None;
    for (scanned, ((height, index), leaf)) in leaves.rev().enumerate() {
        if messages.len() == limit || scanned == MAX_RECENT_SCAN {
            // Resume after the last returned or scanned leaf.
            next_before = Some(format!("{height}:{}", index.saturating_add(1)));
            break;
        }
        let SccpLeafRefV1::Transfer(transfer) = leaf else {
            continue;
        };
        let Some(record) = store::outbound_messages::get(world, &transfer.message_id) else {
            continue;
        };
        if network.is_some_and(|network| network != record.network) {
            continue;
        }
        messages.push(SccpMessageStatusV1::Outbound(outbound_view(
            transfer.message_id,
            record,
        )));
    }
    SccpRecentMessagesV1 {
        messages,
        next_before,
    }
}

/// Newest inbound records strictly before the `(proven_at_height, message_id)` cursor.
///
/// TODO(ws35): index inbound records by proven height in state; this scans every inbound
/// record (keeping only the newest `limit` in a bounded heap).
fn recent_inbound(
    world: &(impl WorldReadOnly + ?Sized),
    network: Option<SccpNetworkV1>,
    before: Option<(u64, [u8; 32])>,
    limit: usize,
) -> SccpRecentMessagesV1 {
    let mut newest: BinaryHeap<Reverse<(u64, [u8; 32])>> = BinaryHeap::new();
    let mut more = false;
    for (message_id, record) in store::inbound_messages::iter(world) {
        let key = (record.proven_at_height, *message_id);
        if network.is_some_and(|network| network != record.network)
            || before.is_some_and(|before| key >= before)
        {
            continue;
        }
        newest.push(Reverse(key));
        if newest.len() > limit {
            newest.pop();
            more = true;
        }
    }
    let mut keys: Vec<(u64, [u8; 32])> = newest.into_iter().map(|Reverse(key)| key).collect();
    keys.sort_unstable_by(|a, b| b.cmp(a));
    let next_before = if more {
        keys.last()
            .map(|(height, message_id)| format!("{height}:{}", hex::encode(message_id)))
    } else {
        None
    };
    let messages = keys
        .into_iter()
        .filter_map(|(_, message_id)| {
            store::inbound_messages::get(world, &message_id).map(|record| {
                SccpMessageStatusV1::Inbound(SccpInboundMessageViewV1 {
                    message_id,
                    record: record.clone(),
                })
            })
        })
        .collect();
    SccpRecentMessagesV1 {
        messages,
        next_before,
    }
}

/// Assemble `GET /v1/sccp/messages/recent?direction&network&before&limit` (§6): records of one
/// direction, newest first, at most `limit` (≤ 50).
///
/// # Errors
///
/// [`SccpReadError::Invalid`] for a malformed `before` cursor.
pub fn recent_messages(
    world: &(impl WorldReadOnly + ?Sized),
    direction: SccpDirectionV1,
    network: Option<SccpNetworkV1>,
    before: Option<&str>,
    limit: usize,
) -> Result<SccpRecentMessagesV1, SccpReadError> {
    let limit = limit.clamp(1, MAX_RECENT_MESSAGES);
    match direction {
        SccpDirectionV1::Outbound => {
            let before = before
                .map(|text| {
                    parse_cursor(text)
                        .and_then(|(height, index)| Some((height, index.parse().ok()?)))
                        .ok_or_else(invalid_cursor)
                })
                .transpose()?;
            Ok(recent_outbound(world, network, before, limit))
        }
        SccpDirectionV1::Inbound => {
            let before = before
                .map(|text| {
                    parse_cursor(text)
                        .and_then(|(height, id)| {
                            let id = <[u8; 32]>::try_from(hex::decode(id).ok()?).ok()?;
                            Some((height, id))
                        })
                        .ok_or_else(invalid_cursor)
                })
                .transpose()?;
            Ok(recent_inbound(world, network, before, limit))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------------------------

/// Assemble `GET /v1/sccp/controls/{network}/{revision}?after_nonce&limit` (§6, §4.14.6):
/// controls with nonce above `after_nonce`, ascending, at most `limit` (≤ 64).
///
/// # Errors
///
/// [`SccpReadError::NotFound`] when the route revision does not exist.
pub fn controls_page(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    after_nonce: u64,
    limit: usize,
) -> Result<SccpControlPageV1, SccpReadError> {
    let next_control_nonce = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .map(|record| record.next_control_nonce)
        .ok_or_else(|| {
            SccpReadError::NotFound(format!("{} revision {revision}", network.profile_key()))
        })?;
    let limit = limit.clamp(1, MAX_CONTROLS_PAGE);
    let mut controls = Vec::new();
    let mut next_after_nonce = None;
    for ((_, _, control_nonce), record) in store::control_messages::range(
        world,
        (
            Bound::Excluded((network, revision, after_nonce)),
            Bound::Included((network, revision, u64::MAX)),
        ),
    ) {
        if controls.len() == limit {
            next_after_nonce = controls
                .last()
                .map(|view: &SccpControlViewV1| view.control_nonce);
            break;
        }
        controls.push(SccpControlViewV1 {
            control_nonce: *control_nonce,
            record: *record,
        });
    }
    Ok(SccpControlPageV1 {
        network,
        revision,
        next_control_nonce,
        controls,
        next_after_nonce,
    })
}

// ---------------------------------------------------------------------------------------------
// Light clients
// ---------------------------------------------------------------------------------------------

/// The last source time the newest profile version of `network` the running release compiles
/// verifies. The chain verifies under the version active at its height
/// ([`super::light_client_profiles`]), which may be older until the Parliament activates the
/// newer one (§4.13.2).
#[must_use]
pub fn compiled_supported_until_ms(network: SccpNetworkV1) -> Option<u64> {
    SccpChainProfilesV1::latest().supported_until_ms(network)
}

/// The newest compiled source-chain profiles of the running release, in network order
/// (`GET /v1/sccp/capabilities`).
#[must_use]
pub fn compiled_profiles() -> Vec<SccpChainProfileViewV1> {
    [
        SccpNetworkV1::EthereumMainnet,
        SccpNetworkV1::BscMainnet,
        SccpNetworkV1::TonMainnet,
    ]
    .into_iter()
    .map(|network| SccpChainProfileViewV1 {
        network,
        supported_until_ms: compiled_supported_until_ms(network),
    })
    .collect()
}

/// Lowest checkpoint height of the stride bucket of `height`, if indexed.
fn lowest_in_bucket(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    stride: u64,
    height: u64,
) -> Option<u64> {
    height
        .checked_div(stride)
        .and_then(|bucket| store::light_client_stride_index::get(world, &(network, bucket)))
        .copied()
}

/// This release's compiled profiles with the version of `network` active at the next block (over
/// the genesis versions of the other networks), the profile the light client's next verification
/// runs under (§4.13.2); `None` when the release does not compile that version.
fn next_block_profiles(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
) -> Option<SccpChainProfilesV1> {
    let next_height = u64::try_from(view.height())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let catalog = SccpLcProfileCatalogV1::compiled();
    let active =
        super::super::light_clients::active_profiles_at(view.world(), next_height, &catalog);
    let profile = active.get(network)?;
    catalog
        .resolve(&catalog.genesis().with(network, profile))
        .ok()
}

/// Assemble `GET /v1/sccp/light-clients/{network}` (§6, §4.13): the light client with its
/// freshness at the committed block time, the `supported_until` of the profile version active at
/// the next block, and its stored data.
///
/// # Errors
///
/// [`SccpReadError::NotFound`] when no light client of `network` is installed.
pub fn light_client_detail(
    view: &(impl StateReadOnly + ?Sized),
    network: SccpNetworkV1,
) -> Result<SccpLightClientDetailV1, SccpReadError> {
    use super::super::light_clients::{WorldLightClientView, is_usable};
    let world = view.world();
    let light_client = *store::light_clients::get(world, &network).ok_or_else(|| {
        SccpReadError::NotFound(format!("no {} light client", network.profile_key()))
    })?;
    let bounds = (network, 0)..=(network, u64::MAX);
    let mut sets = SccpLcSetsSummaryV1::default();
    for ((_, set_id), _) in store::light_client_sets::range(world, bounds.clone()) {
        sets.count += 1;
        sets.oldest_set_id.get_or_insert(*set_id);
        sets.latest_set_id = Some(*set_id);
    }
    let mut checkpoints = SccpLcCheckpointsSummaryV1::default();
    for ((_, height), _) in store::light_client_checkpoints::range(world, bounds.clone()) {
        checkpoints.count += 1;
        checkpoints.lowest_source_height.get_or_insert(*height);
        checkpoints.highest_source_height = Some(*height);
    }
    checkpoints.permanent_buckets =
        store::light_client_stride_index::range(world, bounds).count() as u64;
    // A light client this release cannot verify under its active version is never usable, and
    // neither is one judged without an authenticated block time.
    let profiles = next_block_profiles(view, network);
    let now_ms = view.authenticated_query_ledger_time_ms();
    Ok(SccpLightClientDetailV1 {
        light_client,
        usable: profiles
            .as_ref()
            .zip(now_ms)
            .is_some_and(|(profiles, now_ms)| is_usable(world, profiles, network, now_ms)),
        weak_subjectivity_deadline_ms: profiles.as_ref().and_then(|profiles| {
            iroha_sccp::light_client::weak_subjectivity_deadline_ms_with_profiles(
                profiles,
                &WorldLightClientView(world),
                network,
            )
            .ok()
        }),
        supported_until_ms: profiles.and_then(|profiles| profiles.supported_until_ms(network)),
        sets,
        checkpoints,
    })
}

/// Assemble `GET /v1/sccp/light-clients/{network}/checkpoints?covering=N` (§6, §4.13.5): the
/// lowest retained checkpoint at or above `covering`, and the lowest permanent one.
///
/// # Errors
///
/// [`SccpReadError::NotFound`] when no light client is installed or its head is below
/// `covering` (not finalized on Taira yet); [`SccpReadError::Pruned`] when the head covers it
/// but no checkpoint at or above it is retained.
pub fn checkpoint_cover(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    covering: u64,
) -> Result<SccpLcCheckpointCoverV1, SccpReadError> {
    let light_client = store::light_clients::get(world, &network).ok_or_else(|| {
        SccpReadError::NotFound(format!("no {} light client", network.profile_key()))
    })?;
    let head = light_client.head.latest_finalized;
    let stride = light_client.params.checkpoint_stride;
    let entry = |checkpoint: &iroha_data_model::sccp::light_client::SccpLcCheckpointV1| {
        SccpLcCheckpointEntryV1 {
            checkpoint: *checkpoint,
            permanent: is_permanent_checkpoint(
                network,
                checkpoint,
                stride,
                lowest_in_bucket(world, network, stride, checkpoint.data.source_height),
            ),
        }
    };
    let mut retained =
        store::light_client_checkpoints::range(world, (network, covering)..=(network, u64::MAX))
            .map(|(_, checkpoint)| entry(checkpoint));
    let Some(nearest) = retained.next() else {
        return Err(if head.source_height >= covering {
            SccpReadError::Pruned(format!(
                "no retained {} checkpoint at or above {covering}",
                network.profile_key()
            ))
        } else {
            SccpReadError::NotFound(format!(
                "the {} light client head {} is below {covering}",
                network.profile_key(),
                head.source_height
            ))
        });
    };
    let nearest_permanent = if nearest.permanent {
        Some(nearest)
    } else {
        // The lowest checkpoint of each stride bucket is permanent, so the stride index names
        // the nearest one at or above `covering` directly; only Parliament-installed checkpoints
        // below it need the (bounded) scan of the retained ones.
        let by_stride = covering
            .checked_div(stride)
            .and_then(|bucket| {
                store::light_client_stride_index::range(
                    world,
                    (network, bucket)..=(network, u64::MAX),
                )
                .map(|(_, lowest)| *lowest)
                .find(|lowest| *lowest >= covering)
            })
            .and_then(|height| store::light_client_checkpoints::get(world, &(network, height)))
            .map(|checkpoint| entry(checkpoint))
            .filter(|candidate| candidate.permanent);
        let bound = by_stride.map(|candidate| candidate.checkpoint.data.source_height);
        retained
            .take_while(|candidate| {
                bound.is_none_or(|bound| candidate.checkpoint.data.source_height < bound)
            })
            .take(MAX_CHECKPOINT_SCAN)
            .find(|candidate| candidate.permanent)
            .or(by_stride)
    };
    Ok(SccpLcCheckpointCoverV1 {
        network,
        covering,
        head,
        nearest,
        nearest_permanent,
    })
}

// ---------------------------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------------------------

/// Assemble `GET /v1/sccp/governance/proposals/{proposal_id}` (§6): one SCCP proposal in any
/// phase with its admissibility and newest Parliament attempt.
///
/// # Errors
///
/// [`SccpReadError::NotFound`] when no SCCP proposal has this content id.
pub fn governance_proposal(
    world: &(impl WorldReadOnly + ?Sized),
    content_id: [u8; 32],
) -> Result<SccpGovernanceProposalDetailV1, SccpReadError> {
    use crate::state::GovernanceProposalStatus as Status;
    use iroha_data_model::governance::types::{ProposalContentId, ProposalKind};
    use mv::storage::StorageReadOnly as _;
    let not_found =
        || SccpReadError::NotFound(format!("SCCP proposal {}", hex::encode(content_id)));
    let record = world
        .governance_proposals()
        .get(&content_id)
        .ok_or_else(not_found)?;
    let ProposalKind::SccpRouteGovernance(sccp) = &record.kind else {
        return Err(not_found());
    };
    let content = ProposalContentId::new(content_id);
    let latest_attempt =
        crate::governance::parliament::canonical_governance_attempt_ids_v1(content)
            .map_while(|attempt_id| world.parliament_attempts().get(&attempt_id))
            .last()
            .map(|attempt| *attempt.attempt());
    Ok(SccpGovernanceProposalDetailV1 {
        content_id: content,
        proposer: record.proposer.clone(),
        created_height: record.created_height,
        phase: match record.status {
            Status::Proposed => SccpGovernanceProposalPhaseV1::Proposed,
            Status::Rejected => SccpGovernanceProposalPhaseV1::Rejected,
            Status::Enacted => SccpGovernanceProposalPhaseV1::Enacted,
            Status::Superseded => SccpGovernanceProposalPhaseV1::Superseded,
            Status::ExecutionFailed => SccpGovernanceProposalPhaseV1::ExecutionFailed,
        },
        proposal: (*sccp.proposal).clone(),
        admissible: super::super::governance::preflight_attempt_in(world, &sccp.proposal).is_ok(),
        latest_attempt,
    })
}

// ---------------------------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------------------------

/// Move-only history view retaining the original positional-path allocation.
/// The integrating caller separately retains its request lease and encoded response backing.
pub struct RetainedSccpHistoryView {
    view: SccpHistoryPathViewV1,
    _path: AllocationCharge,
}
impl RetainedSccpHistoryView {
    /// Borrow the complete canonical view without copying its path.
    #[must_use]
    pub fn view(&self) -> &SccpHistoryPathViewV1 {
        &self.view
    }
}

/// Assemble a history view through an explicitly retained, funded durable cache.
/// `size` defaults to the captured World size; source peaks remain independently checked.
///
/// # Errors
/// Refuses absent commitments, invalid indices/sizes, inconsistent stored history and exact
/// original resource failure. Both complete pool admissions precede cache mutation.
#[allow(
    unsafe_code,
    reason = "the path Vec and original charge move immediately into a closed body-before-charge owner"
)]
pub fn history_path_view(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    size: Option<u64>,
    cache: &mut SccpHistoryNodeCache,
    cache_budget: &AllocationBudget,
    request_budget: &AllocationBudget,
) -> Result<RetainedSccpHistoryView, SccpHistoryReadError> {
    let size = size.unwrap_or_else(|| store::history::get(world).size);
    let commitment = store::block_commitments::get(world, &height)
        .ok_or(SccpHistoryReadError::MissingCommitment)?;
    let expected =
        iroha_sccp::v1::hashes::history_leaf(height, &commitment.root, commitment.message_count);
    if store::history_leaves::get(world, &commitment.history_index) != Some(&(height, expected)) {
        return Err(SccpHistoryReadError::Inconsistent);
    }
    let acquired = cache.root_and_path(
        world,
        commitment.history_index,
        size,
        cache_budget,
        request_budget,
    )?;
    iroha_sccp::v1::history::verify_history_inclusion(
        &expected,
        commitment.history_index,
        size,
        acquired.path(),
        &acquired.root(),
    )
    .map_err(|_| SccpHistoryReadError::Inconsistent)?;
    let history_root = acquired.root();
    // SAFETY: no fallible operation separates the exact graph and its retained charge.
    let (history_path, charge) = unsafe { acquired.into_buffer().into_allocation_parts() };
    Ok(RetainedSccpHistoryView {
        view: SccpHistoryPathViewV1 {
            history_size: size,
            history_root,
            proof: SccpBlockRefV1 {
                height,
                sccp_root: commitment.root,
                message_count: commitment.message_count,
                history_index: commitment.history_index,
                history_path,
            },
        },
        _path: charge,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::{
            commitment,
            test_support::{authority, blank_state, header, sample_proposal, sample_route},
        },
        state::StateTransaction,
    };
    use iroha_data_model::sccp::{
        control::{SccpControlLeafRefV1, SccpControlRecordV1, SccpTransferLeafRefV1},
        inbound::{
            SccpBounceStatusV1, SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1,
            SccpSourceLocatorV1,
        },
        light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::{SccpOutboundStatusV1, SccpStatusHeightV1, SccpVoidKindV1, SccpVoidStatusV1},
    };
    use iroha_sccp::v1::history::{history_path, history_root, verify_history_inclusion};

    const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
    const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;

    fn route_with_nonces(stx: &mut StateTransaction<'_, '_>, network: SccpNetworkV1, next: u64) {
        let mut route = sample_route(network);
        let revision = route.revisions.get_mut(&1).expect("revision 1");
        revision.next_outbound_nonce = next;
        revision.next_control_nonce = next + 1;
        store::routes::insert(stx, network, route).expect("route");
    }

    /// Record outbound `nonce` of `network` at leaf `(height, index)`.
    fn outbound(
        stx: &mut StateTransaction<'_, '_>,
        network: SccpNetworkV1,
        nonce: u64,
        height: u64,
        index: u32,
    ) -> [u8; 32] {
        let message_id = [u8::try_from(nonce + 1).expect("small nonce"); 32];
        store::block_leaves::insert(
            stx,
            (height, index),
            SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
        )
        .expect("leaf");
        store::outbound_messages::insert(
            stx,
            message_id,
            SccpOutboundMessageRecordV1 {
                network,
                revision: 1,
                nonce,
                height,
                commitment_index: index,
                deadline_ms: 1_000 + nonce,
                sender: authority(1),
                amount: 5,
                payload: vec![1, 2, 3],
                leaf: [0xaa; 32],
                status: SccpOutboundStatusV1::Recorded,
            },
        )
        .expect("record");
        store::outbound_by_nonce::insert(stx, (network, 1, nonce), message_id).expect("nonce");
        message_id
    }

    fn inbound(stx: &mut StateTransaction<'_, '_>, seed: u8, network: SccpNetworkV1, height: u64) {
        store::inbound_messages::insert(
            stx,
            [seed; 32],
            SccpInboundRecordV1 {
                network,
                revision: 1,
                payload: vec![seed],
                source_locator: SccpSourceLocatorV1 {
                    source_height: 7,
                    block_hash: [seed; 32],
                    index_in_block: 0,
                },
                proven_at_height: height,
                fee_due: 0,
                status: SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
            },
        )
        .expect("inbound");
    }

    #[test]
    fn directions_parse() {
        assert_eq!(
            SccpDirectionV1::parse("outbound"),
            Some(SccpDirectionV1::Outbound)
        );
        assert_eq!(
            SccpDirectionV1::parse("inbound"),
            Some(SccpDirectionV1::Inbound)
        );
        assert_eq!(SccpDirectionV1::parse("both"), None);
    }

    #[test]
    fn message_status_covers_outbound_inbound_and_unknown_ids() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        let world = &*stx.world;
        assert_eq!(
            message_status(world, &[9; 32]),
            SccpMessageStatusV1::Unknown
        );
        let id = outbound(&mut stx, ETH, 0, 10, 0);
        let status = message_status(&*stx.world, &id);
        assert_eq!(
            status.outbound().map(|view| view.state),
            Some(SccpOutboundStateV1::Recorded(SccpRecordedStateV1 {
                deadline_ms: 1_000
            }))
        );
        // Voided and refunded records report their stored state.
        let mut record = store::outbound_messages::get(&*stx.world, &id)
            .expect("record")
            .clone();
        let void = SccpVoidStatusV1 {
            kind: SccpVoidKindV1::Expired,
            proven_at_height: 20,
            refund_pending: Some(iroha_data_model::sccp::inbound::SccpPendingReasonV1::RefundDeferred),
        };
        record.status = SccpOutboundStatusV1::Voided(void);
        store::outbound_messages::insert(&mut stx, id, record.clone()).expect("void");
        let status = message_status(&*stx.world, &id);
        assert_eq!(
            status.outbound().map(|view| view.state),
            Some(SccpOutboundStateV1::Voided(void))
        );
        assert!(!status.is_final());
        record.status = SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height: 21 });
        store::outbound_messages::insert(&mut stx, id, record).expect("refund");
        assert!(message_status(&*stx.world, &id).is_final());
        // Inbound ids report the inbound record and its status.
        inbound(&mut stx, 0x44, BSC, 30);
        let status = message_status(&*stx.world, &[0x44; 32]);
        let view = status.inbound().expect("inbound");
        assert_eq!(
            view.record.status,
            SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled)
        );
        assert!(!status.is_final());
        let mut bounced = view.record.clone();
        bounced.status = SccpInboundStatusV1::Bounced(SccpBounceStatusV1 {
            bounce_message_id: [0x45; 32],
            payout: 1,
        });
        store::inbound_messages::insert(&mut stx, [0x44; 32], bounced).expect("bounce");
        assert!(message_status(&*stx.world, &[0x44; 32]).is_final());
    }

    #[test]
    fn outbound_pages_follow_nonces() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        assert!(matches!(
            outbound_page(&*stx.world, ETH, 1, 0, 10),
            Err(SccpReadError::NotFound(_))
        ));
        route_with_nonces(&mut stx, ETH, 5);
        for nonce in 0..5 {
            outbound(&mut stx, ETH, nonce, 10 + nonce, 0);
        }
        let first = outbound_page(&*stx.world, ETH, 1, 0, 2).expect("page");
        assert_eq!(first.next_outbound_nonce, 5);
        assert_eq!(
            first
                .records
                .iter()
                .map(|view| view.record.nonce)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(first.next_from_nonce, Some(2));
        let last = outbound_page(&*stx.world, ETH, 1, 4, 2).expect("page");
        assert_eq!(last.records.len(), 1);
        assert_eq!(last.next_from_nonce, None);
        assert!(
            outbound_page(&*stx.world, ETH, 1, 9, 2)
                .expect("page")
                .records
                .is_empty()
        );
        assert!(matches!(
            outbound_page(&*stx.world, ETH, 2, 0, 2),
            Err(SccpReadError::NotFound(_))
        ));
    }

    #[test]
    fn recent_outbound_pages_newest_first_and_skip_controls() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        outbound(&mut stx, ETH, 0, 10, 0);
        outbound(&mut stx, BSC, 1, 10, 1);
        store::block_leaves::insert(
            &mut stx,
            (10, 2),
            SccpLeafRefV1::Control(SccpControlLeafRefV1 {
                network: ETH,
                revision: 1,
                control_nonce: 1,
            }),
        )
        .expect("control leaf");
        outbound(&mut stx, ETH, 2, 11, 0);
        let nonces = |page: &SccpRecentMessagesV1| {
            page.messages
                .iter()
                .map(|status| status.outbound().expect("outbound").record.nonce)
                .collect::<Vec<_>>()
        };
        let world = &*stx.world;
        let all = recent_messages(world, SccpDirectionV1::Outbound, None, None, 50).expect("all");
        assert_eq!(nonces(&all), vec![2, 1, 0]);
        assert_eq!(all.next_before, None);
        let first = recent_messages(world, SccpDirectionV1::Outbound, None, None, 2).expect("page");
        assert_eq!(nonces(&first), vec![2, 1]);
        let cursor = first.next_before.expect("more");
        let second = recent_messages(world, SccpDirectionV1::Outbound, None, Some(&cursor), 2)
            .expect("page");
        assert_eq!(nonces(&second), vec![0]);
        let eth =
            recent_messages(world, SccpDirectionV1::Outbound, Some(ETH), None, 50).expect("eth");
        assert_eq!(nonces(&eth), vec![2, 0]);
        for bad in ["10", "x:1", "10:y"] {
            assert!(matches!(
                recent_messages(world, SccpDirectionV1::Outbound, None, Some(bad), 2),
                Err(SccpReadError::Invalid(_))
            ));
        }
    }

    #[test]
    fn recent_inbound_pages_newest_first() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        inbound(&mut stx, 1, ETH, 10);
        inbound(&mut stx, 2, BSC, 12);
        inbound(&mut stx, 3, ETH, 12);
        let ids = |page: &SccpRecentMessagesV1| {
            page.messages
                .iter()
                .map(|status| status.inbound().expect("inbound").message_id[0])
                .collect::<Vec<_>>()
        };
        let world = &*stx.world;
        let first = recent_messages(world, SccpDirectionV1::Inbound, None, None, 2).expect("page");
        assert_eq!(ids(&first), vec![3, 2]);
        let cursor = first.next_before.expect("more");
        assert_eq!(cursor, format!("12:{}", hex::encode([2_u8; 32])));
        let second =
            recent_messages(world, SccpDirectionV1::Inbound, None, Some(&cursor), 2).expect("page");
        assert_eq!(ids(&second), vec![1]);
        assert_eq!(second.next_before, None);
        let eth =
            recent_messages(world, SccpDirectionV1::Inbound, Some(ETH), None, 50).expect("eth");
        assert_eq!(ids(&eth), vec![3, 1]);
        assert!(matches!(
            recent_messages(world, SccpDirectionV1::Inbound, None, Some("12:abcd"), 2),
            Err(SccpReadError::Invalid(_))
        ));
    }

    #[test]
    fn control_pages_follow_nonces() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        assert!(matches!(
            controls_page(&*stx.world, ETH, 1, 0, 10),
            Err(SccpReadError::NotFound(_))
        ));
        route_with_nonces(&mut stx, ETH, 3);
        for (nonce, height) in [(1_u64, 10_u64), (2, 11), (3, 12)] {
            store::control_messages::insert(
                &mut stx,
                (ETH, 1, nonce),
                SccpControlRecordV1 {
                    track: 1,
                    parliament_paused: nonce % 2 == 1,
                    fast_pause_until_ms: 0,
                    height,
                    commitment_index: 0,
                    leaf: [1; 32],
                    certificate_id: [2; 32],
                    effect_hash: [5; 32],
                },
            )
            .expect("control");
        }
        let page = controls_page(&*stx.world, ETH, 1, 0, 2).expect("page");
        assert_eq!(page.next_control_nonce, 4);
        assert_eq!(page.next_after_nonce, Some(2));
        assert_eq!(
            page.controls
                .iter()
                .map(|view| (
                    view.control_nonce,
                    view.record.parliament_paused,
                    view.record.height
                ))
                .collect::<Vec<_>>(),
            vec![(1, true, 10), (2, false, 11)]
        );
        let rest = controls_page(&*stx.world, ETH, 1, 2, 2).expect("page");
        assert_eq!(rest.controls.len(), 1);
        assert_eq!(rest.controls[0].control_nonce, 3);
        assert_eq!(rest.next_after_nonce, None);
        assert!(
            controls_page(&*stx.world, ETH, 1, u64::MAX, 2)
                .expect("page")
                .controls
                .is_empty(),
            "nothing lies above the largest nonce"
        );
    }

    fn light_client(head: u64) -> SccpLightClientV1 {
        SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(ETH).expect("external"),
            head: SccpLcHeadV1 {
                latest_set_id: 2,
                latest_finalized: SccpLcPointV1 {
                    source_height: head,
                    block_hash: [7; 32],
                    source_time_ms: 1,
                },
                last_progress_taira_ms: 1,
            },
            frozen: None,
            state_hash: [8; 32],
        }
    }

    fn checkpoint(
        stx: &mut StateTransaction<'_, '_>,
        height: u64,
        origin: SccpLcCheckpointOriginV1,
    ) {
        crate::smartcontracts::isi::sccp::light_clients::record_checkpoint(
            stx,
            ETH,
            SccpLcCheckpointV1 {
                data: SccpLcCheckpointDataV1 {
                    source_height: height,
                    block_hash: [1; 32],
                    state_root: Some([2; 32]),
                    receipts_or_tx_root: [3; 32],
                    source_time_ms: height,
                },
                recorded_at_taira_ms: 0,
                origin,
            },
        )
        .expect("checkpoint");
    }

    #[test]
    fn checkpoint_covers_pick_the_nearest_retained_and_permanent_anchors() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        assert!(matches!(
            checkpoint_cover(&*stx.world, ETH, 1),
            Err(SccpReadError::NotFound(_))
        ));
        let stride = SccpLightClientParamsV1::defaults_for(ETH)
            .expect("external")
            .checkpoint_stride;
        store::light_clients::insert(&mut stx, ETH, light_client(3 * stride)).expect("lc");
        // Head covers everything below it, but nothing is retained yet.
        assert!(matches!(
            checkpoint_cover(&*stx.world, ETH, 5),
            Err(SccpReadError::Pruned(_))
        ));
        // Bucket 1 keeps `stride + 10` (its lowest); `stride + 20` is prunable; bucket 2 keeps
        // `2 * stride + 5`.
        checkpoint(&mut stx, stride + 10, SccpLcCheckpointOriginV1::Advance);
        checkpoint(&mut stx, stride + 20, SccpLcCheckpointOriginV1::Proof);
        checkpoint(&mut stx, 2 * stride + 5, SccpLcCheckpointOriginV1::Advance);
        let world = &*stx.world;
        let exact = checkpoint_cover(world, ETH, stride + 10).expect("exact");
        assert_eq!(exact.nearest.checkpoint.data.source_height, stride + 10);
        assert!(exact.nearest.permanent);
        assert_eq!(exact.nearest_permanent, Some(exact.nearest));
        let between = checkpoint_cover(world, ETH, stride + 11).expect("between");
        assert_eq!(between.nearest.checkpoint.data.source_height, stride + 20);
        assert!(!between.nearest.permanent);
        assert_eq!(
            between
                .nearest_permanent
                .map(|entry| entry.checkpoint.data.source_height),
            Some(2 * stride + 5)
        );
        assert_eq!(between.head.source_height, 3 * stride);
        // Above every checkpoint but below the head: pruned; above the head: not yet final.
        assert!(matches!(
            checkpoint_cover(world, ETH, 2 * stride + 6),
            Err(SccpReadError::Pruned(_))
        ));
        assert!(matches!(
            checkpoint_cover(world, ETH, 3 * stride + 1),
            Err(SccpReadError::NotFound(_))
        ));
        // More prunable checkpoints than one scan reads lie between the nearest one and the next
        // bucket's lowest: the stride index still names it.
        let run = u64::try_from(MAX_CHECKPOINT_SCAN).expect("small") + 10;
        for offset in 0..run {
            checkpoint(
                &mut stx,
                stride + 30 + offset,
                SccpLcCheckpointOriginV1::Proof,
            );
        }
        let permanent_height = |cover: SccpLcCheckpointCoverV1| {
            assert!(!cover.nearest.permanent);
            cover
                .nearest_permanent
                .map(|entry| entry.checkpoint.data.source_height)
        };
        let far = checkpoint_cover(&*stx.world, ETH, stride + 21).expect("far");
        assert_eq!(far.nearest.checkpoint.data.source_height, stride + 30);
        assert_eq!(permanent_height(far), Some(2 * stride + 5));
        // A Parliament-installed checkpoint below it is nearer and wins.
        checkpoint(&mut stx, stride + 40, SccpLcCheckpointOriginV1::Parliament);
        assert_eq!(
            permanent_height(checkpoint_cover(&*stx.world, ETH, stride + 21).expect("installed")),
            Some(stride + 40)
        );
    }

    #[test]
    fn light_client_details_summarise_stored_data() {
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        assert!(matches!(
            light_client_detail(&stx, ETH),
            Err(SccpReadError::NotFound(_))
        ));
        store::light_clients::insert(&mut stx, ETH, light_client(100_000)).expect("lc");
        checkpoint(&mut stx, 9_000, SccpLcCheckpointOriginV1::Advance);
        checkpoint(&mut stx, 9_100, SccpLcCheckpointOriginV1::Parliament);
        let detail = light_client_detail(&stx, ETH).expect("detail");
        assert_eq!(
            detail.light_client.head.latest_finalized.source_height,
            100_000
        );
        assert_eq!(detail.checkpoints.count, 2);
        assert_eq!(detail.checkpoints.lowest_source_height, Some(9_000));
        assert_eq!(detail.checkpoints.highest_source_height, Some(9_100));
        assert_eq!(detail.checkpoints.permanent_buckets, 1);
        assert_eq!(detail.sets.count, 0);
        // Without activations the genesis version (1) is active at the next block.
        assert!(detail.supported_until_ms.is_some());
        assert_eq!(
            detail.supported_until_ms,
            SccpChainProfilesV1::genesis().supported_until_ms(ETH)
        );
        assert_eq!(
            compiled_profiles()
                .iter()
                .map(|profile| profile.network)
                .collect::<Vec<_>>(),
            [ETH, SccpNetworkV1::BscMainnet, SccpNetworkV1::TonMainnet]
        );
        assert_eq!(compiled_supported_until_ms(SccpNetworkV1::SoraTaira), None);
        // Once the next block runs a version this release does not compile, the light client is
        // neither usable nor bounded here.
        store::light_client_profiles::insert(
            &mut stx,
            (ETH, 2),
            iroha_data_model::sccp::light_client::SccpLcProfileActivationV1 {
                profile_hash: [9; 32],
                activation_height: 0,
                proposal_id: [8; 32],
            },
        )
        .expect("activation");
        let uncompiled = light_client_detail(&stx, ETH).expect("detail");
        assert!(!uncompiled.usable);
        assert_eq!(uncompiled.weak_subjectivity_deadline_ms, None);
        assert_eq!(uncompiled.supported_until_ms, None);
    }

    #[test]
    fn governance_proposals_are_shown_in_any_phase() {
        use crate::state::{GovernanceProposalRecord, GovernanceProposalStatus};
        use iroha_data_model::governance::types::{ProposalKind, SccpRouteGovernanceProposal};
        let state = blank_state();
        let mut block = state.block(header(40));
        let mut stx = block.transaction();
        assert!(matches!(
            governance_proposal(&*stx.world, [1; 32]),
            Err(SccpReadError::NotFound(_))
        ));
        let proposal = sample_proposal(stx.network_id);
        stx.world.governance_proposals.insert(
            [1; 32],
            GovernanceProposalRecord {
                proposer: authority(3),
                kind: ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
                    proposal: Box::new(proposal.clone()),
                }),
                created_height: 7,
                status: GovernanceProposalStatus::Enacted,
            },
        );
        let detail = governance_proposal(&*stx.world, [1; 32]).expect("detail");
        assert_eq!(detail.phase, SccpGovernanceProposalPhaseV1::Enacted);
        assert_eq!(detail.proposal, proposal);
        assert_eq!(detail.proposer, authority(3));
        assert_eq!(detail.created_height, 7);
        assert_eq!(detail.latest_attempt, None);
    }

    #[test]
    fn history_paths_verify_against_their_roots() {
        let state = blank_state();
        let mut leaves = Vec::new();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        for height in 1..=40_u64 {
            let message_id = [u8::try_from(height).expect("small"); 32];
            store::block_leaves::insert(
                &mut stx,
                (height, 0),
                SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
            )
            .expect("leaf");
            store::outbound_messages::insert(
                &mut stx,
                message_id,
                SccpOutboundMessageRecordV1 {
                    network: ETH,
                    revision: 1,
                    nonce: height,
                    height,
                    commitment_index: 0,
                    deadline_ms: 1,
                    sender: authority(1),
                    amount: 1,
                    payload: vec![1],
                    leaf: [u8::try_from(height).expect("small"); 32],
                    status: SccpOutboundStatusV1::Recorded,
                },
            )
            .expect("record");
            commitment::commit_block(&mut stx, height)
                .expect("commit")
                .expect("commitment");
            let index = height - 1;
            leaves.push(
                store::history_leaves::get(&*stx.world, &index)
                    .expect("leaf")
                    .1,
            );
        }
        let world = &*stx.world;
        let pool = state.ivm_execution_budget();
        let mut cache = SccpHistoryNodeCache::new();
        assert!(matches!(
            history_path_view(world, 41, None, &mut cache, &pool, &pool),
            Err(SccpHistoryReadError::MissingCommitment)
        ));
        let retained =
            history_path_view(world, 7, None, &mut cache, &pool, &pool).expect("current size");
        let view = retained.view();
        assert_eq!(view.history_size, 40);
        assert_eq!(view.history_root, history_root(&leaves).expect("root"));
        assert_eq!(
            view.proof.history_path,
            history_path(&leaves, 6).expect("path")
        );
        let retained_older =
            history_path_view(world, 7, Some(33), &mut cache, &pool, &pool).expect("older size");
        let older = retained_older.view();
        verify_history_inclusion(
            &leaves[6],
            6,
            33,
            &older.proof.history_path,
            &history_root(&leaves[..33]).expect("root"),
        )
        .expect("inclusion");
        assert!(matches!(
            history_path_view(world, 7, Some(6), &mut cache, &pool, &pool),
            Err(SccpHistoryReadError::IndexOutOfRange)
        ));
        assert!(matches!(
            history_path_view(world, 7, Some(41), &mut cache, &pool, &pool),
            Err(SccpHistoryReadError::SizeOutOfRange)
        ));
    }
}
