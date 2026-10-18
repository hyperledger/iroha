//! Native standing-panel acceptance, public endorsements and emergency hold transitions.
//!
//! The Parliament seam owns citizen eligibility, boundary draws and Policy Jury anchors.
//! Missing external authority refuses; component prestate is never promoted to authority.

use super::{
    Error, parliament_iface,
    pause_record::{
        FastPauseRoundDraft, PausePanelBody, PausePanelDraft, PauseRecordError,
        RetainedSccpFastPauseRound, RetainedSccpPausePanel,
    },
    store,
};
use crate::state::sccp_pause_entrypoint::PauseOperation;
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::sccp::{AcceptSccpPausePanelSeatV1, EndorseSccpFastPauseV1},
    sccp::{
        events::{
            SccpEvent, SccpFastPauseEndorsedV1, SccpFastPauseNoResultReasonV1 as NoResult,
            SccpPausePanelSeatAcceptedV1,
        },
        fast_pause::{SccpFastPauseEndorsementV1, SccpPanelRoleV1},
        governance::SccpGovernanceSubjectV1,
        params::SccpParametersV1,
        registry::SccpRouteActivationV1,
    },
    transaction::{Executable, TransactionPayload},
};

pub(super) mod certification;
pub(crate) mod draw;

const MAX_DRAW: usize = 27;
const MAX_SEATS: usize = 18;
fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP fast pause: {reason}").into())
}

/// Original local graph failures poison the enclosing carrier, never a replicated NoResult.
fn construction_error(state: &mut StateTransaction<'_, '_>, error: PauseRecordError) -> Error {
    use crate::state::{
        EvidencePreparationError as Preparation, StateStorageAdmissionError as Storage,
    };
    let local = match &error {
        PauseRecordError::Admission(original) => Some(Preparation::Admission(original.clone())),
        PauseRecordError::Allocator { bytes } => Some(Preparation::Allocator {
            requested_bytes: *bytes,
        }),
        PauseRecordError::Account(error) => error.local_refusal().map(Preparation::DecodeResource),
        PauseRecordError::Invalid(_) => None,
    };
    if let Some(local) = local {
        state.arm_local_storage_refusal(Storage::SccpEvidence(local));
        refuse("original pause graph admission did not complete")
    } else {
        refuse(error)
    }
}

/// Current seats are fixed-size indices into the original immutable draw.
/// Accepted originals retain their seat even if currently ineligible; only unaccepted
/// originals participate in the primary-then-backup reserve replacement walk.
fn seats(
    panel: &PausePanelBody,
    k: usize,
    time: u64,
    eligible: u32,
) -> Result<[usize; MAX_SEATS], Error> {
    if !matches!(k, 5 | 7 | 9) || !(2 * k..=3 * k).contains(&panel.drawn.len()) {
        return Err(refuse("invalid panel size"));
    }
    let mut owners = [0; MAX_SEATS];
    let mut reserve = 2 * k;
    for (index, owner) in owners[..2 * k].iter_mut().enumerate() {
        *owner = index;
        if (time < panel.accept_until_ms && !cfg!(all(test, sumeragi_core_mutation = "HC295")))
            || panel.accepted.binary_search(&panel.drawn[index]).is_ok()
        {
            continue;
        }
        while reserve < panel.drawn.len() {
            let next = reserve;
            reserve += 1;
            if eligible & (1 << next) != 0
                && panel.accepted.binary_search(&panel.drawn[next]).is_ok()
            {
                *owner = next;
                break;
            }
        }
    }
    Ok(owners)
}
fn role_of(panel: &PausePanelBody, id: &[u8; 32]) -> Option<SccpPanelRoleV1> {
    if id == &panel.primary_id {
        Some(SccpPanelRoleV1::Primary)
    } else if id == &panel.backup_id {
        Some(SccpPanelRoleV1::Backup)
    } else {
        None
    }
}
fn role_range(role: SccpPanelRoleV1, k: usize) -> core::ops::Range<usize> {
    match role {
        SccpPanelRoleV1::Primary => 0..k,
        SccpPanelRoleV1::Backup => k..2 * k,
    }
}
fn counts(
    panel: &PausePanelBody,
    owners: &[usize; MAX_SEATS],
    role: SccpPanelRoleV1,
    k: usize,
    eligible: u32,
    account: &AccountId,
) -> bool {
    role_range(role, k).any(|seat| {
        let index = owners[seat];
        eligible & (1 << index) != 0 && &panel.drawn[index] == account
    })
}
fn conditions(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    head: u64,
    time: u64,
    parameters: &SccpParametersV1,
) -> Result<(), NoResult> {
    if !store::routes::get(world, &network).is_some_and(|route| {
        route.revisions.values().any(|revision| {
            matches!(
                revision.activation,
                SccpRouteActivationV1::Bidirectional
                    | SccpRouteActivationV1::Paused
                    | SccpRouteActivationV1::InboundOnly
            )
        })
    }) {
        return Err(NoResult::NoLiveRevision);
    }
    if store::governance_revision(world, &SccpGovernanceSubjectV1::FastHold(network)) != head {
        return Err(NoResult::HeadChanged);
    }
    if store::fast_pause_suspended_until_ms::get(world, &network).is_some_and(|until| time < *until)
    {
        return Err(NoResult::Suspended);
    }
    if store::fast_pauses::get(world, &network).is_some_and(|pause| {
        time < pause
            .until_ms
            .saturating_sub(parameters.fast_pause_renew_lead_ms)
    }) {
        return Err(NoResult::RenewalWindowClosed);
    }
    Ok(())
}
fn check_accept(
    world: &(impl WorldReadOnly + ?Sized),
    authority: &AccountId,
    sequence: u64,
) -> Result<(), Error> {
    if store::parameters::get(world).is_none() {
        return Err(refuse("SCCP is absent"));
    }
    let panel = store::pause_panel::get(world)
        .as_ref()
        .ok_or_else(|| refuse("no standing panel"))?;
    if panel.panel_seq != sequence || !panel.drawn.contains(authority) {
        return Err(refuse("authority is not drawn in this panel"));
    }
    if panel.accepted.binary_search(authority).is_ok() {
        return Err(refuse("seat acceptance is already recorded"));
    }
    Ok(())
}
fn check_endorse(
    world: &(impl WorldReadOnly + ?Sized),
    network_id: NetworkId,
    authority: &AccountId,
    instruction: &EndorseSccpFastPauseV1,
    time: u64,
) -> Result<(SccpPanelRoleV1, u32), Error> {
    if instruction.network_id != network_id || instruction.incident_digest == [0; 32] {
        return Err(refuse("wrong chain or zero incident"));
    }
    let parameters = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP is absent"))?;
    conditions(
        world,
        instruction.network,
        instruction.head,
        time,
        parameters,
    )
    .map_err(|reason| refuse(format_args!("{reason:?}")))?;
    let panel = store::pause_panel::get(world)
        .as_ref()
        .ok_or_else(|| refuse("no standing panel"))?;
    let role =
        role_of(panel, &instruction.panel_id).ok_or_else(|| refuse("panel identity changed"))?;
    let observation = parliament_iface::pause_eligibility(world, panel, time)?;
    let eligible = observation.for_original(world, panel, time)?;
    check_current_endorsement(world, authority, instruction, time, panel, role, eligible)?;
    Ok((role, eligible))
}

/// Check the member and duplicate facts after obtaining the original eligibility observation.
fn check_current_endorsement(
    world: &(impl WorldReadOnly + ?Sized),
    authority: &AccountId,
    instruction: &EndorseSccpFastPauseV1,
    time: u64,
    panel: &PausePanelBody,
    role: SccpPanelRoleV1,
    eligible: u32,
) -> Result<(), Error> {
    let parameters = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP is absent"))?;
    let k = parameters.fast_pause_panel_seats as usize;
    let owners = seats(panel, k, time, eligible)?;
    if !counts(panel, &owners, role, k, eligible, authority) {
        return Err(refuse("authority is not a currently eligible seat holder"));
    }
    if store::fast_pause_rounds::get(world, &(instruction.network, role)).is_some_and(|round| {
        round.panel_id == instruction.panel_id
            && round.head == instruction.head
            && time < round.closes_at_ms
            && round
                .endorsers
                .binary_search_by(|(account, _)| account.cmp(authority))
                .is_ok()
    }) {
        return Err(refuse("duplicate endorsement"));
    }
    Ok(())
}

/// Recheck direct signed public panel instructions before ordinary queue fee admission.
/// # Errors
/// Refuses stale state, invalid membership, and unavailable external eligibility.
pub(crate) fn admit(
    world: &(impl WorldReadOnly + ?Sized),
    network: NetworkId,
    payload: &TransactionPayload,
    time: Option<u64>,
) -> Result<(), Error> {
    let Executable::Instructions(instructions) = &payload.instructions else {
        return Ok(());
    };
    for instruction in instructions.iter() {
        if let Some(accept) = instruction
            .as_any()
            .downcast_ref::<AcceptSccpPausePanelSeatV1>()
        {
            check_accept(world, &payload.authority, accept.panel_seq)?;
        }
        if let Some(endorse) = instruction
            .as_any()
            .downcast_ref::<EndorseSccpFastPauseV1>()
        {
            check_endorse(
                world,
                network,
                &payload.authority,
                endorse,
                time.ok_or_else(|| refuse("original committed time is unavailable"))?,
            )?;
        }
    }
    Ok(())
}

fn accepted_panel(
    panel: &RetainedSccpPausePanel,
    authority: &AccountId,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<RetainedSccpPausePanel, PauseRecordError> {
    if panel.accepted.binary_search(authority).is_ok() {
        return Ok(panel.clone());
    }
    let mut drawn = [authority; MAX_DRAW];
    let mut accepted = [authority; MAX_DRAW];
    if panel.drawn.len() > MAX_DRAW || panel.accepted.len() >= MAX_DRAW {
        return Err(PauseRecordError::Invalid("panel draw capacity"));
    }
    for (index, member) in panel.drawn.iter().enumerate() {
        drawn[index] = member;
    }
    for (index, member) in panel.accepted.iter().enumerate() {
        accepted[index] = member;
    }
    accepted[panel.accepted.len()] = authority;
    let count = panel.accepted.len() + 1;
    accepted[..count].sort_unstable();
    RetainedSccpPausePanel::admit_draft(
        &PausePanelDraft {
            panel_seq: panel.panel_seq,
            pulse_id: panel.pulse_id,
            seated_height: panel.seated_height,
            seated_at_ms: panel.seated_at_ms,
            accept_until_ms: panel.accept_until_ms,
            term_ends_at_ms: panel.term_ends_at_ms,
            drawn: &drawn[..panel.drawn.len()],
            accepted: &accepted[..count],
            primary_id: panel.primary_id,
            backup_id: panel.backup_id,
        },
        budget,
    )
}

/// Execute the exact signed acceptance once; it grants no eligibility or pause authority.
pub(super) fn execute_accept(
    instruction: AcceptSccpPausePanelSeatV1,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    state.consume_direct_sccp_pause(PauseOperation::Accept(instruction))?;
    check_accept(&*state.world, authority, instruction.panel_seq)?;
    let original = store::pause_panel::get(&*state.world)
        .as_ref()
        .ok_or_else(|| refuse("no standing panel"))?
        .clone();
    let next = accepted_panel(
        &original,
        authority,
        state.sccp_evidence_preparation_budget(),
    )
    .map_err(|error| construction_error(state, error))?;
    // Public events use the existing shared World sink; panel retention has its
    // own original-pool ownership established above.
    let event = SccpEvent::PausePanelSeatAccepted(SccpPausePanelSeatAcceptedV1 {
        panel_seq: instruction.panel_seq,
        member: authority.clone(),
    });
    store::pause_panel::set(state, Some(next));
    state.world.emit_events(Some(event));
    Ok(())
}

/// Record a current seat holder's exact chain/head-bound public endorsement.
pub(super) fn execute_endorse(
    instruction: EndorseSccpFastPauseV1,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    state.consume_direct_sccp_pause(PauseOperation::Endorse(instruction))?;
    let time = state.block_unix_timestamp_ms();
    let (role, eligible) = check_endorse(
        &*state.world,
        *state.network_id(),
        authority,
        &instruction,
        time,
    )?;
    let parameters = *store::parameters::get(&*state.world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP is absent"))?;
    let original = store::pause_panel::get(&*state.world)
        .as_ref()
        .ok_or_else(|| refuse("no standing panel"))?
        .clone();
    let panel = accepted_panel(
        &original,
        authority,
        state.sccp_evidence_preparation_budget(),
    )
    .map_err(|error| construction_error(state, error))?;
    let prior = store::fast_pause_rounds::get(&*state.world, &(instruction.network, role))
        .filter(|round| {
            round.panel_id == instruction.panel_id
                && round.head == instruction.head
                && time < round.closes_at_ms
        })
        .cloned();
    let fact = SccpFastPauseEndorsementV1 {
        incident_digest: instruction.incident_digest,
        recorded_at_height: state._curr_block.height().get(),
    };
    let mut entries = [(authority, fact); MAX_DRAW];
    let previous = prior
        .as_ref()
        .map_or(&[][..], |round| round.endorsers.as_slice());
    if previous.len() >= MAX_DRAW {
        return Err(refuse("endorsement capacity exhausted"));
    }
    for (index, (member, fact)) in previous.iter().enumerate() {
        entries[index] = (member, *fact);
    }
    entries[previous.len()] = (authority, fact);
    let entries = &mut entries[..=previous.len()];
    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let k = parameters.fast_pause_panel_seats as usize;
    let owners = seats(&panel, k, time, eligible)?;
    let count = u32::try_from(
        entries
            .iter()
            .filter(|(member, _)| counts(&panel, &owners, role, k, eligible, member))
            .count(),
    )
    .map_err(|_| refuse("endorsement count exceeds u32"))?;
    let opened = prior.as_ref().map_or(time, |round| round.opened_at_ms);
    let closes = prior
        .as_ref()
        .map(|round| round.closes_at_ms)
        .or_else(|| time.checked_add(parameters.fast_pause_endorse_window_ms))
        .ok_or_else(|| refuse("round deadline exhausted"))?;
    let next = RetainedSccpFastPauseRound::admit_draft(
        &FastPauseRoundDraft {
            panel_id: instruction.panel_id,
            panel_seq: panel.panel_seq,
            head: instruction.head,
            opened_at_ms: opened,
            closes_at_ms: closes,
            endorsers: entries,
            certify_due: prior.as_ref().is_some_and(|round| round.certify_due)
                || count >= parameters.fast_pause_panel_quorum(),
        },
        state.sccp_evidence_preparation_budget(),
    )
    .map_err(|error| construction_error(state, error))?;
    let event = SccpEvent::FastPauseEndorsed(SccpFastPauseEndorsedV1 {
        network: instruction.network,
        panel_id: instruction.panel_id,
        endorser: authority.clone(),
        incident_digest: instruction.incident_digest,
        count,
    });
    store::pause_panel::set(state, Some(panel));
    store::fast_pause_rounds::insert(state, (instruction.network, role), next)?;
    state.world.emit_events(Some(event));
    Ok(())
}

/// A Parliament duration suspends future decisions, without clearing any active hold.
pub(super) fn suspend(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    duration: u64,
) -> Result<(), Error> {
    if cfg!(all(test, sumeragi_core_mutation = "HC299")) {
        store::fast_pauses::remove(state, network);
    }
    if !network.is_external()
        || duration > 3 * iroha_data_model::sccp::params::SCCP_MAX_FAST_PAUSE_MS_V1
    {
        return Err(refuse("invalid suspension duration or network"));
    }
    if duration == 0 {
        store::fast_pause_suspended_until_ms::remove(state, network);
    } else {
        let until = state
            .block_unix_timestamp_ms()
            .checked_add(duration)
            .ok_or_else(|| refuse("suspension deadline exhausted"))?;
        store::fast_pause_suspended_until_ms::insert(state, network, until)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn holds_part(
    pause: &iroha_data_model::sccp::fast_pause::SccpFastPauseV1,
    part: iroha_data_model::sccp::events::SccpFastPausePartV1,
) -> bool {
    match part {
        iroha_data_model::sccp::events::SccpFastPausePartV1::Taira => pause.taira,
        iroha_data_model::sccp::events::SccpFastPausePartV1::Destination { revision } => {
            pause.revisions.binary_search(&revision).is_ok()
        }
    }
}
/// Selectively release one active part using the approving ballot's casting-open anchor.
/// Parliament authenticates `s0` before the SCCP enactment entry receives it; SCCP never
/// derives an opening from the certificate, enactment time, or ballot metadata.
pub(super) fn lift(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    part: iroha_data_model::sccp::events::SccpFastPausePartV1,
    s0: iroha_data_model::governance::GovernanceAnchorV1,
) -> Result<(), Error> {
    use super::pause_record::{FastPauseDraft, RetainedSccpFastPause};
    use iroha_data_model::sccp::events::{
        SccpFastPauseClearedReasonV1, SccpFastPauseClearedV1, SccpFastPausePartV1 as Part,
        SccpFastPauseRetainedReasonV1, SccpFastPauseRetainedV1,
    };
    let Some(pause) = store::fast_pauses::get(&*state.world, &network)
        .filter(|pause| state.block_unix_timestamp_ms() < pause.until_ms && holds_part(pause, part))
        .cloned()
    else {
        return Ok(());
    };
    if !pause.enacted_at.precedes_casting_open(s0)
        && !cfg!(all(test, sumeragi_core_mutation = "HC298"))
    {
        state.world.emit_events(Some(SccpEvent::FastPauseRetained(
            SccpFastPauseRetainedV1 {
                network,
                part,
                reason: SccpFastPauseRetainedReasonV1::BallotOpenedBeforeOrAtEnactment,
            },
        )));
        return Ok(());
    }
    let subject = SccpGovernanceSubjectV1::FastHold(network);
    let next_head = store::governance_revision(&*state.world, &subject)
        .checked_add(1)
        .ok_or_else(|| refuse("FastHold head exhausted"))?;
    let taira = pause.taira && part != Part::Taira;
    let mut revisions = iroha_allocation::ChargedBuffer::new(
        pause.revisions.len(),
        state.sccp_evidence_preparation_budget(),
    )
    .map_err(|error| {
        let original = match error {
            iroha_allocation::ChargedBufferError::Admission(original) => {
                PauseRecordError::Admission(original)
            }
            iroha_allocation::ChargedBufferError::Allocator { requested_bytes } => {
                PauseRecordError::Allocator {
                    bytes: requested_bytes,
                }
            }
        };
        construction_error(state, original)
    })?;
    for revision in &pause.revisions {
        if part
            != (Part::Destination {
                revision: *revision,
            })
        {
            revisions
                .try_push(*revision)
                .map_err(|_| refuse("pause revision capacity changed"))?;
        }
    }
    let next = if taira || !revisions.as_slice().is_empty() {
        Some(
            RetainedSccpFastPause::admit_draft(
                &FastPauseDraft {
                    certificate_id: pause.certificate_id,
                    effect_hash: pause.effect_hash,
                    panel_id: pause.panel_id,
                    enacted_at: pause.enacted_at,
                    enacted_at_ms: pause.enacted_at_ms,
                    until_ms: pause.until_ms,
                    taira,
                    revisions: revisions.as_slice(),
                },
                state.sccp_evidence_preparation_budget(),
            )
            .map_err(|error| construction_error(state, error))?,
        )
    } else {
        None
    };
    if let Some(next) = next {
        store::fast_pauses::insert(state, network, next)?;
    } else {
        store::fast_pauses::remove(state, network);
    }
    store::set_governance_revision(state, subject, next_head);
    state
        .world
        .emit_events(Some(SccpEvent::FastPauseCleared(SccpFastPauseClearedV1 {
            network,
            part,
            reason: SccpFastPauseClearedReasonV1::Lifted,
        })));
    Ok(())
}

/// Borrowed current seats; every index points into this exact retained panel graph.
pub(crate) struct SeatProjection<'a> {
    /// Original immutable draw and acceptances.
    pub(crate) panel: &'a RetainedSccpPausePanel,
    /// Primary indices then backup indices; only `2 * seats_per_panel` entries are live.
    pub(crate) indices: [usize; MAX_SEATS],
    /// The committed seat count of each independent panel.
    pub(crate) seats_per_panel: usize,
}
/// Read-only current-seat projection for a retained committed observation.
/// Missing eligibility is an error, never an empty successful seat list.
pub(crate) fn current_seats(
    world: &(impl WorldReadOnly + ?Sized),
    time: u64,
) -> Result<Option<SeatProjection<'_>>, Error> {
    let Some(panel) = store::pause_panel::get(world).as_ref() else {
        return Ok(None);
    };
    let parameters = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP is absent"))?;
    let eligibility = parliament_iface::pause_eligibility(world, panel, time)?;
    let eligible = eligibility.for_original(world, panel, time)?;
    let k = parameters.fast_pause_panel_seats as usize;
    Ok(Some(SeatProjection {
        panel,
        indices: seats(panel, k, time, eligible)?,
        seats_per_panel: k,
    }))
}
