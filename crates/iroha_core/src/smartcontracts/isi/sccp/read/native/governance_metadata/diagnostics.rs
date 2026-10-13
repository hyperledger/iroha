//! Scalar diagnostics retain original request admission and never synthesize Parliament authority.

use super::*;
use crate::governance::parliament::ParliamentAttemptStateV1;
use iroha_data_model::{
    governance::types::GovernanceAttemptStatusV1,
    sccp::{
        governance::SccpGovernanceActionV1 as Action, params::SccpParametersV1,
        registry::SccpRouteActivationV1 as Activation,
    },
};
use iroha_sccp::api::{
    SccpGovernanceActiveAttemptV1, SccpGovernanceBodySizesV1, SccpGovernanceReadinessV1,
};

pub(in crate::smartcontracts::isi::sccp::read) fn attempts(
    world: &(impl WorldReadOnly + ?Sized),
    content: ProposalContentId,
) -> impl Iterator<Item = &ParliamentAttemptStateV1> {
    crate::governance::parliament::canonical_governance_attempt_ids_v1(content)
        .map_while(|id| world.parliament_attempts().get(&id))
}

pub(in crate::smartcontracts::isi::sccp::read) fn attempt_view(
    attempt: &ParliamentAttemptStateV1,
) -> SccpGovernanceAttemptViewV1 {
    SccpGovernanceAttemptViewV1 {
        attempt: *attempt.attempt(),
        expected_head: attempt.expected_head(),
        terminal_height: attempt.terminal_height(),
        superseding_head: attempt.superseding_head(),
        execution_failure_root: attempt.execution_failure_root(),
    }
}

pub(in crate::smartcontracts::isi::sccp::read) fn parameters_before(
    world: &(impl WorldReadOnly + ?Sized),
    proposal: &SccpGovernanceProposalV1,
) -> Option<SccpParametersV1> {
    proposal
        .actions
        .iter()
        .any(|action| matches!(action, Action::SetParameters(_)))
        .then(|| *store::parameters::get(world))
        .flatten()
}

fn original_activation(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
) -> Option<Activation> {
    store::routes::get(world, &network)?
        .revisions
        .get(&revision)
        .map(|record| record.activation)
}

/// Resolve a pause's target after preceding activation intents, without mutating World.
/// An absent or ambiguous live target is reported as absent rather than guessed.
fn live_target(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    rows: &[SccpGovernanceActivationDiffV1],
    control: SccpNativeReadControl<'_>,
) -> Result<Option<u32>> {
    let effective = |revision| {
        rows.iter()
            .rev()
            .find(|row| row.network == network && row.revision == Some(revision))
            .map_or_else(
                || original_activation(world, network, revision),
                |row| row.requested,
            )
    };
    let original = store::routes::get(world, &network);
    let candidates = original
        .into_iter()
        .flat_map(|route| route.revisions.keys().copied())
        .chain(
            rows.iter()
                .filter(|row| row.network == network)
                .filter_map(|row| row.revision),
        );
    let mut target = None;
    for revision in candidates {
        deadline_check(control)?;
        if effective(revision).is_some_and(Activation::is_live) {
            if target.is_some_and(|current| current != revision) {
                return Ok(None);
            }
            target = Some(revision);
        }
    }
    Ok(target)
}

pub(in crate::smartcontracts::isi::sccp::read) fn activation_diff(
    world: &(impl WorldReadOnly + ?Sized),
    proposal: &SccpGovernanceProposalV1,
    rows: &mut Vec<SccpGovernanceActivationDiffV1>,
    control: SccpNativeReadControl<'_>,
) -> Result<()> {
    for (index, action) in proposal.actions.iter().enumerate() {
        deadline_check(control)?;
        let index = u32::try_from(index)
            .map_err(|_| SccpNativeReadError::Unavailable("proposal action count"))?;
        let changes = match action {
            Action::RegisterRoute(action) => [
                Some((
                    action.network,
                    Some(action.revision),
                    Some(Activation::Staged),
                )),
                None,
            ],
            Action::ActivateRevision(action) => [
                Some((
                    action.network,
                    Some(action.revision),
                    Some(Activation::Bidirectional),
                )),
                None,
            ],
            Action::SwitchRevision(action) => [
                Some((
                    action.network,
                    Some(action.from),
                    Some(Activation::InboundOnly),
                )),
                Some((
                    action.network,
                    Some(action.to),
                    Some(Activation::Bidirectional),
                )),
            ],
            Action::DeactivateOutbound(action) => [
                Some((
                    action.network,
                    Some(action.revision),
                    Some(Activation::InboundOnly),
                )),
                None,
            ],
            Action::RetireRevision(action) => [
                Some((
                    action.network,
                    Some(action.revision),
                    Some(Activation::Retired),
                )),
                None,
            ],
            Action::RemoveStaged(action) => {
                [Some((action.network, Some(action.revision), None)), None]
            }
            Action::SetTairaPaused(action) => [
                Some((
                    action.network,
                    live_target(world, action.network, rows, control)?,
                    Some(if action.paused {
                        Activation::Paused
                    } else {
                        Activation::Bidirectional
                    }),
                )),
                None,
            ],
            _ => [None, None],
        };
        for (network, revision, requested) in changes.into_iter().flatten() {
            rows.push(SccpGovernanceActivationDiffV1 {
                action_index: index,
                network,
                revision,
                current: revision
                    .and_then(|revision| original_activation(world, network, revision)),
                requested,
            });
        }
    }
    Ok(())
}

fn active_sccp(world: &(impl WorldReadOnly + ?Sized), attempt: &ParliamentAttemptStateV1) -> bool {
    matches!(
        attempt.attempt().status,
        GovernanceAttemptStatusV1::Active | GovernanceAttemptStatusV1::Certified
    ) && world
        .governance_proposals()
        .get(attempt.attempt().proposal_content_id.as_bytes())
        .is_some_and(|proposal| matches!(proposal.kind, ProposalKind::SccpRouteGovernance(_)))
}

/// Read original governance diagnostics under the caller's complete retained allocation.
/// # Errors
/// Preserves allocation, cancellation, deadline and malformed original beacon refusal.
pub fn readiness(
    view: &(impl StateReadOnly + ?Sized),
    gov: &iroha_config::parameters::actual::Governance,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<SccpGovernanceReadinessV1>> {
    deadline_check(control)?;
    let world = view.world();
    let mut count = 0_usize;
    for (_, attempt) in world.parliament_attempts().iter() {
        deadline_check(control)?;
        if active_sccp(world, attempt) {
            count = count
                .checked_add(1)
                .ok_or(SccpNativeReadError::PhysicalAllocation)?;
        }
    }
    let bytes = count
        .checked_mul(size_of::<SccpGovernanceActiveAttemptV1>())
        .and_then(|bytes| bytes.checked_add(size_of::<SccpGovernanceReadinessV1>()))
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let charge = budget.try_reserve_bytes(bytes)?;
    let mut active_attempts = Vec::new();
    active_attempts
        .try_reserve_exact(count)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    for (_, attempt) in world.parliament_attempts().iter() {
        deadline_check(control)?;
        if active_sccp(world, attempt) {
            // TODO: bind the Parliament-owned due iterator when that external workstream
            // supplies it. A certified height alone is not the complete next due item.
            active_attempts.push(SccpGovernanceActiveAttemptV1 {
                attempt: *attempt.attempt(),
                due_available: false,
                next_due_height: None,
                next_due_timestamp_ms: None,
            });
        }
    }
    let committed_height = u64::try_from(view.height())
        .map_err(|_| SccpNativeReadError::Unavailable("height width"))?;
    let active_beacon_session = crate::beacon::active_global_threshold_beacon_session_id_v1(world)
        .map_err(|_| SccpNativeReadError::Unavailable("active beacon session"))?;
    let beacon_matches_current_roster = active_beacon_session
        .and_then(|id| {
            world
                .global_beacon_key_sessions()
                .get(&id)
                .map(|record| (id, record))
        })
        .is_some_and(|(id, record)| {
            record.session.session_id == id
                && record.session.network_id == *view.network_id()
                && record
                    .activated_at_height
                    .is_some_and(|height| height <= committed_height)
                && record.retired_at_height.is_none()
                && crate::beacon::authenticated_global_threshold_beacon_roster_hash_iter_v1(
                    record.session.record(),
                    view.commit_topology().iter(),
                )
                .is_ok()
        });
    let seats = |value| {
        u64::try_from(value).map_err(|_| SccpNativeReadError::Unavailable("governance body size"))
    };
    let body_sizes = SccpGovernanceBodySizesV1 {
        rules_committee: seats(gov.rules_committee_size)?,
        agenda_council: seats(gov.agenda_council_size)?,
        interest_panel: seats(gov.interest_panel_size)?,
        review_panel: seats(gov.review_panel_size)?,
        coordination_council: seats(gov.coordination_council_size)?,
        policy_jury: seats(gov.policy_jury_size)?,
        confirmation_jury: seats(gov.confirmation_jury_size)?,
        oversight_committee: seats(gov.oversight_committee_size)?,
        mpc_committee: seats(gov.mpc_committee_size)?,
        fma_committee: seats(gov.fma_committee_size)?,
        alternates: seats(gov.parliament_alternate_size)?,
    };
    deadline_check(control)?;
    Ok(SccpNativeDataV1 { data: SccpGovernanceReadinessV1 {
        committed_height, eligible_citizens: None, body_sizes, active_beacon_session, beacon_matches_current_roster,
        parliament_binding_ballot_available: crate::smartcontracts::isi::sccp::parliament_iface::parliament_binding_ballot_available(),
        reconciliation_available: crate::smartcontracts::isi::sccp::governance::sccp_reconciliation_available(),
        attempt_latency_ms: crate::smartcontracts::isi::sccp::parliament_iface::parliament_sccp_attempt_latency_ms(), active_attempts,
    }, _charge: charge })
}
