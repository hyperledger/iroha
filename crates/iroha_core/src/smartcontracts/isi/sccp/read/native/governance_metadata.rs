//! Request-funded governance rows borrowing original proposal, account and route graphs.

use super::*;
use crate::{
    smartcontracts::isi::sccp::governance::preflight_rejection_in,
    state::{GovernanceProposalRecord, GovernanceProposalStatus},
};
use iroha_data_model::{
    account::AccountId,
    governance::types::{GovernanceAttemptV1, ProposalContentId, ProposalKind},
    sccp::{
        governance::{SccpGovernanceBaseRevisionV1, SccpGovernanceProposalV1},
        registry::SccpRouteV1,
    },
};
use iroha_sccp::api::{
    SccpGovernanceActivationDiffV1, SccpGovernanceAttemptViewV1, SccpGovernanceProposalDetailV1,
    SccpGovernanceProposalPhaseV1, SccpGovernanceProposalStatusV1,
};
pub(in crate::smartcontracts::isi::sccp::read) mod diagnostics;
pub use diagnostics::readiness;
use mv::storage::StorageReadOnly as _;
use norito::{
    core::{Encoder, PayloadRef, SerializePayload},
    json::{BoundedJsonError, JsonSerialize, JsonWriteSink},
};

macro_rules! schema {
    ($view:ty, $wire:ty) => {
        impl norito::NoritoSchema for $view {
            fn nominal_name() -> String {
                <$wire as norito::NoritoSchema>::nominal_name()
            }
            fn frame_name() -> String {
                <$wire as norito::NoritoSchema>::frame_name()
            }
        }
    };
}
macro_rules! sequence {
    ($view:ty, $wire:ty) => {
        schema!($view, Vec<$wire>);
        impl SerializePayload for $view {
            fn serialize(
                &self,
                encoder: &mut Encoder<'_>,
            ) -> std::result::Result<(), norito::Error> {
                self.0.serialize(encoder)
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                self.0.encoded_len_hint()
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                self.0.encoded_len_exact()
            }
        }
        impl JsonSerialize for $view {
            fn json_serialize(&self, out: &mut String) {
                self.0.json_serialize(out)
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn JsonWriteSink,
            ) -> std::result::Result<(), BoundedJsonError> {
                self.0.json_serialize_to(out)
            }
        }
    };
}

/// Canonical route sequence whose nested account and revision graphs remain in the view.
pub struct Registry<'a>(Vec<PayloadRef<'a, SccpRouteV1>>);
sequence!(Registry<'_>, SccpRouteV1);

/// One open proposal, borrowing the original retained action graph.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct ProposalStatus<'a> {
    content_id: ProposalContentId,
    created_height: u64,
    proposal: PayloadRef<'a, SccpGovernanceProposalV1>,
    admissible: bool,
    latest_attempt: Option<GovernanceAttemptV1>,
}
schema!(ProposalStatus<'_>, SccpGovernanceProposalStatusV1);

/// Open proposal sequence in the canonical creation-height and content-id order.
pub struct Proposals<'a>(Vec<ProposalStatus<'a>>);
sequence!(Proposals<'_>, SccpGovernanceProposalStatusV1);

/// Detail of one proposal in any phase, borrowing both proposer and action graph.
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
pub struct ProposalDetail<'a> {
    content_id: ProposalContentId,
    proposer: PayloadRef<'a, AccountId>,
    created_height: u64,
    phase: SccpGovernanceProposalPhaseV1,
    proposal: PayloadRef<'a, SccpGovernanceProposalV1>,
    admissible: bool,
    latest_attempt: Option<GovernanceAttemptV1>,
    attempts: Vec<SccpGovernanceAttemptViewV1>,
    parameters_before: Option<iroha_data_model::sccp::params::SccpParametersV1>,
    activation_diff: Vec<SccpGovernanceActivationDiffV1>,
}
schema!(ProposalDetail<'_>, SccpGovernanceProposalDetailV1);

fn reserve_rows<T>(
    count: usize,
    budget: &AllocationBudget,
) -> Result<(Vec<T>, AllocationReservation)> {
    let bytes = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<T>>()))
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let charge = budget.try_reserve_bytes(bytes)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    Ok((rows, charge))
}

fn count_rows<T>(
    rows: impl Iterator<Item = T>,
    control: SccpNativeReadControl<'_>,
) -> Result<usize> {
    let mut count = 0_usize;
    for _ in rows {
        deadline_check(control)?;
        count = count
            .checked_add(1)
            .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    }
    Ok(count)
}

/// Borrow the registry in stored network order, admitting its reference shell first.
/// # Errors
/// Preserves original allocation, physical, deadline and cancellation refusal.
pub fn registry<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Registry<'a>>> {
    deadline_check(control)?;
    let world = view.world();
    let count = count_rows(store::routes::iter(world), control)?;
    let (mut rows, charge) = reserve_rows(count, budget)?;
    for (_, route) in store::routes::iter(world) {
        deadline_check(control)?;
        rows.push(PayloadRef(route));
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: Registry(rows),
        _charge: charge,
    })
}

/// Read the scalar governance revisions in original subject order under the caller's pool.
/// # Errors
/// Preserves original allocation, physical, deadline and cancellation refusal.
pub fn revisions(
    view: &(impl StateReadOnly + ?Sized),
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Vec<SccpGovernanceBaseRevisionV1>>> {
    deadline_check(control)?;
    let world = view.world();
    let count = count_rows(store::governance_revisions::iter(world), control)?;
    let (mut rows, charge) = reserve_rows(count, budget)?;
    for (subject, revision) in store::governance_revisions::iter(world) {
        deadline_check(control)?;
        rows.push((*subject, *revision).into());
    }
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: rows,
        _charge: charge,
    })
}

fn latest_attempt(
    world: &(impl WorldReadOnly + ?Sized),
    content: ProposalContentId,
) -> Option<GovernanceAttemptV1> {
    crate::governance::parliament::canonical_governance_attempt_ids_v1(content)
        .map_while(|attempt_id| world.parliament_attempts().get(&attempt_id))
        .last()
        .map(|attempt| *attempt.attempt())
}

fn open(record: &GovernanceProposalRecord) -> bool {
    record.status == GovernanceProposalStatus::Proposed
        && matches!(&record.kind, ProposalKind::SccpRouteGovernance(_))
}

/// Borrow open proposals, sorting only the funded reference shell without graph copies.
/// # Errors
/// Preserves original allocation, physical, deadline and cancellation refusal.
pub fn proposals<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<Proposals<'a>>> {
    deadline_check(control)?;
    let world = view.world();
    let mut count = 0_usize;
    for (_, record) in world.governance_proposals().iter() {
        deadline_check(control)?;
        if open(record) {
            count = count
                .checked_add(1)
                .ok_or(SccpNativeReadError::PhysicalAllocation)?;
        }
    }
    let (mut rows, charge) = reserve_rows(count, budget)?;
    for (id, record) in world.governance_proposals().iter() {
        deadline_check(control)?;
        if !open(record) {
            continue;
        }
        let ProposalKind::SccpRouteGovernance(sccp) = &record.kind else {
            continue;
        };
        let content_id = ProposalContentId::new(*id);
        rows.push(ProposalStatus {
            content_id,
            created_height: record.created_height,
            proposal: PayloadRef(&sccp.proposal),
            admissible: preflight_rejection_in(world, &sccp.proposal).is_none(),
            latest_attempt: latest_attempt(world, content_id),
        });
    }
    rows.sort_unstable_by_key(|row| (row.created_height, *row.content_id.as_bytes()));
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data: Proposals(rows),
        _charge: charge,
    })
}

/// Borrow one original proposal in any phase, without constructing diagnostic strings.
/// # Errors
/// Preserves missing-record, original allocation, deadline and cancellation refusal.
pub fn proposal<'a>(
    view: &'a (impl StateReadOnly + ?Sized),
    id: [u8; 32],
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<SccpNativeDataV1<ProposalDetail<'a>>> {
    deadline_check(control)?;
    let world = view.world();
    let record = world
        .governance_proposals()
        .get(&id)
        .ok_or(SccpNativeReadError::NotFound("SCCP proposal"))?;
    let ProposalKind::SccpRouteGovernance(sccp) = &record.kind else {
        return Err(SccpNativeReadError::NotFound("SCCP proposal"));
    };
    let content_id = ProposalContentId::new(id);
    let attempt_count = diagnostics::attempts(world, content_id).count();
    let diff_count = sccp
        .proposal
        .actions
        .len()
        .checked_mul(2)
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let bytes = attempt_count
        .checked_mul(size_of::<SccpGovernanceAttemptViewV1>())
        .and_then(|bytes| {
            diff_count
                .checked_mul(size_of::<SccpGovernanceActivationDiffV1>())
                .and_then(|diff| bytes.checked_add(diff))
        })
        .and_then(|bytes| bytes.checked_add(size_of::<ProposalDetail<'_>>()))
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let charge = budget.try_reserve_bytes(bytes)?;
    let mut attempts = Vec::new();
    attempts
        .try_reserve_exact(attempt_count)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    for attempt in diagnostics::attempts(world, content_id) {
        deadline_check(control)?;
        attempts.push(diagnostics::attempt_view(attempt));
    }
    let mut activation_diff = Vec::new();
    activation_diff
        .try_reserve_exact(diff_count)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    diagnostics::activation_diff(world, &sccp.proposal, &mut activation_diff, control)?;
    let data = ProposalDetail {
        content_id,
        proposer: PayloadRef(&record.proposer),
        created_height: record.created_height,
        phase: match record.status {
            GovernanceProposalStatus::Proposed => SccpGovernanceProposalPhaseV1::Proposed,
            GovernanceProposalStatus::Rejected => SccpGovernanceProposalPhaseV1::Rejected,
            GovernanceProposalStatus::Enacted => SccpGovernanceProposalPhaseV1::Enacted,
            GovernanceProposalStatus::Superseded => SccpGovernanceProposalPhaseV1::Superseded,
            GovernanceProposalStatus::ExecutionFailed => {
                SccpGovernanceProposalPhaseV1::ExecutionFailed
            }
        },
        proposal: PayloadRef(&sccp.proposal),
        admissible: preflight_rejection_in(world, &sccp.proposal).is_none(),
        latest_attempt: latest_attempt(world, content_id),
        attempts,
        parameters_before: diagnostics::parameters_before(world, &sccp.proposal),
        activation_diff,
    };
    deadline_check(control)?;
    Ok(SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

#[cfg(test)]
mod tests;
