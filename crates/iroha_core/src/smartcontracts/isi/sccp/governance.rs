//! SCCP governance through the SORA Parliament (`specs/sccp.md` §4.14.3). Owner: ws33.
//!
//! `ProposeSccpRouteGovernance` → 8-body Parliament → due certificate → atomic enactment. The
//! expected head is scoped per SCCP subject: for a proposal `P` with sorted subjects `S(P)`,
//! `version = 1 + Σ rev(s)` and `head_root = parliament_governance_head_root_v1(&[(s,
//! rev(s))])` ([`subject_heads`]; the Parliament code in `world.rs` wraps it). Attempt creation
//! additionally checks `base_revisions` and every `RegisterRoute` destination word
//! ([`preflight_attempt`]). Enactment ([`enact`]) applies every action in order and increments
//! `rev(s)` for each subject inside the same effect transaction; any failed precondition fails
//! the whole enactment, which the pipeline records as `ExecutionFailed` with no SCCP change.

#[cfg(test)]
#[path = "governance/anchor_tests.rs"]
mod anchor_tests;
#[path = "governance/holds.rs"]
mod holds;
#[cfg(test)]
#[path = "governance/installation_tests.rs"]
mod installation_tests;
#[cfg(test)]
#[path = "governance/reference_fixtures.rs"]
mod reference_fixtures;
#[path = "governance/registration.rs"]
mod registration;

use super::{
    Error, controls, escrow, light_clients,
    recipients::{self, SccpRecipientClassV1},
    registry, store,
};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    governance::{
        GovernanceAnchorV1,
        types::{ProposalKind, SccpRouteGovernanceProposal},
    },
    sccp::{
        deployment::SccpDeploymentV1,
        events::{SccpEvent, SccpGovernanceEnactedV1, SccpStrandedReleasedV1},
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
            SccpRegisterRouteActionV1, SccpReleaseStrandedActionV1, SccpRouteRevisionActionV1,
            SccpSwitchRevisionActionV1,
        },
        registry::{SccpRouteActivationV1, SccpRouteRevisionV1},
    },
};
use iroha_sccp::v1::constants::TON_AMOUNT_BOUND;

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP governance: {reason}").into())
}

/// Whether all authenticated quarantine reconciliation paths are implemented (§10.2).
///
/// The R1–R6 accounting consumers are implemented. TODO: Parliament must supply the
/// authenticated remaining budget and position of the shared G1/G2a pass before the
/// production reconciliation close can run. A separate SCCP budget or an assumed-empty
/// Parliament prefix cannot open this gate.
#[must_use]
pub const fn sccp_reconciliation_available() -> bool {
    false
}

/// Return `(version, heads)` of `proposal` against `world`: `heads = [(s, rev(s))]` over the
/// sorted subjects `S(P)` and `version = 1 + Σ rev(s)` (§4.14.3).
///
/// # Errors
///
/// Fails when the version overflows `u64`.
pub fn subject_heads(
    world: &(impl WorldReadOnly + ?Sized),
    proposal: &SccpGovernanceProposalV1,
) -> Result<(u64, Vec<(SccpGovernanceSubjectV1, u64)>), Error> {
    heads_for_subjects(world, proposal.subjects())
}

/// Read revision heads and their checked version for an already ordered subject set.
fn heads_for_subjects(
    world: &(impl WorldReadOnly + ?Sized),
    subjects: impl IntoIterator<Item = SccpGovernanceSubjectV1>,
) -> Result<(u64, Vec<(SccpGovernanceSubjectV1, u64)>), Error> {
    let heads: Vec<_> = subjects
        .into_iter()
        .map(|subject| {
            let revision = store::governance_revision(world, &subject);
            (subject, revision)
        })
        .collect();
    let version = heads
        .iter()
        .try_fold(1_u64, |sum, (_, revision)| sum.checked_add(*revision))
        .ok_or_else(|| refuse("the proposal's head version overflows"))?;
    Ok((version, heads))
}

/// Check the SCCP preconditions of a new Parliament attempt: every `rev(s)` still equals
/// `base_revisions` and every `RegisterRoute` destination word is unused (§4.14.3 step 2).
///
/// # Errors
///
/// Fails when the proposal is stale; it can then never get another attempt.
pub fn preflight_attempt(
    state_transaction: &StateTransaction<'_, '_>,
    proposal: &SccpGovernanceProposalV1,
) -> Result<(), Error> {
    preflight_attempt_in(&*state_transaction.world, proposal)
}

/// [`preflight_attempt`] over any world view (the proposals read API reports it).
///
/// # Errors
///
/// Fails when the proposal is stale.
pub fn preflight_attempt_in(
    world: &(impl WorldReadOnly + ?Sized),
    proposal: &SccpGovernanceProposalV1,
) -> Result<(), Error> {
    match preflight_rejection_in(world, proposal) {
        None => Ok(()),
        Some(PreflightRejection::Stale {
            subject,
            current,
            base,
        }) => Err(refuse(format_args!(
            "stale proposal: subject {subject:?} is at revision {current}, not {base}"
        ))),
        Some(PreflightRejection::DestinationUsed) => {
            Err(refuse("the destination word is already registered"))
        }
    }
}

/// Scalar outcome of the shared preflight relation, before diagnostic string construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreflightRejection {
    /// The first base revision differs from current committed state.
    Stale {
        subject: SccpGovernanceSubjectV1,
        current: u64,
        base: u64,
    },
    /// A requested deployment word is already registered.
    DestinationUsed,
}

/// Check exactly the preflight relation without allocating a diagnostic on rejection.
pub(super) fn preflight_rejection_in(
    world: &(impl WorldReadOnly + ?Sized),
    proposal: &SccpGovernanceProposalV1,
) -> Option<PreflightRejection> {
    for base in &proposal.base_revisions {
        let current = store::governance_revision(world, &base.subject);
        if current != base.revision {
            return Some(PreflightRejection::Stale {
                subject: base.subject,
                current,
                base: base.revision,
            });
        }
    }
    for action in &proposal.actions {
        if let SccpGovernanceActionV1::RegisterRoute(register) = action
            && store::destination_words::contains(world, &register.deployment.destination_word())
        {
            return Some(PreflightRejection::DestinationUsed);
        }
    }
    None
}

fn ensure_word_unused(
    world: &(impl WorldReadOnly + ?Sized),
    deployment: &SccpDeploymentV1,
) -> Result<(), Error> {
    if store::destination_words::contains(world, &deployment.destination_word()) {
        return Err(refuse("the destination word is already registered"));
    }
    Ok(())
}

/// Apply every action of the certified `proposal` in order and increment the revision of each
/// of its subjects (§4.14.3 step 4). Runs inside the isolated effect transaction.
/// The Parliament adapter authenticates the certificate id, effect hash and approving Policy
/// Jury's casting-open `s0` before calling; SCCP consumes no certificate internals.
///
/// # Errors
///
/// Fails on the first action whose precondition does not hold; the caller drops the effect
/// transaction.
pub fn enact(
    state_transaction: &mut StateTransaction<'_, '_>,
    certificate_id: [u8; 32],
    effect_hash: [u8; 32],
    s0: GovernanceAnchorV1,
    proposal: &SccpGovernanceProposalV1,
) -> Result<(), Error> {
    if proposal.network_id != *state_transaction.network_id() {
        return Err(refuse("the proposal belongs to a different NetworkId"));
    }
    if store::parameters::get(&*state_transaction.world).is_none() {
        return Err(refuse("SCCP does not exist on this network"));
    }
    let proposal_id = ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(proposal.clone()),
    })
    .fingerprint();
    #[cfg(all(test, sumeragi_core_mutation = "HC237"))]
    let certificate_id = {
        let _ = certificate_id;
        proposal_id
    };
    let cause = controls::ControlCauseV1::from_parliament(certificate_id, effect_hash)?;
    #[cfg(all(test, sumeragi_core_mutation = "HC397"))]
    let s0 = {
        let _ = s0;
        GovernanceAnchorV1 {
            height: 0,
            position: 0,
            timestamp_ms: 0,
        }
    };
    for (index, action) in proposal.actions.iter().enumerate() {
        apply_action(state_transaction, action, proposal_id, cause, s0)
            .map_err(|error| refuse(format_args!("action {index}: {error}")))?;
    }
    let subjects = proposal.subjects();
    for subject in &subjects {
        let next = store::governance_revision(&*state_transaction.world, subject)
            .checked_add(1)
            .ok_or_else(|| refuse("a subject revision overflows"))?;
        store::set_governance_revision(state_transaction, subject.clone(), next);
    }
    state_transaction
        .world
        .emit_events(Some(SccpEvent::GovernanceEnacted(
            SccpGovernanceEnactedV1 {
                proposal_id,
                subjects,
            },
        )));
    Ok(())
}

fn apply_action(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpGovernanceActionV1,
    proposal_id: [u8; 32],
    cause: controls::ControlCauseV1,
    s0: GovernanceAnchorV1,
) -> Result<(), Error> {
    match action {
        SccpGovernanceActionV1::RegisterRoute(register) => {
            register_route(state_transaction, register)
        }
        SccpGovernanceActionV1::AttestSccpDeploymentProgress(action) => {
            holds::attest(state_transaction, action)
        }
        SccpGovernanceActionV1::QuarantineSccpRevision(action) => {
            holds::quarantine(state_transaction, *action, cause)
        }
        SccpGovernanceActionV1::OpenSccpReconciliation(action) => super::reconciliation::open(
            state_transaction,
            action.network,
            action.revision,
            action.window_ms,
        ),
        SccpGovernanceActionV1::ActivateRevision(action) => {
            activate_revision(state_transaction, *action)
        }
        SccpGovernanceActionV1::SwitchRevision(action) => {
            switch_revision(state_transaction, action)
        }
        SccpGovernanceActionV1::DeactivateOutbound(action) => registry::set_activation(
            state_transaction,
            action.network,
            action.revision,
            SccpRouteActivationV1::InboundOnly,
        ),
        SccpGovernanceActionV1::RetireRevision(action) => {
            retire_revision(state_transaction, *action)
        }
        SccpGovernanceActionV1::RemoveStaged(action) => remove_staged(state_transaction, *action),
        SccpGovernanceActionV1::ReleaseStranded(action) => {
            release_stranded(state_transaction, action, proposal_id)
        }
        SccpGovernanceActionV1::SetTairaPaused(action) => {
            if !action.paused {
                super::fast_pause::lift(
                    state_transaction,
                    action.network,
                    iroha_data_model::sccp::events::SccpFastPausePartV1::Taira,
                    s0,
                )?;
            }
            set_taira_paused(state_transaction, action.network, action.paused)
        }
        SccpGovernanceActionV1::SetDestinationPaused(action) => {
            let Some(mut route) =
                store::routes::get(&*state_transaction.world, &action.network).cloned()
            else {
                return Ok(());
            };
            // A revision retired or removed since the proposal has nothing left to mint.
            if let Some(revision) = route
                .revisions
                .get_mut(&action.revision)
                .filter(|revision| revision.activation != SccpRouteActivationV1::Retired)
            {
                // The caller writes only its own Parliament flag. record_control snapshots
                // the complete post-update state inside this same isolated effect transaction.
                if !action.paused {
                    super::fast_pause::lift(
                        state_transaction,
                        action.network,
                        iroha_data_model::sccp::events::SccpFastPausePartV1::Destination {
                            revision: action.revision,
                        },
                        s0,
                    )?;
                }
                revision.destination_paused = action.paused;
                store::routes::insert(state_transaction, action.network, route)?;
                controls::record_control(
                    state_transaction,
                    action.network,
                    action.revision,
                    cause,
                )?;
            }
            Ok(())
        }
        SccpGovernanceActionV1::InitializeLightClient(action) => {
            light_clients::initialize(state_transaction, action, proposal_id)
        }
        SccpGovernanceActionV1::InstallTrustedCheckpoint(action) => {
            light_clients::install_checkpoint(state_transaction, action, proposal_id)
        }
        SccpGovernanceActionV1::FreezeLightClient(action) => {
            light_clients::freeze(state_transaction, action, proposal_id)
        }
        SccpGovernanceActionV1::SetFastPauseSuspended(action) => {
            super::fast_pause::suspend(state_transaction, action.network, action.duration_ms)
        }
        SccpGovernanceActionV1::SetParameters(action) => {
            super::init::check_parameters(state_transaction, &action.next)
                .map_err(|error| refuse(format_args!("parameters: {error}")))?;
            store::parameters::set(state_transaction, Some(action.next));
            Ok(())
        }
        SccpGovernanceActionV1::ActivateLightClientProfile(action) => {
            light_clients::activate_profile(state_transaction, action, proposal_id)
        }
    }
}

fn register_route(
    state_transaction: &mut StateTransaction<'_, '_>,
    register: &SccpRegisterRouteActionV1,
) -> Result<(), Error> {
    let network = register.network;
    let world = &*state_transaction.world;
    store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    let route = store::routes::get(world, &network)
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    let expected_revision = route
        .latest_revision()
        .checked_add(1)
        .ok_or_else(|| refuse("the revision counter is exhausted"))?;
    if register.revision != expected_revision {
        return Err(refuse(format_args!(
            "revision {} is not the next revision {expected_revision}",
            register.revision
        )));
    }
    if !register.deployment.fits_network(network) {
        return Err(refuse("the deployment does not fit the network"));
    }
    let cap = register.max_wrapped_supply;
    if cap == 0 || (network == SccpNetworkV1::TonMainnet && cap >= TON_AMOUNT_BOUND) {
        return Err(refuse(format_args!("supply cap {cap} is out of bounds")));
    }
    ensure_word_unused(world, &register.deployment)?;
    registration::validate_available(state_transaction, register)?;
    let gates = (
        super::parliament_iface::parliament_binding_ballot_available(),
        sccp_reconciliation_available(),
    );
    // Only module unit tests can exercise installation before the owners open P0.
    #[cfg(test)]
    let gates = tests::LAUNCH_GATES.with(|override_| override_.get().unwrap_or(gates));
    if !(cfg!(all(test, sumeragi_core_mutation = "HC396")) || gates.0 && gates.1) {
        return Err(refuse(
            "RegisterRoute launch/reconciliation authority is unavailable",
        ));
    }
    let revision = SccpRouteRevisionV1::staged(
        register.revision,
        register.deployment,
        register.initial_committee,
        register.max_wrapped_supply,
        state_transaction._curr_block.height().get(),
    );
    let destination_word = revision.destination_word;
    let mut route = route.clone();
    route.revisions.insert(register.revision, revision);
    store::routes::insert(state_transaction, network, route)?;
    store::destination_words::insert(
        state_transaction,
        destination_word,
        (network, register.revision),
    )?;
    registry::emit_activation_changed(
        state_transaction,
        network,
        register.revision,
        None,
        Some(SccpRouteActivationV1::Staged),
    );
    Ok(())
}

fn revision_activation(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
) -> Result<SccpRouteActivationV1, Error> {
    store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .map(|record| record.activation)
        .ok_or_else(|| refuse(format_args!("revision {revision} does not exist")))
}

fn activate_revision(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: SccpRouteRevisionActionV1,
) -> Result<(), Error> {
    let world = &*state_transaction.world;
    if revision_activation(world, action.network, action.revision)? != SccpRouteActivationV1::Staged
    {
        return Err(refuse(format_args!(
            "revision {} is not Staged",
            action.revision
        )));
    }
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let profiles = light_clients::executing_profiles(state_transaction)?;
    let world = &*state_transaction.world;
    if !light_clients::is_usable(world, &profiles, action.network, now_ms) {
        return Err(refuse(format_args!(
            "the {} light client is not usable",
            action.network.profile_key()
        )));
    }
    registry::set_activation(
        state_transaction,
        action.network,
        action.revision,
        SccpRouteActivationV1::Bidirectional,
    )
}

fn switch_revision(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpSwitchRevisionActionV1,
) -> Result<(), Error> {
    if revision_activation(&*state_transaction.world, action.network, action.to)?
        != SccpRouteActivationV1::Staged
    {
        return Err(refuse(format_args!("revision {} is not Staged", action.to)));
    }
    registry::set_activation(
        state_transaction,
        action.network,
        action.from,
        SccpRouteActivationV1::InboundOnly,
    )?;
    registry::set_activation(
        state_transaction,
        action.network,
        action.to,
        SccpRouteActivationV1::Bidirectional,
    )
}

fn retire_revision(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: SccpRouteRevisionActionV1,
) -> Result<(), Error> {
    let world = &*state_transaction.world;
    let record = store::routes::get(world, &action.network)
        .and_then(|route| route.revisions.get(&action.revision))
        .ok_or_else(|| refuse(format_args!("revision {} does not exist", action.revision)))?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC288"))
        && record.quarantine.is_some()
        && !super::reconciliation::is_reconciled(world, action.network, action.revision)
    {
        return Err(refuse(
            "quarantined revision must be reconciled before retirement",
        ));
    }
    let liability = record.liability;
    if liability != 0 {
        return Err(refuse(format_args!(
            "revision {} still has liability {liability}",
            action.revision
        )));
    }
    if store::pending_count(world, &(action.network, action.revision)) != (0, 0) {
        return Err(refuse(format_args!(
            "revision {} has pending settlements",
            action.revision
        )));
    }
    registry::set_activation(
        state_transaction,
        action.network,
        action.revision,
        SccpRouteActivationV1::Retired,
    )
}

fn remove_staged(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: SccpRouteRevisionActionV1,
) -> Result<(), Error> {
    let mut route = store::routes::get(&*state_transaction.world, &action.network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", action.network.profile_key())))?;
    let removable = route.revisions.get(&action.revision).is_some_and(|record| {
        record.activation == SccpRouteActivationV1::Staged
            && !record.ever_activated
            && record.liability == 0
    });
    if !removable {
        return Err(refuse(format_args!(
            "revision {} is not a never-activated Staged revision",
            action.revision
        )));
    }
    // The destination word stays reserved forever.
    route.revisions.remove(&action.revision);
    store::routes::insert(state_transaction, action.network, route)?;
    registry::emit_activation_changed(
        state_transaction,
        action.network,
        action.revision,
        Some(SccpRouteActivationV1::Staged),
        None,
    );
    Ok(())
}

fn release_stranded(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpReleaseStrandedActionV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    let network = action.network;
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    route.stranded = route
        .stranded
        .checked_sub(action.amount)
        .ok_or_else(|| refuse(format_args!("only {} is stranded", route.stranded)))?;
    let registered = match recipients::classify_account(state_transaction, action.recipient.clone())
    {
        SccpRecipientClassV1::Creditable { registered, .. } => registered,
        SccpRecipientClassV1::Uncreditable { .. } | SccpRecipientClassV1::Undecodable => {
            return Err(refuse("the recipient cannot be credited"));
        }
    };
    if !registered {
        recipients::register_recipient(state_transaction, &action.recipient, network, None)?;
    }
    escrow::release(
        state_transaction,
        network,
        &action.recipient,
        action.amount,
        proposal_id,
    )?;
    store::routes::insert(state_transaction, network, route)?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::StrandedReleased(SccpStrandedReleasedV1 {
            network,
            recipient: action.recipient.clone(),
            amount: action.amount,
            memo: action.memo.clone(),
            proposal_id,
        })));
    Ok(())
}

/// Apply `SetTairaPaused` with "ensure" semantics: it never fails (§4.14.3).
fn set_taira_paused(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    paused: bool,
) -> Result<(), Error> {
    let (from, to) = if paused {
        (
            SccpRouteActivationV1::Bidirectional,
            SccpRouteActivationV1::Paused,
        )
    } else {
        (
            SccpRouteActivationV1::Paused,
            SccpRouteActivationV1::Bidirectional,
        )
    };
    let revision = store::routes::get(&*state_transaction.world, &network).and_then(|route| {
        route
            .revisions
            .values()
            .find(|record| record.activation == from)
            .map(|record| record.revision)
    });
    if let Some(revision) = revision {
        registry::set_activation(state_transaction, network, revision, to)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        blank_state, header, sample_generation_at, sample_pin, sample_proposal,
    };
    use iroha_data_model::sccp::{
        deployment::{SccpEvmDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1},
        governance::{
            SccpSetDestinationPausedActionV1, SccpSetParametersActionV1, SccpSetTairaPausedActionV1,
        },
        params::SccpParametersV1,
        registry::SccpRouteRevisionV1,
    };

    const S0: GovernanceAnchorV1 = GovernanceAnchorV1 {
        height: 1,
        position: 0,
        timestamp_ms: 1,
    };

    thread_local! {
        pub(super) static LAUNCH_GATES: std::cell::Cell<Option<(bool, bool)>> = const { std::cell::Cell::new(None) };
    }

    /// Override only the two launch predicates on this unit test's thread.
    pub(super) fn with_launch_gates<R>(gates: (bool, bool), run: impl FnOnce() -> R) -> R {
        struct Restore(Option<(bool, bool)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                LAUNCH_GATES.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(LAUNCH_GATES.with(|slot| slot.replace(Some(gates))));
        run()
    }

    const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

    fn proposal(
        network_id: iroha_data_model::NetworkId,
        base: Vec<(SccpGovernanceSubjectV1, u64)>,
        actions: Vec<SccpGovernanceActionV1>,
    ) -> SccpGovernanceProposalV1 {
        SccpGovernanceProposalV1 {
            network_id,
            base_revisions: base.into_iter().map(Into::into).collect(),
            actions,
        }
    }

    fn evm(seed: u8) -> SccpDeploymentV1 {
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [seed; 20],
            runtime_code_hash: [seed; 32],
        })
    }

    fn register(revision: u32, seed: u8) -> SccpGovernanceActionV1 {
        SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
            network: NETWORK,
            revision,
            deployment: evm(seed),
            initial_committee: sample_pin(&sample_generation_at(1, 1)),
            max_wrapped_supply: 1_000_000_000_000,
        })
    }

    /// Initialize SCCP with generation 1 current.
    fn setup(stx: &mut StateTransaction<'_, '_>) {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
        crate::smartcontracts::isi::sccp::test_support::install_generation(
            stx,
            1,
            sample_generation_at(1, 1),
        )
        .expect("generation");
        store::committee_current::set(stx, 1);
    }

    /// Existing-state fixture for lifecycle tests, not evidence of successful registration.
    /// RegisterRoute still requires the original identity and all launch/forgery authority.
    fn existing_staged(stx: &mut StateTransaction<'_, '_>, revision: u32, seed: u8) {
        let mut route = store::routes::get(&*stx.world, &NETWORK)
            .cloned()
            .expect("route");
        let deployment = evm(seed);
        route.revisions.insert(
            revision,
            SccpRouteRevisionV1::staged(
                revision,
                deployment,
                sample_pin(store::committee_generations::get(&*stx.world, &1).expect("generation")),
                1_000_000_000_000,
                1,
            ),
        );
        store::routes::insert(stx, NETWORK, route).expect("existing revision");
        store::destination_words::insert(stx, deployment.destination_word(), (NETWORK, revision))
            .expect("existing destination");
    }

    #[test]
    fn register_route_refuses_without_authenticated_native_committee_pin() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        let code = SccpTonCodeRefV1 {
            hash: [5; 32],
            depth: 0,
        };
        for (network, deployment) in [
            (NETWORK, evm(7)),
            (
                SccpNetworkV1::TonMainnet,
                SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
                    master_account: [9; 32],
                    minter_code: code,
                    wallet_code: code,
                    bucket_code: code,
                }),
            ),
        ] {
            let before = store::routes::get(&*stx.world, &network)
                .cloned()
                .expect("route");
            let proposal = proposal(
                stx.network_id,
                Vec::new(),
                vec![SccpGovernanceActionV1::RegisterRoute(
                    SccpRegisterRouteActionV1 {
                        network,
                        revision: 1,
                        deployment,
                        initial_committee: sample_pin(&sample_generation_at(1, 1)),
                        max_wrapped_supply: 1_000_000_000_000,
                    },
                )],
            );
            let error = enact(&mut stx, [0x43; 32], [0x45; 32], S0, &proposal)
                .expect_err("no original authority for the supplied native pin");
            assert!(
                error
                    .to_string()
                    .contains("original committed execution tip is absent"),
                "{error}"
            );
            assert_eq!(store::routes::get(&*stx.world, &network), Some(&before));
            assert!(!store::destination_words::contains(
                &*stx.world,
                &deployment.destination_word()
            ));
            assert_eq!(
                store::governance_revision(&*stx.world, &SccpGovernanceSubjectV1::Route(network)),
                0
            );
        }
    }

    fn activation(stx: &StateTransaction<'_, '_>, revision: u32) -> Option<SccpRouteActivationV1> {
        store::routes::get(&*stx.world, &NETWORK)
            .and_then(|route| route.revisions.get(&revision))
            .map(|record| record.activation)
    }

    #[test]
    fn heads_are_scoped_per_subject() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let id = stx.network_id;
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let pause = proposal(
            id,
            vec![],
            vec![
                register(1, 7),
                SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 {
                    next: SccpParametersV1::taira_default(),
                }),
            ],
        );
        let (version, heads) = subject_heads(&*stx.world, &pause).expect("heads");
        assert_eq!(version, 1);
        assert_eq!(
            heads,
            vec![
                (SccpGovernanceSubjectV1::Route(NETWORK), 0),
                (SccpGovernanceSubjectV1::Parameters, 0),
            ]
        );
        store::set_governance_revision(&mut stx, route, 3);
        store::set_governance_revision(&mut stx, SccpGovernanceSubjectV1::Parameters, 2);
        assert_eq!(subject_heads(&*stx.world, &pause).expect("heads").0, 6);
    }

    #[test]
    fn stale_base_revisions_and_taken_words_refuse_attempts() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let fresh = proposal(id, vec![(route.clone(), 0)], vec![register(1, 7)]);
        assert_eq!(preflight_rejection_in(stx.world(), &fresh), None);
        preflight_attempt(&stx, &fresh).expect("fresh");
        store::destination_words::insert(&mut stx, evm(7).destination_word(), (NETWORK, 9))
            .expect("word");
        preflight_attempt(&stx, &fresh).expect_err("word taken");
        assert_eq!(
            preflight_rejection_in(stx.world(), &fresh),
            Some(PreflightRejection::DestinationUsed)
        );
        let other = proposal(id, vec![(route.clone(), 0)], vec![register(1, 8)]);
        store::set_governance_revision(&mut stx, route, 1);
        assert_eq!(
            preflight_rejection_in(stx.world(), &fresh),
            Some(PreflightRejection::Stale {
                subject: route,
                current: 1,
                base: 0,
            }),
            "stale revision is reported before a reused destination word"
        );
        let error = preflight_attempt(&stx, &other).expect_err("stale");
        assert!(error.to_string().contains("stale"), "{error}");
    }

    #[test]
    fn existing_revision_activation_pause_and_subject_counts_follow_their_rules() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let control = SccpGovernanceSubjectV1::RouteControl(NETWORK);
        existing_staged(&mut stx, 1, 7);
        store::set_governance_revision(&mut stx, route.clone(), 1);
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Staged));
        assert_eq!(store::governance_revision(&*stx.world, &route), 1);
        assert_eq!(
            store::destination_words::get(&*stx.world, &evm(7).destination_word()),
            Some(&(NETWORK, 1))
        );
        let staged = store::routes::get(&*stx.world, &NETWORK)
            .and_then(|route| route.revisions.get(&1))
            .expect("revision");
        assert_eq!(staged.deployment, evm(7));
        assert_eq!(staged.destination_word, evm(7).destination_word());

        // Activation needs a usable light client; the failure leaves the caller to drop the
        // effect transaction.
        let activate = proposal(
            id,
            vec![(route.clone(), 1)],
            vec![SccpGovernanceActionV1::ActivateRevision(
                SccpRouteRevisionActionV1 {
                    network: NETWORK,
                    revision: 1,
                },
            )],
        );
        let error =
            enact(&mut stx, [0x43; 32], [0x45; 32], S0, &activate).expect_err("no light client");
        assert!(error.to_string().contains("light client"), "{error}");

        // Force the revision live to exercise the pause pair.
        registry::set_activation(&mut stx, NETWORK, 1, SccpRouteActivationV1::Bidirectional)
            .expect("live");
        let pause = proposal(
            id,
            vec![(route.clone(), 1), (control.clone(), 0)],
            vec![
                SccpGovernanceActionV1::SetTairaPaused(SccpSetTairaPausedActionV1 {
                    network: NETWORK,
                    paused: true,
                }),
                SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
                    network: NETWORK,
                    revision: 1,
                    paused: true,
                }),
            ],
        );
        enact(&mut stx, [0x43; 32], [0x45; 32], S0, &pause).expect("pause");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Paused));
        assert!(registry::destination_paused(&*stx.world, NETWORK, 1));
        assert_eq!(store::governance_revision(&*stx.world, &route), 2);
        assert_eq!(store::governance_revision(&*stx.world, &control), 1);
        assert_eq!(store::control_messages::len(&*stx.world), 1);
        // Ensure semantics: pausing again changes nothing and never fails.
        set_taira_paused(&mut stx, NETWORK, true).expect("ensure");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Paused));
        set_taira_paused(&mut stx, NETWORK, false).expect("resume");
        assert_eq!(
            activation(&stx, 1),
            Some(SccpRouteActivationV1::Bidirectional)
        );

        let error = enact(
            &mut stx,
            [0x43; 32],
            [0x45; 32],
            S0,
            &proposal(id, vec![(route.clone(), 2)], vec![register(5, 9)]),
        )
        .expect_err("revision gap");
        assert!(error.to_string().contains("next revision"), "{error}");
    }

    #[test]
    fn retirement_removal_and_switching_follow_their_rules() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        existing_staged(&mut stx, 1, 7);
        existing_staged(&mut stx, 2, 8);
        registry::set_activation(&mut stx, NETWORK, 1, SccpRouteActivationV1::Bidirectional)
            .expect("live");
        let revision = |revision| SccpRouteRevisionActionV1 {
            network: NETWORK,
            revision,
        };
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::SwitchRevision(SccpSwitchRevisionActionV1 {
                network: NETWORK,
                from: 1,
                to: 2,
            }),
            [2; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect("switch");
        assert_eq!(
            activation(&stx, 1),
            Some(SccpRouteActivationV1::InboundOnly)
        );
        assert_eq!(
            activation(&stx, 2),
            Some(SccpRouteActivationV1::Bidirectional)
        );

        store::set_pending_counts(&mut stx, (NETWORK, 1), (1, 0));
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RetireRevision(revision(1)),
            [3; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect_err("pending");
        store::set_pending_counts(&mut stx, (NETWORK, 1), (0, 0));
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RetireRevision(revision(1)),
            [3; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect("retire");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Retired));
        // A control for a retired revision is a successful no-op.
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::SetDestinationPaused(SccpSetDestinationPausedActionV1 {
                network: NETWORK,
                revision: 1,
                paused: true,
            }),
            [4; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect("no-op");
        assert_eq!(store::control_messages::len(&*stx.world), 0);

        existing_staged(&mut stx, 3, 9);
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RemoveStaged(revision(3)),
            [6; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect("remove");
        assert_eq!(activation(&stx, 3), None);
        assert!(store::destination_words::contains(
            &*stx.world,
            &evm(9).destination_word()
        ));
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RemoveStaged(revision(2)),
            [7; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect_err("live revisions cannot be removed");
    }

    #[test]
    fn profile_activation_is_enacted_under_the_light_client_subject() {
        use iroha_data_model::sccp::governance::SccpActivateLightClientProfileActionV1;
        let state = blank_state();
        let mut block = state.block(header(5));
        let subject = SccpGovernanceSubjectV1::LightClient(NETWORK);
        let activate = |version: u32| {
            SccpGovernanceActionV1::ActivateLightClientProfile(
                SccpActivateLightClientProfileActionV1 {
                    network: NETWORK,
                    version,
                    profile_hash: [3; 32],
                },
            )
        };
        {
            let mut stx = block.transaction();
            let id = stx.network_id;
            setup(&mut stx);
            let heads = subject_heads(&*stx.world, &proposal(id, vec![], vec![activate(2)]))
                .expect("heads")
                .1;
            assert_eq!(heads, vec![(subject.clone(), 0)]);
            // Version 1 is active from genesis: re-activating it is refused at enactment and
            // the light-client head does not move.
            let error = enact(
                &mut stx,
                [0x43; 32],
                [0x45; 32],
                S0,
                &proposal(id, vec![(subject.clone(), 0)], vec![activate(1)]),
            )
            .expect_err("not above version 1");
            assert!(error.to_string().contains("does not exceed"), "{error}");
            assert!(!stx.is_execution_deferred());
            assert_eq!(store::governance_revision(&*stx.world, &subject), 0);
        }
        {
            // This release compiles only version 1, so enacting version 2 fails closed: the
            // node refuses the block instead of recording what it cannot verify.
            let mut stx = block.transaction();
            let id = stx.network_id;
            setup(&mut stx);
            enact(
                &mut stx,
                [0x43; 32],
                [0x45; 32],
                S0,
                &proposal(id, vec![(subject.clone(), 0)], vec![activate(2)]),
            )
            .expect_err("version 2 is not compiled");
            assert!(stx.is_execution_deferred());
            assert!(store::light_client_profiles::is_empty(&*stx.world));
        }
    }

    #[test]
    fn enactment_checks_the_network_id_and_sccp() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        let proposal = sample_proposal(id);
        enact(&mut stx, [0x43; 32], [0x45; 32], S0, &proposal).expect_err("no SCCP");
        let mut foreign = proposal;
        foreign.network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new([9; 32])),
        );
        setup(&mut stx);
        let error =
            enact(&mut stx, [0x43; 32], [0x45; 32], S0, &foreign).expect_err("foreign network");
        assert!(error.to_string().contains("NetworkId"), "{error}");
    }

    #[test]
    fn set_parameters_validates_the_full_pinned_policy_before_writing() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        stx.nexus.staking.unbonding_delay = std::time::Duration::from_secs(21 * 86_400);
        stx.nexus.staking.max_slash_bps = 1;
        let mut consensus = stx.world.parameters.get().sumeragi().clone();
        consensus.epoch_length_blocks = std::num::NonZeroU64::new(3_600).expect("epoch");
        consensus.block_cadence_ms = std::num::NonZeroU64::new(1_000).expect("cadence");
        stx.world.parameters.get_mut().set_sumeragi(consensus);
        let original = *store::parameters::get(&*stx.world);
        let mut next = original.expect("original parameters");
        next.enabled = false;
        let action = SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 { next });
        stx.nexus.staking.unbonding_delay -= std::time::Duration::from_millis(1);
        let error = apply_action(
            &mut stx,
            &action,
            [7; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect_err("short delay");
        assert!(error.to_string().contains("unbonding_delay"), "{error}");
        assert_eq!(*store::parameters::get(&*stx.world), original);
        stx.nexus.staking.unbonding_delay += std::time::Duration::from_millis(1);
        apply_action(
            &mut stx,
            &action,
            [7; 32],
            controls::ControlCauseV1::for_test([0x43; 32], [0x45; 32]),
            S0,
        )
        .expect("valid complete parameters");
        assert_eq!(*store::parameters::get(&*stx.world), Some(next));
    }

    #[test]
    fn enactment_rejects_empty_parliament_bindings_before_effects() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        existing_staged(&mut stx, 1, 7);
        let proposal = proposal(
            stx.network_id,
            vec![(SccpGovernanceSubjectV1::RouteControl(NETWORK), 0)],
            vec![SccpGovernanceActionV1::SetDestinationPaused(
                SccpSetDestinationPausedActionV1 {
                    network: NETWORK,
                    revision: 1,
                    paused: true,
                },
            )],
        );
        let original = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
        for (certificate_id, effect_hash) in [([0; 32], [0x45; 32]), ([0x43; 32], [0; 32])] {
            let error = enact(&mut stx, certificate_id, effect_hash, S0, &proposal)
                .expect_err("invalid cause");
            assert!(error.to_string().contains("binding is zero"), "{error}");
            assert_eq!(store::routes::get(&*stx.world, &NETWORK), Some(&original));
            assert!(store::control_messages::is_empty(&*stx.world));
            assert_eq!(
                store::governance_revision(
                    &*stx.world,
                    &SccpGovernanceSubjectV1::RouteControl(NETWORK)
                ),
                0
            );
        }
    }
}

#[cfg(test)]
pub(crate) use registration::reference_pin_rows;
