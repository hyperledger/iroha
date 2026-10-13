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
//!
//! `RegisterRoute` is fail-closed ([`register_route`]): no route is registered before the launch
//! gate opens (§10.2).

use super::{
    Error, controls, escrow, init, light_clients, parliament_iface,
    recipients::{self, SccpRecipientClassV1},
    registry, store,
};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        deployment::SccpDeploymentV1,
        events::{SccpEvent, SccpGovernanceEnactedV1, SccpStrandedReleasedV1},
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
            SccpRegisterRouteActionV1, SccpReleaseStrandedActionV1, SccpRouteRevisionActionV1,
            SccpSwitchRevisionActionV1,
        },
        registry::SccpRouteActivationV1,
    },
};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP governance: {reason}").into())
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
    let heads: Vec<_> = proposal
        .subjects()
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
    for base in &proposal.base_revisions {
        let current = store::governance_revision(world, &base.subject);
        if current != base.revision {
            return Err(refuse(format_args!(
                "stale proposal: subject {:?} is at revision {current}, not {}",
                base.subject, base.revision
            )));
        }
    }
    for action in &proposal.actions {
        if let SccpGovernanceActionV1::RegisterRoute(register) = action {
            ensure_word_unused(world, &register.deployment)?;
        }
    }
    Ok(())
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
/// The authenticated World owner derives `cause` from the exact due certificate. This
/// function receives no substitute certificate or independent verification authority.
///
/// TODO: the current Parliament reducer must carry its actual Policy Jury casting-open
/// anchor through the shared millisecond pass before the §4.14.7 selective lift can run.
/// The current recorder preserves any active fast-pause part; it does not fabricate s0.
///
/// # Errors
///
/// Fails on the first action whose precondition does not hold; the caller drops the effect
/// transaction.
pub fn enact(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal: &SccpGovernanceProposalV1,
    proposal_id: [u8; 32],
    cause: controls::ControlCauseV1,
) -> Result<(), Error> {
    if proposal.network_id != *state_transaction.network_id() {
        return Err(refuse("the proposal belongs to a different NetworkId"));
    }
    if store::parameters::get(&*state_transaction.world).is_none() {
        return Err(refuse("SCCP does not exist on this network"));
    }
    if cause.track != iroha_sccp::v1::control::TRACK_PARLIAMENT
        || cause.certificate_id == [0; 32]
        || cause.effect_hash == [0; 32]
    {
        return Err(refuse("the enacted Parliament cause is malformed"));
    }
    for (index, action) in proposal.actions.iter().enumerate() {
        apply_action(state_transaction, action, proposal_id, cause)
            .map_err(|error| refuse(format_args!("action {index}: {error}")))?;
    }
    let subjects = proposal.subjects();
    for subject in &subjects {
        let next = store::governance_revision(&*state_transaction.world, subject)
            .checked_add(1)
            .ok_or_else(|| refuse("a subject revision overflows"))?;
        store::set_governance_revision(state_transaction, *subject, next);
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
) -> Result<(), Error> {
    match action {
        SccpGovernanceActionV1::RegisterRoute(register) => register_route(register),
        SccpGovernanceActionV1::ActivateRevision(action) => {
            activate_revision(state_transaction, action)
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
            retire_revision(state_transaction, action)
        }
        SccpGovernanceActionV1::RemoveStaged(action) => remove_staged(state_transaction, action),
        SccpGovernanceActionV1::ReleaseStranded(action) => {
            release_stranded(state_transaction, action, proposal_id)
        }
        SccpGovernanceActionV1::SetTairaPaused(action) => {
            set_taira_paused(state_transaction, action.network, action.paused)
        }
        SccpGovernanceActionV1::SetDestinationPaused(action) => {
            let recordable = store::routes::get(&*state_transaction.world, &action.network)
                .and_then(|route| route.revisions.get(&action.revision))
                .is_some_and(|revision| revision.activation != SccpRouteActivationV1::Retired);
            // A revision retired or removed since the proposal has nothing left to mint.
            if recordable {
                // Parliament owns its flag. The recorder observes the resulting complete
                // state and preserves any independent active fast-pause destination part.
                let mut route = store::routes::get(&*state_transaction.world, &action.network)
                    .cloned()
                    .ok_or_else(|| refuse("the recordable route disappeared"))?;
                route
                    .revisions
                    .get_mut(&action.revision)
                    .ok_or_else(|| refuse("the recordable revision disappeared"))?
                    .destination_paused = action.paused;
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
        SccpGovernanceActionV1::SetParameters(action) => {
            init::check_parameters(state_transaction, &action.next)
                .map_err(|error| refuse(format_args!("parameters: {error}")))?;
            store::parameters::set(state_transaction, Some(action.next));
            Ok(())
        }
        SccpGovernanceActionV1::ActivateLightClientProfile(action) => {
            light_clients::activate_profile(state_transaction, action, proposal_id)
        }
    }
}

/// Refuse `RegisterRoute` (§4.14.3): the action is fail-closed.
///
/// P0: the launch gate of §10.2 is closed while
/// [`parliament_iface::parliament_binding_ballot_available`] is false, so no route is
/// registered and the registry keeps the empty routes of genesis. The rules that follow P0 bind
/// the deployment to a committee generation (P1, P2, P5) and recompute its address from that
/// pin (P3, P4); these authenticated enactment checks remain incomplete, so an open gate
/// alone does not make the action enactable either.
///
/// TODO: WP-S4: authenticate the required `initial_committee` and enact registration under
/// P1–P5 with the revision, destination-word and supply-cap rules.
///
/// TODO: WP-S9: the launch gate also needs `sccp_reconciliation_available()` (§10.2).
fn register_route(register: &SccpRegisterRouteActionV1) -> Result<(), Error> {
    let route = register.network.profile_key();
    let revision = register.revision;
    if !parliament_iface::parliament_binding_ballot_available() {
        return Err(refuse(format_args!(
            "RegisterRoute of {route} revision {revision}: the launch gate is closed until the \
             Parliament's binding ballot is available"
        )));
    }
    Err(refuse(format_args!(
        "RegisterRoute of {route} revision {revision}: authenticated committee pin and deployment checks are incomplete"
    )))
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
    action: &SccpRouteRevisionActionV1,
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
    action: &SccpRouteRevisionActionV1,
) -> Result<(), Error> {
    let world = &*state_transaction.world;
    let liability = store::routes::get(world, &action.network)
        .and_then(|route| route.revisions.get(&action.revision))
        .map(|record| record.liability)
        .ok_or_else(|| refuse(format_args!("revision {} does not exist", action.revision)))?;
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
    action: &SccpRouteRevisionActionV1,
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
        blank_state, effect_cause, header, sample_proposal, set_sccp_staking_profile,
    };
    use iroha_data_model::sccp::{
        deployment::SccpEvmDeploymentV1,
        governance::{
            SccpSetDestinationPausedActionV1, SccpSetParametersActionV1, SccpSetTairaPausedActionV1,
        },
        params::SccpParametersV1,
        registry::SccpRouteRevisionV1,
    };

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
            initial_committee: iroha_data_model::sccp::deployment::SccpCommitteePinV1 {
                generation: 1,
                committee_root: [0x44; 32],
                start_height: 1,
                until_ms: 1_801_209_600_000,
            },
            max_wrapped_supply: 1_000_000_000_000,
        })
    }

    /// Initialize SCCP as genesis does: the parameters and the empty routes.
    fn setup(stx: &mut StateTransaction<'_, '_>) {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
    }

    /// Seed revision `revision` as a registration leaves it: `Staged`, with its destination
    /// word reserved. Enacting `RegisterRoute` is fail-closed, so tests seed the revision.
    fn stage(stx: &mut StateTransaction<'_, '_>, revision: u32, seed: u8) {
        let deployment = evm(seed);
        let word = deployment.destination_word();
        let mut route = store::routes::get(&*stx.world, &NETWORK)
            .cloned()
            .expect("route");
        route.revisions.insert(
            revision,
            SccpRouteRevisionV1::staged(
                revision,
                deployment,
                iroha_data_model::sccp::deployment::SccpCommitteePinV1 {
                    generation: 1,
                    committee_root: [0x44; 32],
                    start_height: 1,
                    until_ms: 1_801_209_600_000,
                },
                1_000_000_000_000,
                5,
            ),
        );
        store::routes::insert(stx, NETWORK, route).expect("route");
        store::destination_words::insert(stx, word, (NETWORK, revision)).expect("word");
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
        let fresh = proposal(id, vec![(route, 0)], vec![register(1, 7)]);
        preflight_attempt(&stx, &fresh).expect("fresh");
        store::destination_words::insert(&mut stx, evm(7).destination_word(), (NETWORK, 9))
            .expect("word");
        preflight_attempt(&stx, &fresh).expect_err("word taken");
        let other = proposal(id, vec![(route, 0)], vec![register(1, 8)]);
        store::set_governance_revision(&mut stx, route, 1);
        let error = preflight_attempt(&stx, &other).expect_err("stale");
        assert!(error.to_string().contains("stale"), "{error}");
    }

    #[test]
    fn register_route_is_fail_closed_while_the_launch_gate_is_closed() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        assert!(!parliament_iface::parliament_binding_ballot_available());
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let bring_up = proposal(id, vec![(route, 0)], vec![register(1, 7)]);
        preflight_attempt(&stx, &bring_up).expect("the attempt preflight does not read the gate");
        let error = enact(&mut stx, &bring_up, [1; 32], effect_cause())
            .expect_err("the launch gate is closed");
        assert!(error.to_string().contains("launch gate"), "{error}");
        assert_eq!(activation(&stx, 1), None, "no revision is registered");
        assert!(store::destination_words::is_empty(&*stx.world));
        assert_eq!(store::governance_revision(&*stx.world, &route), 0);
        // The refusal reads no state: every network and revision is refused alike.
        for (network, revision) in [
            (SccpNetworkV1::BscMainnet, 1),
            (SccpNetworkV1::TonMainnet, 9),
        ] {
            let SccpGovernanceActionV1::RegisterRoute(mut action) = register(revision, 8) else {
                unreachable!("register builds a RegisterRoute action")
            };
            action.network = network;
            let error = register_route(&action).expect_err("fail-closed");
            assert!(error.to_string().contains("launch gate"), "{error}");
        }
    }

    #[test]
    fn enactment_activates_pauses_and_counts_revisions() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let control = SccpGovernanceSubjectV1::RouteControl(NETWORK);
        stage(&mut stx, 1, 7);
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Staged));

        // Activation needs a usable light client; the failure leaves the caller to drop the
        // effect transaction.
        let activate = proposal(
            id,
            vec![(route, 0)],
            vec![SccpGovernanceActionV1::ActivateRevision(
                SccpRouteRevisionActionV1 {
                    network: NETWORK,
                    revision: 1,
                },
            )],
        );
        let error =
            enact(&mut stx, &activate, [2; 32], effect_cause()).expect_err("no light client");
        assert!(error.to_string().contains("light client"), "{error}");
        assert_eq!(store::governance_revision(&*stx.world, &route), 0);

        // Force the revision live to exercise the pause pair.
        registry::set_activation(&mut stx, NETWORK, 1, SccpRouteActivationV1::Bidirectional)
            .expect("live");
        let pause = proposal(
            id,
            vec![(route, 0), (control, 0)],
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
        enact(&mut stx, &pause, [3; 32], effect_cause()).expect("pause");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Paused));
        assert!(registry::destination_paused(&*stx.world, NETWORK, 1));
        assert_eq!(store::governance_revision(&*stx.world, &route), 1);
        assert_eq!(store::governance_revision(&*stx.world, &control), 1);
        assert_eq!(store::control_messages::len(&*stx.world), 1);
        let recorded = store::control_messages::get(&*stx.world, &(NETWORK, 1, 1)).unwrap();
        let cause = effect_cause();
        assert_eq!(recorded.track, 1);
        assert_eq!(recorded.certificate_id, cause.certificate_id);
        assert_ne!(
            recorded.certificate_id, [3; 32],
            "the proposal id is not the certificate id"
        );
        assert_eq!(recorded.effect_hash, cause.effect_hash);
        assert!(recorded.parliament_paused);
        // Ensure semantics: pausing again changes nothing and never fails.
        set_taira_paused(&mut stx, NETWORK, true).expect("ensure");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Paused));
        set_taira_paused(&mut stx, NETWORK, false).expect("resume");
        assert_eq!(
            activation(&stx, 1),
            Some(SccpRouteActivationV1::Bidirectional)
        );
    }

    #[test]
    fn set_parameters_checks_the_whole_table_against_the_new_value() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        let set = |next| SccpGovernanceActionV1::SetParameters(SccpSetParametersActionV1 { next });
        let mut next = SccpParametersV1::taira_default();
        next.outbound_ttl_ms = 2 * 86_400_000;
        // L1: without the staking profile the node policy does not cover the liability window.
        let error = apply_action(&mut stx, &set(next), [1; 32], effect_cause()).expect_err("L1");
        assert!(error.to_string().contains("unbonding_delay_ms"), "{error}");
        set_sccp_staking_profile(&mut stx);
        apply_action(&mut stx, &set(next), [1; 32], effect_cause()).expect("a valid table");
        assert_eq!(*store::parameters::get(&*stx.world), Some(next));
        // An own bound, a joint rule and the staking floor each refuse, and the stored value
        // stays.
        let mut dust = next;
        dust.min_outbound_amount = 0;
        let mut short_validity = next;
        short_validity.committee_validity_ms = short_validity.fast_pause_hold_ms;
        let mut long_grace = next;
        long_grace.forgery_evidence_grace_ms += 1;
        for (invalid, field) in [
            (dust, "min_outbound_amount"),
            (short_validity, "committee_validity_ms"),
            (long_grace, "unbonding_delay_ms"),
        ] {
            let error =
                apply_action(&mut stx, &set(invalid), [2; 32], effect_cause()).expect_err(field);
            assert!(error.to_string().contains(field), "{error}");
            assert_eq!(*store::parameters::get(&*stx.world), Some(next));
        }
    }

    #[test]
    fn retirement_removal_and_switching_follow_their_rules() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        stage(&mut stx, 1, 7);
        stage(&mut stx, 2, 8);
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
            effect_cause(),
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
            effect_cause(),
        )
        .expect_err("pending");
        store::set_pending_counts(&mut stx, (NETWORK, 1), (0, 0));
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RetireRevision(revision(1)),
            [3; 32],
            effect_cause(),
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
            effect_cause(),
        )
        .expect("no-op");
        assert_eq!(store::control_messages::len(&*stx.world), 0);

        stage(&mut stx, 3, 9);
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RemoveStaged(revision(3)),
            [6; 32],
            effect_cause(),
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
            effect_cause(),
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
            assert_eq!(heads, vec![(subject, 0)]);
            // Version 1 is active from genesis: re-activating it is refused at enactment and
            // the light-client head does not move.
            let error = enact(
                &mut stx,
                &proposal(id, vec![(subject, 0)], vec![activate(1)]),
                [1; 32],
                effect_cause(),
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
                &proposal(id, vec![(subject, 0)], vec![activate(2)]),
                [2; 32],
                effect_cause(),
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
        enact(&mut stx, &proposal, [1; 32], effect_cause()).expect_err("no SCCP");
        let mut foreign = proposal;
        foreign.network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new([9; 32])),
        );
        setup(&mut stx);
        let error =
            enact(&mut stx, &foreign, [1; 32], effect_cause()).expect_err("foreign network");
        assert!(error.to_string().contains("NetworkId"), "{error}");
    }

    #[test]
    fn enactment_rejects_non_parliament_or_empty_cause_before_effects() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        stage(&mut stx, 1, 7);
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
        for cause in [
            controls::ControlCauseV1 {
                track: 2,
                ..effect_cause()
            },
            controls::ControlCauseV1 {
                track: 0,
                ..effect_cause()
            },
            controls::ControlCauseV1 {
                certificate_id: [0; 32],
                ..effect_cause()
            },
            controls::ControlCauseV1 {
                effect_hash: [0; 32],
                ..effect_cause()
            },
        ] {
            let error = enact(&mut stx, &proposal, [8; 32], cause).expect_err("invalid cause");
            assert!(error.to_string().contains("Parliament cause"), "{error}");
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
