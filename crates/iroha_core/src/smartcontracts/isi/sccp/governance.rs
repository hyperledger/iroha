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

use super::{
    Error, controls, escrow, light_clients,
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
            SccpClearBridgeKeyFaultActionV1, SccpGovernanceActionV1, SccpGovernanceProposalV1,
            SccpGovernanceSubjectV1, SccpRegisterRouteActionV1, SccpReleaseStrandedActionV1,
            SccpRouteRevisionActionV1, SccpSwitchRevisionActionV1,
        },
        registry::{SccpRouteActivationV1, SccpRouteRevisionV1},
    },
};
use iroha_sccp::v1::{
    constants::TON_AMOUNT_BOUND,
    roster::RosterV1,
    ton_cell::{TonMinterInitV1, minter_account_id},
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
///
/// # Errors
///
/// Fails on the first action whose precondition does not hold; the caller drops the effect
/// transaction.
pub fn enact(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal: &SccpGovernanceProposalV1,
    proposal_id: [u8; 32],
) -> Result<(), Error> {
    if proposal.network_id != *state_transaction.network_id() {
        return Err(refuse("the proposal belongs to a different NetworkId"));
    }
    if store::parameters::get(&*state_transaction.world).is_none() {
        return Err(refuse("SCCP does not exist on this network"));
    }
    for (index, action) in proposal.actions.iter().enumerate() {
        apply_action(state_transaction, action, proposal_id)
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
) -> Result<(), Error> {
    match action {
        SccpGovernanceActionV1::RegisterRoute(register) => {
            register_route(state_transaction, register)
        }
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
                controls::record_control(
                    state_transaction,
                    action.network,
                    action.revision,
                    action.paused,
                    proposal_id,
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
            action
                .next
                .validate()
                .map_err(|error| refuse(format_args!("parameters: {error}")))?;
            store::parameters::set(state_transaction, Some(action.next.clone()));
            Ok(())
        }
        SccpGovernanceActionV1::ClearBridgeKeyFault(action) => {
            clear_bridge_key_fault(state_transaction, action)
        }
        SccpGovernanceActionV1::ActivateLightClientProfile(action) => {
            light_clients::activate_profile(state_transaction, action, proposal_id)
        }
    }
}

/// Check that generation `generation` can pin a new deployment at `now_ms` and return it as
/// the `iroha_sccp` roster with its stored digest (§4.14.3 `RegisterRoute`).
fn pinnable_generation(
    world: &(impl WorldReadOnly + ?Sized),
    generation: u64,
    now_ms: u64,
    roster_max_age_ms: u64,
) -> Result<(RosterV1, [u8; 32]), Error> {
    let roster = store::rosters::get(world, &generation)
        .ok_or_else(|| refuse(format_args!("generation {generation} does not exist")))?;
    if roster.is_inert() {
        return Err(refuse(format_args!("generation {generation} is inert")));
    }
    if roster.valid_until_ms <= now_ms.saturating_add(roster_max_age_ms) {
        return Err(refuse(format_args!(
            "generation {generation} expires too soon to rotate"
        )));
    }
    // Every handoff from the pinned generation to the current one must be attested, so the
    // deployment can be rotated forward to the signing generation.
    let current = *store::roster_current::get(world);
    for successor in generation..current {
        let handoff = store::rosters::get(world, &successor)
            .and_then(|roster| roster.handoff_height)
            .ok_or_else(|| refuse(format_args!("generation {successor} has no handoff")))?;
        let attested = store::attestation_status::get(world, &handoff)
            .is_some_and(|status| status.attested_at_height.is_some());
        if !attested {
            return Err(refuse(format_args!(
                "the handoff subject {handoff} of generation {successor} is unattested"
            )));
        }
    }
    Ok((
        RosterV1 {
            generation,
            valid_from_ms: roster.valid_from_ms,
            valid_until_ms: roster.valid_until_ms,
            members: roster.members.iter().map(|member| member.address).collect(),
        },
        roster.digest,
    ))
}

fn register_route(
    state_transaction: &mut StateTransaction<'_, '_>,
    register: &SccpRegisterRouteActionV1,
) -> Result<(), Error> {
    let network = register.network;
    let world = &*state_transaction.world;
    let roster_max_age_ms = store::parameters::get(world)
        .as_ref()
        .map(|params| params.roster_max_age_ms)
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    let mut route = store::routes::get(world, &network)
        .cloned()
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
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let (roster, digest) = pinnable_generation(
        world,
        register.initial_roster_generation,
        now_ms,
        roster_max_age_ms,
    )?;
    if let SccpDeploymentV1::Ton(ton) = &register.deployment {
        let init = TonMinterInitV1 {
            taira_network_id: *state_transaction.network_id().as_bytes(),
            route_revision: register.revision,
            max_supply: cap,
            roster,
            wallet_code: ton.wallet_code,
            bucket_code: ton.bucket_code,
        };
        let expected = minter_account_id(&init, ton.minter_code)
            .map_err(|error| refuse(format_args!("TON minter address: {error}")))?;
        if expected != ton.master_account {
            return Err(refuse(
                "the TON master account is not the canonical minter address",
            ));
        }
    }
    let height = state_transaction._curr_block.height().get();
    let word = register.deployment.destination_word();
    route.revisions.insert(
        register.revision,
        SccpRouteRevisionV1::staged(
            register.revision,
            register.deployment.clone(),
            cap,
            register.initial_roster_generation,
            digest,
            height,
        ),
    );
    store::routes::insert(state_transaction, network, route)?;
    store::destination_words::insert(state_transaction, word, (network, register.revision))?;
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

fn clear_bridge_key_fault(
    state_transaction: &mut StateTransaction<'_, '_>,
    action: &SccpClearBridgeKeyFaultActionV1,
) -> Result<(), Error> {
    let mut state = store::bridge_keys::get(&*state_transaction.world, &action.peer)
        .cloned()
        .ok_or_else(|| refuse("the peer has no bridge-key state"))?;
    if state.barred != Some(action.fault) {
        return Err(refuse("the peer's newest fault is not the named one"));
    }
    state.barred = None;
    store::bridge_keys::insert(state_transaction, action.peer.clone(), state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        blank_state, header, peer, sample_bridge_key_state, sample_proposal, sample_roster,
    };
    use iroha_data_model::sccp::{
        deployment::SccpEvmDeploymentV1,
        governance::{
            SccpSetDestinationPausedActionV1, SccpSetParametersActionV1, SccpSetTairaPausedActionV1,
        },
        keys::SccpFaultRefV1,
        params::SccpParametersV1,
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
            max_wrapped_supply: 1_000_000_000_000,
            initial_roster_generation: 1,
        })
    }

    /// Initialize SCCP with generation 1 current.
    fn setup(stx: &mut StateTransaction<'_, '_>) {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
        store::rosters::insert(stx, 1, sample_roster(1, 1)).expect("roster");
        store::roster_current::set(stx, 1);
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
        preflight_attempt(&stx, &fresh).expect("fresh");
        store::destination_words::insert(&mut stx, evm(7).destination_word(), (NETWORK, 9))
            .expect("word");
        preflight_attempt(&stx, &fresh).expect_err("word taken");
        let other = proposal(id, vec![(route.clone(), 0)], vec![register(1, 8)]);
        store::set_governance_revision(&mut stx, route, 1);
        let error = preflight_attempt(&stx, &other).expect_err("stale");
        assert!(error.to_string().contains("stale"), "{error}");
    }

    #[test]
    fn enactment_registers_activates_pauses_and_counts_revisions() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        let control = SccpGovernanceSubjectV1::RouteControl(NETWORK);
        let bring_up = proposal(id, vec![(route.clone(), 0)], vec![register(1, 7)]);
        enact(&mut stx, &bring_up, [1; 32]).expect("register");
        assert_eq!(activation(&stx, 1), Some(SccpRouteActivationV1::Staged));
        assert_eq!(store::governance_revision(&*stx.world, &route), 1);
        assert_eq!(
            store::destination_words::get(&*stx.world, &evm(7).destination_word()),
            Some(&(NETWORK, 1))
        );
        let staged = store::routes::get(&*stx.world, &NETWORK)
            .and_then(|route| route.revisions.get(&1))
            .expect("revision");
        assert_eq!(staged.initial_roster_digest, sample_roster(1, 1).digest);

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
        let error = enact(&mut stx, &activate, [2; 32]).expect_err("no light client");
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
        enact(&mut stx, &pause, [3; 32]).expect("pause");
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
            &proposal(id, vec![(route.clone(), 2)], vec![register(5, 9)]),
            [4; 32],
        )
        .expect_err("revision gap");
        assert!(error.to_string().contains("next revision"), "{error}");
    }

    #[test]
    fn retirement_removal_and_switching_follow_their_rules() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let id = stx.network_id;
        setup(&mut stx);
        let route = SccpGovernanceSubjectV1::Route(NETWORK);
        enact(
            &mut stx,
            &proposal(
                id,
                vec![(route.clone(), 0)],
                vec![register(1, 7), register(2, 8)],
            ),
            [1; 32],
        )
        .expect("register two");
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
        )
        .expect_err("pending");
        store::set_pending_counts(&mut stx, (NETWORK, 1), (0, 0));
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RetireRevision(revision(1)),
            [3; 32],
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
        )
        .expect("no-op");
        assert_eq!(store::control_messages::len(&*stx.world), 0);

        enact(
            &mut stx,
            &proposal(id, vec![(route.clone(), 1)], vec![register(3, 9)]),
            [5; 32],
        )
        .expect("register third");
        apply_action(
            &mut stx,
            &SccpGovernanceActionV1::RemoveStaged(revision(3)),
            [6; 32],
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
        )
        .expect_err("live revisions cannot be removed");
    }

    #[test]
    fn bridge_key_faults_clear_only_by_name() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        setup(&mut stx);
        let fault = SccpFaultRefV1 {
            address: [4; 20],
            height: 3,
        };
        let mut key_state = sample_bridge_key_state(1);
        key_state.barred = Some(SccpFaultRefV1 {
            address: [4; 20],
            height: 4,
        });
        store::bridge_keys::insert(&mut stx, peer(1), key_state).expect("state");
        let action = SccpGovernanceActionV1::ClearBridgeKeyFault(SccpClearBridgeKeyFaultActionV1 {
            peer: peer(1),
            fault,
        });
        apply_action(&mut stx, &action, [1; 32]).expect_err("a newer fault");
        let mut key_state = store::bridge_keys::get(&*stx.world, &peer(1))
            .cloned()
            .expect("state");
        key_state.barred = Some(fault);
        store::bridge_keys::insert(&mut stx, peer(1), key_state).expect("state");
        apply_action(&mut stx, &action, [1; 32]).expect("clear");
        assert_eq!(
            store::bridge_keys::get(&*stx.world, &peer(1))
                .expect("state")
                .barred,
            None
        );
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
                &proposal(id, vec![(subject.clone(), 0)], vec![activate(1)]),
                [1; 32],
            )
            .expect_err("not above version 1");
            assert!(error.to_string().contains("does not exceed"), "{error}");
            assert!(stx.execution_deferral().is_none());
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
                &proposal(id, vec![(subject.clone(), 0)], vec![activate(2)]),
                [2; 32],
            )
            .expect_err("version 2 is not compiled");
            assert!(stx.execution_deferral().is_some());
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
        enact(&mut stx, &proposal, [1; 32]).expect_err("no SCCP");
        let mut foreign = proposal;
        foreign.network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new([9; 32])),
        );
        setup(&mut stx);
        let error = enact(&mut stx, &foreign, [1; 32]).expect_err("foreign network");
        assert!(error.to_string().contains("NetworkId"), "{error}");
    }
}
