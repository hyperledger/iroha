//! Authenticated preparation of immutable future validator committees.

use super::{
    BlockHashRead, GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, StateBlock, StateReadOnly,
    StateTransaction, WorldReadOnly, public_lane_validator_record_matches_key,
};
use crate::beacon::{
    GlobalThresholdBeaconSessionBindingV1,
    authenticated_global_threshold_beacon_roster_hash_iter_v1,
    authenticated_global_threshold_beacon_roster_hash_v1,
    seat_readiness::verify_global_threshold_beacon_seat_readiness_v1,
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use iroha_data_model::sumeragi::epoch::{
    BeaconEpochBindingV1, ValidatorEpochAuthorizationV1, ValidatorEpochDecisionV1,
    ValidatorGenerationV1,
};
use iroha_data_model::{
    account::AccountId,
    nexus::{ValidatorCommitteeOperationV1, ValidatorCommitteeTransitionV1},
};
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use mv::storage::StorageReadOnly;

#[cfg(test)]
#[path = "validator_committee/tests.rs"]
pub(crate) mod tests;

/// A requested exit cannot release either a current seat or an immutable future seat.
#[expect(
    single_use_lifetimes,
    reason = "stable Rust requires a named reference lifetime in the iterator item"
)]
pub(crate) fn peer_has_committee_obligation<'a>(
    world: &impl WorldReadOnly,
    current: impl IntoIterator<Item = &'a PeerId>,
    peer: &PeerId,
) -> bool {
    current.into_iter().any(|seat| seat == peer)
        || world
            .validator_committee_transitions()
            .iter()
            .any(|(_, transition)| {
                transition.outcome.is_none()
                    && transition
                        .preparation
                        .committee
                        .iter()
                        .any(|seat| &seat.validator == peer)
            })
}

struct StakingBoundaryUpdates {
    validators: Vec<(
        (LaneId, AccountId),
        iroha_data_model::nexus::PublicLaneValidatorRecord,
    )>,
    shares: Vec<(
        (LaneId, AccountId, AccountId),
        iroha_data_model::nexus::PublicLaneStakeShare,
    )>,
}

/// Compute all custody extensions before publishing any part of a committee decision.
fn prepare_staking_obligations(
    world: &impl WorldReadOnly,
    boundary: &iroha_data_model::sumeragi::epoch::ValidatorEpochBoundaryV1,
) -> Result<StakingBoundaryUpdates, Attempt<String>> {
    let mut updates = StakingBoundaryUpdates {
        validators: Vec::new(),
        shares: Vec::new(),
    };
    if boundary.next.mode != iroha_data_model::parameter::system::ConsensusMode::Npos {
        return Ok(updates);
    }
    let parameters = world
        .sumeragi_npos_parameters()?
        .ok_or("staking boundary lacks signed NPoS parameters")?;
    let outcome = &boundary.next.authorization;
    let mut obligations = std::collections::BTreeMap::<PeerId, u64>::new();
    for seat in &boundary.next.committee {
        obligations.insert(seat.validator.clone(), outcome.last_height);
    }
    for preparation in world
        .validator_committee_transitions()
        .iter()
        .filter(|(epoch, transition)| **epoch != outcome.epoch && transition.outcome.is_none())
        .map(|(_, transition)| &transition.preparation)
        .chain(boundary.preparation.iter())
    {
        for seat in &preparation.committee {
            let through = obligations.entry(seat.validator.clone()).or_default();
            *through = (*through).max(preparation.last_height);
        }
    }
    for (key, record) in world
        .public_lane_validators()
        .iter()
        .filter(|(key, _)| key.0 == LaneId::SINGLE)
    {
        if !public_lane_validator_record_matches_key(key, record) {
            return Err(("committee custody has a noncanonical validator owner".to_owned()).into());
        }
        let through = obligations.get(&record.peer_id).copied();
        if let Some(through) = through {
            if record.deactivation_height.is_some_and(|end| end <= through) {
                return Err(
                    ("committee decision retains an already ended validator tenure".to_owned())
                        .into(),
                );
            }
            let release = through
                .checked_add(parameters.evidence_horizon_blocks())
                .and_then(|height| height.checked_add(parameters.slashing_delay_blocks()))
                .ok_or("committee custody liability height overflows")?;
            for (share_key, share) in world
                .public_lane_stake_shares()
                .iter()
                .filter(|(share_key, _)| share_key.0 == key.0 && share_key.1 == key.1)
            {
                let mut retained = share.clone();
                for pending in retained.pending_unbonds.values_mut() {
                    pending.slashable_through_height =
                        pending.slashable_through_height.max(through);
                    pending.liability_release_height =
                        pending.liability_release_height.max(release);
                }
                if &retained != share {
                    updates.shares.push((share_key.clone(), retained));
                }
            }
        } else if let Some(requested) = record.election_exit_height {
            if record.deactivation_height.is_none() && requested <= outcome.first_height {
                let mut ended = record.clone();
                ended.deactivation_height = Some(
                    outcome
                        .first_height
                        .max(requested)
                        .max(record.activation_height),
                );
                updates.validators.push((key.clone(), ended));
            }
        }
    }
    Ok(updates)
}

fn add_obligations(
    obligations: &mut std::collections::BTreeMap<PeerId, u64>,
    peers: impl IntoIterator<Item = PeerId>,
    through: u64,
) {
    for peer in peers {
        let retained = obligations.entry(peer).or_default();
        *retained = (*retained).max(through);
    }
}

/// Snapshot metadata cannot shorten stake liability proved by retained committee history.
fn validate_retained_staking_obligations(
    world: &impl WorldReadOnly,
    historical: &std::collections::BTreeMap<PeerId, u64>,
    live: &std::collections::BTreeMap<PeerId, u64>,
) -> Result<(), String> {
    let mut covered = std::collections::BTreeSet::new();
    for (key, record) in world
        .public_lane_validators()
        .iter()
        .filter(|(key, _)| key.0 == LaneId::SINGLE)
    {
        if !public_lane_validator_record_matches_key(key, record) {
            return Err(
                "retained committee custody has a substituted validator identity".to_owned(),
            );
        }
        if let Some(through) = live.get(&record.peer_id) {
            if !covered.insert(record.peer_id.clone())
                || record
                    .deactivation_height
                    .is_some_and(|end| end <= *through)
            {
                return Err(
                    "snapshot revokes or duplicates a retained committee obligation".to_owned(),
                );
            }
        }
        let Some(through) = historical
            .get(&record.peer_id)
            .copied()
            .filter(|height| *height >= record.activation_height)
        else {
            continue;
        };
        for (_, share) in world
            .public_lane_stake_shares()
            .iter()
            .filter(|(share_key, _)| share_key.0 == key.0 && share_key.1 == key.1)
        {
            if share.pending_unbonds.values().any(|pending| {
                pending.slashable_through_height < through
                    || pending.liability_release_height < pending.slashable_through_height
            }) {
                return Err("snapshot shortens pending stake liability below authenticated committee service".to_owned());
            }
        }
    }
    if live.keys().any(|peer| !covered.contains(peer)) {
        return Err("snapshot omits the owner of a current or frozen committee seat".to_owned());
    }
    Ok(())
}

/// Check every persisted preparation, including exact storage identities.
pub(crate) fn validate_persisted_progress(world: &impl WorldReadOnly) -> Result<(), String> {
    for (epoch, transition) in world.validator_committee_transitions().iter() {
        if *epoch != transition.preparation.target_epoch {
            return Err("committee snapshot key differs from its exact target epoch".to_owned());
        }
        verify_progress(world, transition)?;
    }
    Ok(())
}

/// Match the currently effective authorization to the exact persisted signing session.
fn validate_current_beacon(
    world: &impl WorldReadOnly,
    authority: &ValidatorGenerationV1,
    authorization: &ValidatorEpochAuthorizationV1,
    committed_height: u64,
) -> Result<(), String> {
    authorization
        .validate_against_generation(authority)
        .map_err(|error| error.to_string())?;
    let active = world.active_global_beacon_key_session();
    let (session_id, transcript_hash, latest_activation) = match authorization.beacon {
        BeaconEpochBindingV1::Installed(binding) => {
            if active != Some(binding.session_id) {
                return Err(
                    "committee authorization differs from the active beacon pointer".to_owned(),
                );
            }
            (
                binding.session_id,
                Some(binding.transcript_hash),
                authorization.first_height,
            )
        }
        BeaconEpochBindingV1::Bootstrap => {
            let Some(session_id) = active else {
                if world.global_beacon_key_sessions().iter().next().is_some() {
                    return Err(
                        "bootstrap has a finalized session without its activation".to_owned()
                    );
                }
                return Ok(());
            };
            (
                session_id,
                None,
                committed_height
                    .checked_add(1)
                    .ok_or("bootstrap height overflows")?,
            )
        }
    };
    let record = world
        .global_beacon_key_sessions()
        .get(&session_id)
        .ok_or("committee authorization lacks its exact beacon session")?;
    record.validate().map_err(|error| error.to_string())?;
    // The same ordered BLS roster may serve several generations. Its actual DKG
    // transcript must name the generation authorized at this restore cut.
    if !cfg!(all(test, sumeragi_core_mutation = "HC54"))
        && record.session.adaptive_dkg.session.authority_generation != authority.generation
    {
        return Err("active beacon differs from the authorized signing generation".to_owned());
    }
    if record.session.network_id != authority.network_id
        || transcript_hash.is_some_and(|hash| hash != record.session.transcript_hash)
        || record
            .activated_at_height
            .is_none_or(|height| height > latest_activation)
        || record.retired_at_height.is_some()
        || record.session.adaptive_dkg.finalized_at_height > committed_height
        || (authorization.decision == ValidatorEpochDecisionV1::Activate
            && record.activated_at_height != Some(authorization.first_height))
    {
        return Err("committee authorization differs from the active beacon lifecycle".to_owned());
    }
    authenticated_global_threshold_beacon_roster_hash_iter_v1(
        &record.session,
        authority.validators.iter(),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Authenticate both presence and absence from the exact snapshot cut with the same native
/// verifier used by recovery. World supplies no authority to that reader. Genesis-only checks
/// authenticate its signed authority, not its execution roots; startup must reexecute genesis.
pub(crate) fn validate_committed_progress(
    world: &impl WorldReadOnly,
    chain_id: &iroha_model_base::chain::ChainId,
    network: iroha_data_model::NetworkId,
    hashes: &[iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>],
    kura: &crate::kura::Kura,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(), Attempt<String>> {
    use crate::sumeragi::{certified_chain::CertifiedChain, schedule::ConsensusSchedule};
    use iroha_data_model::parameter::system::ConsensusMode;
    validate_persisted_progress(world)?;
    let height = u64::try_from(hashes.len()).map_err(|_| "committed height overflows")?;
    if height == 0 {
        if !world.consensus_schedule().entries().is_empty()
            || world
                .validator_committee_transitions()
                .iter()
                .next()
                .is_some()
            || world.global_beacon_pulses().iter().next().is_some()
            || world.global_beacon_pulse_slots().iter().next().is_some()
            || world.global_beacon_latest_pulse().iter().next().is_some()
            || world.global_beacon_key_sessions().iter().next().is_some()
            || world.active_global_beacon_key_session().is_some()
        {
            return Err("uncommitted State invents native authority or preparation".into());
        }
        return Ok(());
    }
    let reader = CertifiedChain::from_pinned(chain_id, &network, hashes, kura, budget)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
    let mut graph: Option<ConsensusSchedule> = None;
    let mut historical_obligations = std::collections::BTreeMap::new();
    let mut observed = std::collections::BTreeSet::new();
    let mut observed_pulses = 0_usize;
    let mut latest_pulse = None;
    for certified in reader.walk(1, height) {
        let certified =
            certified.map_err(|error| error.map_rejection(|error| error.to_string()))?;
        if let Some(pulse) = &certified.commitment().beacon {
            let slot = (
                iroha_data_model::governance::types::BeaconSessionId::for_network_v1(&network),
                certified.height(),
            );
            if world.global_beacon_pulses().get(&pulse.pulse_id) != Some(pulse)
                || world.global_beacon_pulse_slots().get(&slot) != Some(&pulse.pulse_id)
            {
                return Err(
                    "restored beacon pulse differs from its exact certified native result".into(),
                );
            }
            observed_pulses = observed_pulses
                .checked_add(1)
                .ok_or("pulse count overflows")?;
            latest_pulse = Some(
                crate::beacon::validate_persisted_global_threshold_beacon_pulse_v1(pulse)
                    .map_err(|error| error.to_string())?,
            );
        }
        let schedule = &certified.commitment().schedule;
        let current = &schedule.current;
        graph = Some(
            match graph {
                None => ConsensusSchedule::from_genesis_outcome(schedule),
                Some(previous) => previous.advanced(schedule),
            }
            .map_err(|error| error.to_string())?,
        );
        if current.mode == ConsensusMode::Npos {
            add_obligations(
                &mut historical_obligations,
                current.committee.iter().map(|seat| seat.validator.clone()),
                current.authorization.last_height,
            );
        }
        let Some(boundary) = &schedule.boundary else {
            continue;
        };
        let outcome = &boundary.next.authorization;
        if let Some(preparation) = &boundary.preparation {
            let transition = world
                .validator_committee_transitions()
                .get(&preparation.target_epoch)
                .ok_or("committee snapshot omits an incumbent-certified preparation")?;
            if &transition.preparation != preparation
                || preparation.selection_height != certified.height()
                || certified.block().header().prev_block_hash()
                    != Some(preparation.selection_anchor)
                || !observed.insert(preparation.target_epoch)
            {
                return Err(
                    "committee snapshot changes or duplicates a certified preparation".into(),
                );
            }
            preparation.validate_against_preparing_authorization(outcome)?;
            add_obligations(
                &mut historical_obligations,
                preparation
                    .committee
                    .iter()
                    .map(|seat| seat.validator.clone()),
                preparation.last_height,
            );
            if preparation
                .first_height
                .checked_sub(1)
                .ok_or("preparation cutoff underflows")?
                > height
                && transition.outcome.is_some()
            {
                return Err("committee snapshot invents a future terminal decision".into());
            }
        }
        match outcome.decision {
            ValidatorEpochDecisionV1::Activate | ValidatorEpochDecisionV1::RetainAndCancel => {
                let transition = world
                    .validator_committee_transitions()
                    .get(&outcome.epoch)
                    .ok_or("committee snapshot omits a certified terminal attempt")?;
                if transition.outcome.as_ref() != Some(outcome) {
                    return Err(
                        "committee terminal decision differs from native certified history".into(),
                    );
                }
                if outcome.decision == ValidatorEpochDecisionV1::Activate {
                    let BeaconEpochBindingV1::Installed(previous) = current.authorization.beacon
                    else {
                        return Err("activation lacks the incumbent installed beacon".into());
                    };
                    let BeaconEpochBindingV1::Installed(next) = outcome.beacon else {
                        return Err("activation lacks its target installed beacon".into());
                    };
                    let old = world
                        .global_beacon_key_sessions()
                        .get(&previous.session_id)
                        .ok_or("activation snapshot omits incumbent beacon history")?;
                    let new = world
                        .global_beacon_key_sessions()
                        .get(&next.session_id)
                        .ok_or("activation snapshot omits target beacon history")?;
                    if old.session.transcript_hash != previous.transcript_hash
                        || old.retired_at_height != Some(outcome.first_height)
                        || new.session.transcript_hash != next.transcript_hash
                        || new.activated_at_height != Some(outcome.first_height)
                    {
                        return Err(
                            "beacon lifecycle differs from certified native activation".into()
                        );
                    }
                }
            }
            ValidatorEpochDecisionV1::Retain => {
                if world
                    .validator_committee_transitions()
                    .get(&outcome.epoch)
                    .is_some()
                {
                    return Err("retention omitted cancellation of a frozen attempt".into());
                }
            }
            ValidatorEpochDecisionV1::Genesis => {
                return Err("epoch boundary resets genesis authorization".into());
            }
        }
    }
    if world.global_beacon_pulses().iter().count() != observed_pulses
        || world.global_beacon_pulse_slots().iter().count() != observed_pulses
        || world.global_beacon_latest_pulse().iter().count() != usize::from(latest_pulse.is_some())
        || world
            .global_beacon_latest_pulse()
            .get(&super::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
            != latest_pulse.as_ref()
    {
        return Err("restored beacon history adds or omits certified native pulse work".into());
    }
    let graph = graph.ok_or("committed native prefix is empty")?;
    if world.consensus_schedule().canonical() != &graph {
        return Err("restored native schedule differs from the exact certified cut".into());
    }
    let next = graph
        .ready(
            height
                .checked_add(1)
                .ok_or("next authority height overflows")?,
        )
        .map_err(|error| error.to_string())?;
    validate_current_beacon(
        world,
        &next.epoch.generation(),
        &next.epoch.authorization,
        height,
    )?;
    let mut live_obligations = std::collections::BTreeMap::new();
    if next.epoch.mode == ConsensusMode::Npos {
        add_obligations(
            &mut live_obligations,
            next.epoch
                .committee
                .iter()
                .map(|seat| seat.validator.clone()),
            next.epoch.authorization.last_height,
        );
        for (_, transition) in world
            .validator_committee_transitions()
            .iter()
            .filter(|(_, transition)| transition.outcome.is_none())
        {
            add_obligations(
                &mut live_obligations,
                transition
                    .preparation
                    .committee
                    .iter()
                    .map(|seat| seat.validator.clone()),
                transition.preparation.last_height,
            );
        }
    }
    for (peer, through) in &live_obligations {
        let retained = historical_obligations.entry(peer.clone()).or_default();
        *retained = (*retained).max(*through);
    }
    if observed.len() != world.validator_committee_transitions().iter().count() {
        return Err("committee snapshot contains an uncertified preparation".into());
    }
    validate_retained_staking_obligations(world, &historical_obligations, &live_obligations)
        .map_err(Into::into)
}

/// Resolve the incumbent validator generation from the authenticated committed result.
/// The next-height World schedule must agree with the certified boundary decision; mutable
/// registrations and local certificate caches cannot supply replacement authority.
pub(crate) fn current_authority(
    state: &impl StateReadOnly,
) -> Result<(ValidatorGenerationV1, ValidatorEpochAuthorizationV1), Attempt<String>> {
    let height = u64::try_from(state.height()).map_err(|_| "committed height overflows")?;
    let block =
        crate::sumeragi::certified_chain::committed_block(state, height).map_err(|error| {
            if cfg!(all(test, sumeragi_core_mutation = "HC48")) {
                return Attempt::Rejected(error.to_string());
            }
            error.map_rejection(|error| error.to_string())
        })?;
    let outcome = &block.commitment().schedule;
    outcome.validate().map_err(|error| error.to_string())?;
    let context = outcome
        .boundary
        .as_ref()
        .map_or(&outcome.current, |boundary| &boundary.next);
    let scheduled = state
        .world()
        .consensus_schedule()
        .ready(
            height
                .checked_add(1)
                .ok_or("next authority height overflows")?,
        )
        .map_err(|error| error.to_string())?;
    if context.network_id != *state.network_id() || scheduled.epoch != *context {
        return Err("native incumbent result differs from the applied State authority".into());
    }
    // This deterministic reader deliberately does not decode the per-node QC. Its State cut
    // was admitted by original execution/publication, or by authenticated startup recovery.
    Ok((context.generation(), context.authorization))
}

/// Admit a finalized public transcript without giving it independent rotation authority.
/// The returned flag permits next-height activation only for the genesis bootstrap.
pub(crate) fn validate_beacon_finalization(
    state: &StateTransaction<'_, '_>,
    record: &crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    authorizing_roster: &[PeerId],
) -> Result<bool, Attempt<String>> {
    let (authority, authorization) = current_authority(state)?;
    validate_beacon_preparation(
        &state.world,
        state.block_height(),
        &authority,
        &authorization,
        record,
        authorizing_roster,
    )
    .map_err(Attempt::Rejected)
}

fn validate_beacon_preparation(
    world: &impl WorldReadOnly,
    height: u64,
    authority: &ValidatorGenerationV1,
    authorization: &ValidatorEpochAuthorizationV1,
    record: &crate::beacon::RetainedFinalizedGlobalThresholdBeaconSessionV1,
    authorizing_roster: &[PeerId],
) -> Result<bool, String> {
    authorization
        .validate_against_generation(authority)
        .map_err(|error| error.to_string())?;
    record.validate().map_err(|error| error.to_string())?;
    if !(authorization.first_height..=authorization.last_height).contains(&height)
        || record.session.network_id != authority.network_id
        || record.activated_at_height.is_some()
        || record.retired_at_height.is_some()
        || record.session.adaptive_dkg.finalized_at_height > height
        || !authority.validators.iter().eq(authorizing_roster.iter())
    {
        return Err(
            "beacon finalization differs from its authenticated execution context".to_owned(),
        );
    }
    let active = world.active_global_beacon_key_session();
    if active.is_none() {
        if authority.generation != 0 || authorization.beacon != BeaconEpochBindingV1::Bootstrap {
            return Err(
                "only the authenticated genesis authority may bootstrap a beacon".to_owned(),
            );
        }
        // A genuine transcript for another generation is not bootstrap custody,
        // even when every participant and public possession proof is valid.
        if !cfg!(all(test, sumeragi_core_mutation = "HC54"))
            && record.session.adaptive_dkg.session.authority_generation != authority.generation
        {
            return Err("bootstrap beacon differs from the genesis signing generation".to_owned());
        }
        authenticated_global_threshold_beacon_roster_hash_v1(&record.session, authorizing_roster)
            .map_err(|error| error.to_string())?;
        return Ok(true);
    }
    let BeaconEpochBindingV1::Installed(incumbent) = authorization.beacon else {
        return Err("a pending beacon requires the installed incumbent authorization".to_owned());
    };
    let target_epoch = authorization
        .epoch
        .checked_add(1)
        .ok_or("target epoch overflows")?;
    let transition = world
        .validator_committee_transitions()
        .get(&target_epoch)
        .ok_or("beacon finalization requires an authenticated frozen committee")?;
    transition.validate()?;
    let preparation = &transition.preparation;
    preparation.validate_against_preparing_authorization(authorization)?;
    let current = world
        .global_beacon_key_sessions()
        .get(&incumbent.session_id)
        .ok_or("incumbent beacon public state is absent")?;
    if active != Some(incumbent.session_id)
        || current.session.transcript_hash != incumbent.transcript_hash
        || !current.is_active_at(height)
        || transition.outcome.is_some()
        || height >= authorization.last_height
        || record.session.session_id != preparation.beacon_session_id()?
        || record.session.adaptive_dkg.session.attempt_id != preparation.transition_id()?
        || record.session.adaptive_dkg.session.authority_generation
            != preparation.authority_generation
        || record.session.adaptive_dkg.session.start_height <= preparation.selection_height
        || record.session.adaptive_dkg.finalized_at_height >= preparation.first_height - 1
    {
        return Err(
            "beacon finalization does not belong to the live preparation attempt".to_owned(),
        );
    }
    let target_roster = preparation.committee.iter().map(|seat| &seat.validator);
    authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, target_roster)
        .map_err(|error| error.to_string())?;
    Ok(false)
}

impl StateBlock<'_> {
    /// Stage the complete certified boundary effect in the original execution overlay.
    /// Publication of this overlay is still gated by the current committee's exact finality.
    pub(crate) fn finalize_validator_committee_boundary(
        &mut self,
        frozen: &crate::sumeragi::epoch_election::FrozenEpochBoundary,
    ) -> Result<(), Attempt<String>> {
        let context = frozen.current();
        let boundary = frozen.boundary();
        boundary.validate_against(context)?;
        let snapshot = &boundary.next;
        if boundary.height != self._curr_block.height().get()
            || context.network_id != self.network_id
        {
            return Err(
                ("committee boundary belongs to another execution context".to_owned()).into(),
            );
        }
        let anchor_index = boundary
            .height
            .checked_sub(2)
            .and_then(|height| usize::try_from(height).ok())
            .ok_or("boundary lacks its exact pretransaction State anchor")?;
        if self.block_hashes().hash_at(anchor_index) != Some(&boundary.selection_anchor)
            || self.block_hashes().hash_count() != anchor_index + 1
            || self
                .world
                .consensus_schedule()
                .ready(boundary.height)
                .map_err(|error| error.to_string())?
                .epoch
                != *context
        {
            return Err(
                ("frozen boundary source differs from the original State cut".to_owned()).into(),
            );
        }
        // The sealed capability proved all target custody and preparation readiness before B
        // transactions. Mandatory authorized slashing remains an execution effect; transaction
        // guards prevent voluntary release/rebinding of those exact original obligations.
        let outcome = &snapshot.authorization;
        let mut completed = None;
        let mut beacon_rotation = None;
        match outcome.decision {
            ValidatorEpochDecisionV1::Activate | ValidatorEpochDecisionV1::RetainAndCancel => {
                let mut transition = self
                    .world
                    .validator_committee_transitions
                    .get(&snapshot.authorization.epoch)
                    .cloned()
                    .ok_or("boundary decision lacks its frozen committee attempt")?;
                if transition.outcome.is_some() {
                    return Err(("committee attempt is already terminal".to_owned()).into());
                }
                transition
                    .preparation
                    .validate_against_preparing_authorization(&context.authorization)?;
                verify_progress(&self.world, &transition)?;
                transition.outcome = Some(*outcome);
                transition.validate()?;
                if outcome.decision == ValidatorEpochDecisionV1::Activate {
                    let credentials = transition
                        .credentials
                        .as_ref()
                        .ok_or("activated committee lacks prepared credentials")?;
                    if transition.preparation.committee != snapshot.committee {
                        return Err((
                            "activation substitutes the frozen committee or its exact credentials"
                                .to_owned()
                        ).into());
                    }
                    let BeaconEpochBindingV1::Installed(previous) = context.authorization.beacon
                    else {
                        return Err(
                            ("committee activation requires an installed incumbent beacon"
                                .to_owned())
                            .into(),
                        );
                    };
                    if self.world.active_global_beacon_key_session() != Some(previous.session_id) {
                        return Err(("committee activation lost the exact incumbent beacon"
                            .to_owned())
                        .into());
                    }
                    let mut old = self
                        .world
                        .global_beacon_key_sessions
                        .get(&previous.session_id)
                        .cloned()
                        .ok_or("incumbent beacon session is absent")?;
                    let mut next = self
                        .world
                        .global_beacon_key_sessions
                        .get(&credentials.beacon.session_id)
                        .cloned()
                        .ok_or("target beacon session is absent")?;
                    if old.session.transcript_hash != previous.transcript_hash
                        || next.activated_at_height.is_some()
                        || next.retired_at_height.is_some()
                    {
                        return Err(("committee activation beacon credentials have changed"
                            .to_owned())
                        .into());
                    }
                    old.retire(outcome.first_height)
                        .map_err(|error| error.to_string())?;
                    next.activate(outcome.first_height)
                        .map_err(|error| error.to_string())?;
                    beacon_rotation = Some((old, next));
                }
                completed = Some(transition);
            }
            ValidatorEpochDecisionV1::Retain => {
                if self
                    .world
                    .validator_committee_transitions
                    .get(&snapshot.authorization.epoch)
                    .is_some()
                {
                    return Err(
                        ("retention must cancel the exact frozen attempt".to_owned()).into(),
                    );
                }
            }
            ValidatorEpochDecisionV1::Genesis => {
                return Err(("boundary cannot reset scheduling authorization".to_owned()).into());
            }
        }
        let future = boundary
            .preparation
            .as_ref()
            .map(
                |preparation| -> Result<ValidatorCommitteeTransitionV1, String> {
                    preparation.validate_against_preparing_authorization(outcome)?;
                    let anchor_index = boundary
                        .height
                        .checked_sub(2)
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or("future committee has no committed pre-boundary anchor")?;
                    if self.block_hashes().hash_at(anchor_index)
                        != Some(&preparation.selection_anchor)
                        || self
                            .world
                            .validator_committee_transitions
                            .get(&preparation.target_epoch)
                            .is_some()
                    {
                        return Err(
                            ("future committee attempts cannot be replaced or reanchored"
                                .to_owned())
                            .into(),
                        );
                    }
                    let transition = ValidatorCommitteeTransitionV1 {
                        preparation: preparation.clone(),
                        credentials: None,
                        readiness: Vec::new(),
                        outcome: None,
                    };
                    verify_progress(&self.world, &transition)?;
                    Ok(transition)
                },
            )
            .transpose()?;
        let staking = prepare_staking_obligations(&self.world, boundary)?;
        // All checks precede these writes; the carrier publishes membership, the generation
        // authorization, the beacon pointer and this same World journal only after exact
        // incumbent finality.
        if let Some((old, next)) = beacon_rotation {
            let next_id = next.session.session_id;
            self.world
                .global_beacon_key_sessions
                .insert(old.session.session_id, old);
            self.world.global_beacon_key_sessions.insert(next_id, next);
            self.world
                .global_beacon_active_session
                .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, next_id);
        }
        if let Some(transition) = completed {
            self.world
                .validator_committee_transitions
                .insert(transition.preparation.target_epoch, transition);
        }
        if let Some(transition) = future {
            self.world
                .validator_committee_transitions
                .insert(transition.preparation.target_epoch, transition);
        }
        for (key, record) in staking.validators {
            self.world.public_lane_validators.insert(key, record);
        }
        for (key, share) in staking.shares {
            self.world.public_lane_stake_shares.insert(key, share);
        }
        Ok(())
    }
}

fn owns_validator(world: &impl WorldReadOnly, owner: &AccountId, peer: &PeerId) -> bool {
    world.public_lane_validators().iter().any(|(key, record)| {
        public_lane_validator_record_matches_key(key, record)
            && &record.validator == owner
            && &record.peer_id == peer
            && !record.total_stake.is_zero()
    })
}

/// Reverify the prepared transcript and every recorded actual-custody proof from public state.
pub(crate) fn verify_progress(
    world: &impl WorldReadOnly,
    transition: &ValidatorCommitteeTransitionV1,
) -> Result<(), String> {
    transition.validate()?;
    // Canonical preparation validation verifies every ordered BLS proof directly.
    let Some(credentials) = &transition.credentials else {
        return Ok(());
    };
    let record = world
        .global_beacon_key_sessions()
        .get(&credentials.beacon.session_id)
        .ok_or("prepared beacon transcript has not been finalized")?;
    record.validate().map_err(|error| error.to_string())?;
    let session = &record.session;
    let preparation = &transition.preparation;
    if session.network_id != preparation.network_id
        || session.session_id != preparation.beacon_session_id()?
        || session.adaptive_dkg.session.attempt_id != preparation.transition_id()?
        || session.adaptive_dkg.session.authority_generation != preparation.authority_generation
        || session.transcript_hash != credentials.beacon.transcript_hash
        || session.adaptive_dkg.session.start_height <= preparation.selection_height
        || session.adaptive_dkg.finalized_at_height >= preparation.first_height - 1
    {
        return Err(
            "beacon transcript is outside its exact preparation attempt or cutoff".to_owned(),
        );
    }
    let peers = preparation.committee.iter().map(|voter| &voter.validator);
    let roster_hash = authenticated_global_threshold_beacon_roster_hash_iter_v1(session, peers)
        .map_err(|error| error.to_string())?;
    let validated = session;
    validated
        .check_binding(&GlobalThresholdBeaconSessionBindingV1 {
            network_id: preparation.network_id,
            session_id: credentials.beacon.session_id,
            roster_hash,
            transcript_hash: credentials.beacon.transcript_hash,
        })
        .map_err(|error| error.to_string())?;
    let target = preparation.generation();
    for readiness in &transition.readiness {
        let context = transition.readiness_context(readiness.validator_index)?;
        verify_global_threshold_beacon_seat_readiness_v1(
            &validated,
            &target,
            &context,
            &readiness.beacon,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

impl StateTransaction<'_, '_> {
    /// Consume a signed preparation command after exact owner, attempt and proof checks.
    pub(crate) fn apply_validator_committee_operation(
        &mut self,
        owner: &AccountId,
        operation: ValidatorCommitteeOperationV1,
    ) -> Result<(), Attempt<String>> {
        let (_, authorization) = current_authority(self)?;
        match operation {
            ValidatorCommitteeOperationV1::PrepareCredentials(command) => {
                let mut transition = self.pending_committee_transition(
                    command.target_epoch,
                    command.transition_id,
                    &authorization,
                )?;
                if transition.credentials.is_some() || !transition.readiness.is_empty() {
                    return Err(
                        "prepared credentials cannot be replaced within a frozen attempt"
                            .to_owned()
                            .into(),
                    );
                }
                if !transition
                    .preparation
                    .committee
                    .iter()
                    .any(|voter| owns_validator(&self.world, owner, &voter.validator))
                {
                    return Err(
                        "preparing credentials requires an exact target validator owner"
                            .to_owned()
                            .into(),
                    );
                }
                let beacon = self
                    .world
                    .global_beacon_key_sessions
                    .get(&command.credentials.beacon.session_id)
                    .ok_or("target beacon session is absent")?;
                if beacon.activated_at_height.is_some() || beacon.retired_at_height.is_some() {
                    return Err("target beacon session has already been consumed"
                        .to_owned()
                        .into());
                }
                transition.credentials = Some(command.credentials);
                verify_progress(&self.world, &transition)?;
                self.world
                    .validator_committee_transitions
                    .insert(command.target_epoch, transition);
            }
            ValidatorCommitteeOperationV1::AdmitSeat(command) => {
                let mut transition = self.pending_committee_transition(
                    command.target_epoch,
                    command.transition_id,
                    &authorization,
                )?;
                let index = usize::try_from(command.readiness.validator_index)
                    .map_err(|_| "invalid target seat")?;
                let seat = transition
                    .preparation
                    .committee
                    .get(index)
                    .ok_or("invalid target seat")?;
                if !owns_validator(&self.world, owner, &seat.validator) {
                    return Err("seat readiness requires that exact target validator owner"
                        .to_owned()
                        .into());
                }
                let insertion = transition
                    .readiness
                    .binary_search_by_key(&command.readiness.validator_index, |ready| {
                        ready.validator_index
                    })
                    .err()
                    .ok_or("target seat readiness is already recorded")?;
                transition.readiness.insert(insertion, command.readiness);
                verify_progress(&self.world, &transition)?;
                self.world
                    .validator_committee_transitions
                    .insert(command.target_epoch, transition);
            }
        }
        Ok(())
    }

    fn pending_committee_transition(
        &self,
        target_epoch: u64,
        transition_id: [u8; 32],
        authorization: &ValidatorEpochAuthorizationV1,
    ) -> Result<ValidatorCommitteeTransitionV1, String> {
        let transition = self
            .world
            .validator_committee_transitions
            .get(&target_epoch)
            .ok_or("validator committee attempt has not been frozen")?;
        transition
            .preparation
            .validate_against_preparing_authorization(authorization)?;
        if transition.preparation.transition_id()? != transition_id
            || transition.outcome.is_some()
            || self.block_height() >= authorization.last_height
            || self.block_height() < authorization.first_height
        {
            return Err(
                "committee attempt is terminal, replayed or outside its preparation cutoff"
                    .to_owned(),
            );
        }
        Ok(transition.clone())
    }
}
