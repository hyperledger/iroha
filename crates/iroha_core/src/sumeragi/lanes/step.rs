//! The lane step of a global block (`specs/sumeragi_lanes.md` §2, §4.3 step 4, §6): after the
//! block's transactions execute, advance the merged frontiers, record the load sample, retire
//! lanes, reconcile fixed lanes with the policy, close stalled lanes and apply at most one
//! autoscale transition.
//!
//! The lane set is World state, so the step runs inside the execution output seal's finalizer
//! next to the schedule step: the Sumeragi executor passes the block's [`LaneStepInput`] with the
//! validation profile and takes the outcome after validation. Every rule reads committed data
//! only.

use iroha_crypto::Algorithm;
use iroha_data_model::{
    NetworkId,
    consensus::ConsensusKeyRole,
    parameter::system::SumeragiParameters,
    sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRecord,
        SumeragiLaneSample, SumeragiLaneState,
    },
};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use thiserror::Error;

pub use super::custody::CustodyViolation;
use super::{lane_genesis_hash, lane_genesis_result, lane_policy, merge::LaneStepInput};
use crate::{
    state::{StateBlock, StateReadOnly, WorldReadOnly, live_consensus_key_pop_for_peer_with_role},
    sumeragi::{
        commitment::chain_hash,
        schedule::{ChainParamsRecord, canonical_committee, scheduled_committee},
    },
};

/// Domain tag of a lane incarnation.
pub const LANE_INCARNATION_TAG: &[u8] = b"iroha/sumeragi/lane/incarnation/v1";
/// Domain tag of an elastic committee rank.
pub const LANE_COMMITTEE_RANK_TAG: &[u8] = b"iroha/sumeragi/lane/committee-rank/v1";

/// The lane step of the block a [`StateBlock`] executes.
#[derive(Debug, Default)]
pub enum LaneStep {
    /// Not a Sumeragi block: the lane set is left alone.
    #[default]
    Off,
    /// Run after execution with this input.
    Requested(LaneStepInput),
    /// The outcome.
    Done(Result<(), LaneStepError>),
}

/// Why a lane step failed; local custody remains typed and semantic failures are invalid.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LaneStepError {
    /// Original policy or custody work did not finish; a local owner invariant requires recovery.
    #[error("lane step deferred: {0}")]
    Deferred(#[from] crate::execution_attempt::ExecutionDeferred),
    /// A merge names a lane the state no longer has.
    #[error("merged lane {0} has no record")]
    MissingLane(LaneId),
    /// Original pinned stake custody or its global lifetime is invalid.
    #[error("lane custody: {0}")]
    Custody(CustodyViolation),
    /// The step never ran.
    #[error("the lane step did not run")]
    NotAdvanced,
}

impl From<crate::execution_attempt::ExecutionAttemptError<CustodyViolation>> for LaneStepError {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<CustodyViolation>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                Self::Custody(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                Self::Deferred(original)
            }
        }
    }
}

impl StateBlock<'_> {
    /// Request the lane step of the block this overlay executes next.
    pub(crate) fn request_sumeragi_lanes(&mut self, input: LaneStepInput) {
        self.sumeragi_lanes_step = LaneStep::Requested(input);
    }

    /// Run a requested lane step before the output seal completes.
    ///
    /// # Errors
    /// Retains and returns the real lane outcome; an unfinished transition cannot be sealed.
    pub(crate) fn advance_requested_sumeragi_lanes(&mut self) -> Result<(), LaneStepError> {
        self.sumeragi_lanes_step = match std::mem::take(&mut self.sumeragi_lanes_step) {
            LaneStep::Requested(input) => LaneStep::Done(advance(self, &input)),
            original => original,
        };
        match &self.sumeragi_lanes_step {
            LaneStep::Done(outcome) => outcome.clone(),
            LaneStep::Off => Ok(()),
            LaneStep::Requested(_) => unreachable!("original requested lane step ran"),
        }
    }

    /// The outcome of the requested step.
    ///
    /// # Errors
    /// The step failed or never ran.
    pub(crate) fn take_sumeragi_lanes(&mut self) -> Result<(), LaneStepError> {
        match std::mem::take(&mut self.sumeragi_lanes_step) {
            LaneStep::Done(outcome) => outcome,
            LaneStep::Off | LaneStep::Requested(_) => Err(LaneStepError::NotAdvanced),
        }
    }
}

/// Run the lane step of the block `block` executes (height `h`).
///
/// # Errors
/// A merge or original custody binding is inconsistent, or local custody allocation refused.
pub fn advance(block: &mut StateBlock<'_>, input: &LaneStepInput) -> Result<(), LaneStepError> {
    let height = block._curr_block.height().get();
    let time_ms = u64::try_from(block._curr_block.creation_time().as_millis()).unwrap_or(u64::MAX);
    let policy = lane_policy(&block.world)?;
    let network = *block.network_id();
    let budget = block.pipeline_ivm_prepared_cache.execution_budget();
    let mut state = super::custody::admit_state(block.world.sumeragi_lanes.get(), budget)
        .map_err(super::custody::state_admission_attempt_error)
        .map_err(LaneStepError::from)?;
    apply_merges(&mut state, input, height)?;
    record_sample(&mut state, policy.as_ref(), input, height, time_ms, budget)?;
    super::custody::prepare_retirement(&mut state, &block.world, height)
        .map_err(LaneStepError::from)?;
    retire(&mut state, height);
    let pool = |incarnation: &[u8; 32], size: u32| {
        elastic_committee(&block.world, height, incarnation, size)
    };
    let creation_capacity =
        super::custody::creation_capacity(&state, &block.world).map_err(LaneStepError::from)?;
    reconcile(
        &mut state,
        policy.as_ref(),
        &network,
        height,
        creation_capacity,
        pool,
    );
    super::custody::pin_created(
        &mut state,
        &block.world,
        &block.nexus,
        &network,
        block.chain_id().as_str(),
        policy.as_ref(),
        height,
        budget,
    )
    .map_err(LaneStepError::from)?;
    *block.world.sumeragi_lanes.get_mut() = state;
    Ok(())
}

/// Advance the frontiers of merged lanes and count unserved load (§4.3 step 4, §6.4).
fn apply_merges(
    state: &mut SumeragiLaneState,
    input: &LaneStepInput,
    height: u64,
) -> Result<(), LaneStepError> {
    for merge in &input.merges {
        let record = state
            .lane_mut(merge.lane)
            .ok_or(LaneStepError::MissingLane(merge.lane))?;
        record.merged = SumeragiLaneFrontier {
            height: merge.to,
            block_hash: merge.tip_hash,
            result: merge.tip_result,
        };
        record.merged_at = height;
        record.rescued = 0;
    }
    for (lane, count) in &input.rescued {
        if let Some(record) = state.lane_mut(*lane) {
            record.rescued = record.rescued.saturating_add(*count);
        }
    }
    Ok(())
}

/// Append this block's load sample, keeping the autoscale window (§6.1).
fn record_sample(
    state: &mut SumeragiLaneState,
    policy: Option<&SumeragiLanePolicy>,
    input: &LaneStepInput,
    height: u64,
    time_ms: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(), LaneStepError> {
    let Some(autoscale) = policy.and_then(|policy| policy.autoscale.as_ref()) else {
        state.samples = Default::default();
        return Ok(());
    };
    let policy = policy.expect("autoscale comes from the policy");
    let active_elastic = |record: &&SumeragiLaneRecord| {
        policy.is_elastic(record.lane) && record.admits_anchor(height)
    };
    let elastic_count = state.lanes.iter().filter(active_elastic).count();
    let transactions = input
        .executed
        .iter()
        .filter(|(lane, _)| {
            lane.as_u32() == 0
                || state
                    .lanes
                    .iter()
                    .filter(active_elastic)
                    .any(|record| record.lane == **lane)
        })
        .map(|(_, count)| *count)
        .fold(0u64, u64::saturating_add);
    let sample = SumeragiLaneSample {
        height,
        time_ms,
        transactions,
        lanes: u32::try_from(elastic_count.saturating_add(1)).unwrap_or(u32::MAX),
    };
    let keep = usize::try_from(autoscale.window)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let samples = super::custody::retain_samples(&state.samples, Some((sample, keep)), budget)
        .map_err(|error| {
            LaneStepError::Deferred(super::custody::samples_admission_deferred(error))
        })?;
    state.samples = samples;
    Ok(())
}

/// Remove lanes whose retirement height is reached (§6.3).
fn retire(state: &mut SumeragiLaneState, height: u64) {
    state.lanes.retain(|record| {
        record
            .retirement_height()
            .is_none_or(|retirement| height < retirement)
    });
}

/// Close lanes the policy no longer lists or that stalled, create missing fixed lanes, and
/// apply at most one autoscale transition.
fn reconcile(
    state: &mut SumeragiLaneState,
    policy: Option<&SumeragiLanePolicy>,
    network: &NetworkId,
    height: u64,
    mut creation_capacity: usize,
    mut pool: impl FnMut(&[u8; 32], u32) -> Option<Vec<SumeragiLaneMember>>,
) {
    let close_at = height.saturating_add(1);
    let Some(policy) = policy else {
        for record in &mut state.lanes {
            record.closing.get_or_insert(close_at);
        }
        return;
    };
    for record in &mut state.lanes {
        if record.closing.is_some() {
            continue;
        }
        let listed = if policy.is_elastic(record.lane) {
            policy
                .autoscale
                .as_ref()
                .is_some_and(|autoscale| autoscale.dataspace == record.dataspace)
        } else {
            policy.fixed_lane(record.lane).is_some_and(|fixed| {
                fixed.dataspace == record.dataspace && fixed.committee == record.committee
            })
        };
        let stalled =
            record.rescued > 0 && height >= record.merged_at.saturating_add(policy.stall_window);
        if !listed || stalled {
            record.closing = Some(close_at);
        }
    }
    for fixed in &policy.fixed {
        if creation_capacity > 0 && state.lane(fixed.lane).is_none() {
            let record = create(
                state,
                policy,
                network,
                fixed.lane,
                fixed.dataspace,
                fixed.committee.clone(),
                height,
            );
            state.upsert(record);
            creation_capacity -= 1;
        }
    }
    let Some(transition) = autoscale_decision(state, policy, height) else {
        return;
    };
    match transition {
        Transition::Open(lane) => {
            if creation_capacity == 0 {
                return;
            }
            let autoscale = policy
                .autoscale
                .as_ref()
                .expect("a decision needs autoscale");
            let incarnation = incarnation(
                network,
                lane,
                autoscale.dataspace,
                height,
                state.incarnations,
            );
            let Some(committee) = pool(&incarnation, autoscale.committee_size) else {
                return;
            };
            let record = create(
                state,
                policy,
                network,
                lane,
                autoscale.dataspace,
                committee,
                height,
            );
            state.upsert(record);
            state.last_transition = height;
        }
        Transition::Close(lane) => {
            if let Some(record) = state.lane_mut(lane) {
                record.closing = Some(close_at);
            }
            state.last_transition = height;
        }
    }
}

/// A new incarnation of `lane`, active two global heights later (§2.2).
fn create(
    state: &mut SumeragiLaneState,
    policy: &SumeragiLanePolicy,
    network: &NetworkId,
    lane: LaneId,
    dataspace: DataSpaceId,
    committee: Vec<SumeragiLaneMember>,
    height: u64,
) -> SumeragiLaneRecord {
    let incarnation = incarnation(network, lane, dataspace, height, state.incarnations);
    state.incarnations = state.incarnations.saturating_add(1);
    let active_from = height.saturating_add(2);
    let mut record = SumeragiLaneRecord {
        da_layout: policy.da_layout,
        lane,
        dataspace,
        incarnation,
        params: policy.lane_params.clone(),
        committee,
        created_at: height,
        active_from,
        closing: None,
        anchor_freshness: policy.anchor_freshness,
        merged: SumeragiLaneFrontier::default(),
        merged_at: active_from,
        rescued: 0,
    };
    record.merged = SumeragiLaneFrontier {
        height: 0,
        block_hash: lane_genesis_hash(network, &record).0,
        result: lane_genesis_result(&record).0,
    };
    record
}

/// Incarnation `ι = H(TAG ‖ network ‖ be32(lane) ‖ be64(dataspace) ‖ be64(height) ‖
/// be64(counter))` (§1).
#[must_use]
pub fn incarnation(
    network: &NetworkId,
    lane: LaneId,
    dataspace: DataSpaceId,
    height: u64,
    counter: u64,
) -> [u8; 32] {
    let mut bytes = LANE_INCARNATION_TAG.to_vec();
    bytes.extend_from_slice(network.as_bytes());
    bytes.extend_from_slice(&lane.as_u32().to_be_bytes());
    bytes.extend_from_slice(&dataspace.as_u64().to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&counter.to_be_bytes());
    chain_hash(&bytes).0
}

/// An autoscale transition (§6.2–§6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// Open this elastic lane.
    Open(LaneId),
    /// Close this elastic lane.
    Close(LaneId),
}

/// The autoscale transition at `height`, if any: outside the cooldown, open the lowest free
/// elastic lane at or above the scale-out utilization, close the highest open elastic lane
/// below the scale-in utilization.
#[must_use]
pub fn autoscale_decision(
    state: &SumeragiLaneState,
    policy: &SumeragiLanePolicy,
    height: u64,
) -> Option<Transition> {
    let autoscale = policy.autoscale.as_ref()?;
    if state.last_transition != 0
        && height < state.last_transition.saturating_add(autoscale.cooldown)
    {
        return None;
    }
    let utilization = utilization_permille(
        &state.samples,
        autoscale.window,
        autoscale.per_lane_target_tps,
    )?;
    if utilization >= u64::from(autoscale.scale_out_permille) {
        return (autoscale.min_lane.as_u32()..autoscale.max_lane_exclusive.as_u32())
            .map(LaneId::new)
            .find(|lane| state.lane(*lane).is_none())
            .map(Transition::Open);
    }
    if utilization < u64::from(autoscale.scale_in_permille) {
        return state
            .lanes
            .iter()
            .rev()
            .find(|record| {
                policy.is_elastic(record.lane)
                    && record.closing.is_none()
                    && record.active_from <= height
            })
            .map(|record| Transition::Close(record.lane));
    }
    None
}

/// Utilization of the default-route lanes over the last `window` sample intervals, per mille:
/// executed transactions over `Σ interval × lanes × per_lane_target_tps`. `None` until the
/// window is full or when it offered no capacity.
#[must_use]
pub fn utilization_permille(samples: &[SumeragiLaneSample], window: u32, tps: u32) -> Option<u64> {
    let window = usize::try_from(window).ok()?;
    let first = samples.len().checked_sub(window.checked_add(1)?)?;
    let mut transactions = 0u128;
    // Capacity in thousandths of a transaction: interval (ms) × lanes × tx/s.
    let mut capacity = 0u128;
    for pair in samples[first..].windows(2) {
        let interval = pair[1].time_ms.saturating_sub(pair[0].time_ms);
        transactions = transactions.saturating_add(u128::from(pair[1].transactions));
        capacity = capacity
            .saturating_add(u128::from(interval) * u128::from(pair[1].lanes) * u128::from(tps));
    }
    if capacity == 0 {
        return None;
    }
    Some(u64::try_from(transactions.saturating_mul(1_000_000) / capacity).unwrap_or(u64::MAX))
}

/// An elastic lane committee (§6.2): `size` global validators live at `height` with their
/// proofs of possession, ranked by `H(TAG ‖ incarnation ‖ key)`, in canonical order; `None` if
/// fewer are available.
fn elastic_committee(
    world: &impl WorldReadOnly,
    height: u64,
    incarnation: &[u8; 32],
    size: u32,
) -> Option<Vec<SumeragiLaneMember>> {
    let size = usize::try_from(size).ok()?;
    let mut ranked = scheduled_committee(world, height)
        .ok()?
        .into_iter()
        .filter_map(|peer| {
            let pop = live_consensus_key_pop_for_peer_with_role(
                world,
                &peer,
                height,
                ConsensusKeyRole::Validator,
            )?;
            Some((rank(incarnation, &peer), peer, pop))
        })
        .collect::<Vec<_>>();
    if ranked.len() < size {
        return None;
    }
    ranked.sort_by(|a, b| a.0.cmp(&b.0));
    ranked.truncate(size);
    let order = canonical_committee(ranked.iter().map(|(_, peer, _)| peer.clone())).ok()?;
    Some(
        order
            .into_iter()
            .filter_map(|peer| {
                let pop = ranked
                    .iter()
                    .find(|(_, candidate, _)| *candidate == peer)
                    .map(|(_, _, pop)| pop.clone())?;
                Some(SumeragiLaneMember { peer, pop })
            })
            .collect(),
    )
}

fn rank(incarnation: &[u8; 32], peer: &PeerId) -> [u8; 32] {
    let mut bytes = LANE_COMMITTEE_RANK_TAG.to_vec();
    bytes.extend_from_slice(incarnation);
    let (_, key) = peer.public_key().to_bytes();
    bytes.extend_from_slice(&key);
    chain_hash(&bytes).0
}

/// Check the policy's pinned lane parameters and every fixed member's proof of possession.
///
/// # Errors
/// The lane parameters fail chain parameter validation, or a member's key is not BLS-normal
/// or its proof of possession does not verify.
pub fn validate_policy(policy: &SumeragiLanePolicy) -> Result<(), String> {
    policy.validate().map_err(|error| error.to_string())?;
    validate_lane_params(&policy.lane_params)?;
    for fixed in &policy.fixed {
        for member in &fixed.committee {
            let key = member.peer.public_key();
            if key.algorithm() != Algorithm::BlsNormal {
                return Err(format!(
                    "lane {} member {} is not BLS-normal",
                    fixed.lane, member.peer
                ));
            }
            iroha_crypto::bls_normal_pop_verify(key, &member.pop).map_err(|error| {
                format!(
                    "lane {} member {}: proof of possession: {error}",
                    fixed.lane, member.peer
                )
            })?;
        }
    }
    Ok(())
}

fn validate_lane_params(params: &SumeragiParameters) -> Result<(), String> {
    ChainParamsRecord::from_parameters(params)
        .validate()
        .map_err(|error| format!("lane parameters: {error}"))
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneAutoscale, SumeragiLaneMerge,
    };

    use super::*;

    fn network() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::prehashed([5; 32])))
    }

    fn member(seed: u8) -> SumeragiLaneMember {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
        SumeragiLaneMember {
            peer: PeerId::new(pair.public_key().clone()),
            pop: iroha_crypto::bls_normal_pop_prove(pair.private_key()).expect("pop"),
        }
    }

    fn policy() -> SumeragiLanePolicy {
        SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 4,
            max_merge_blocks: 8,
            stall_window: 10,
            lane_params: SumeragiParameters::default(),
            fixed: vec![SumeragiFixedLane {
                lane: LaneId::new(2),
                dataspace: DataSpaceId::new(0),
                committee: vec![member(1), member(2)],
            }],
            routes: Vec::new(),
            autoscale: Some(SumeragiLaneAutoscale {
                min_lane: LaneId::new(16),
                max_lane_exclusive: LaneId::new(18),
                dataspace: DataSpaceId::new(0),
                committee_size: 2,
                per_lane_target_tps: 10,
                window: 4,
                scale_out_permille: 800,
                scale_in_permille: 200,
                cooldown: 3,
            }),
        }
    }

    fn samples(per_block: u64, lanes: u32, count: u64) -> Vec<SumeragiLaneSample> {
        (0..count)
            .map(|index| SumeragiLaneSample {
                height: index + 1,
                time_ms: index * 1000,
                transactions: per_block,
                lanes,
            })
            .collect()
    }

    fn pool(_incarnation: &[u8; 32], size: u32) -> Option<Vec<SumeragiLaneMember>> {
        Some(
            (1..=u8::try_from(size).unwrap())
                .map(|seed| member(seed + 10))
                .collect(),
        )
    }

    #[test]
    fn exhausted_custody_defers_creation_without_blocking_closure() {
        let mut state = SumeragiLaneState::default();
        let policy = policy();
        reconcile(&mut state, Some(&policy), &network(), 1, 0, pool);
        assert!(state.lanes.is_empty());
        assert_eq!(state.incarnations, 0);
        state.samples = samples(9, 1, 5).try_into().unwrap();
        reconcile(&mut state, Some(&policy), &network(), 20, 1, pool);
        assert_eq!(
            state.lanes.len(),
            1,
            "fixed creation consumed the one free obligation"
        );
        assert!(state.lane(LaneId::new(16)).is_none());
        assert_eq!(state.last_transition, 0);
        reconcile(&mut state, None, &network(), 21, 0, pool);
        assert_eq!(state.lanes[0].closing, Some(22));
        retire(&mut state, 27);
        assert!(state.lanes.is_empty());
    }

    #[test]
    fn utilization_needs_a_full_window() {
        // One lane at 10 tx/s over one-second intervals carrying 8 tx each: 800 ‰.
        assert_eq!(utilization_permille(&samples(8, 1, 5), 4, 10), Some(800));
        assert_eq!(utilization_permille(&samples(8, 1, 4), 4, 10), None);
        // Two lanes halve it.
        assert_eq!(utilization_permille(&samples(8, 2, 5), 4, 10), Some(400));
        // No elapsed time offers no capacity.
        let mut still = samples(8, 1, 5);
        for sample in &mut still {
            sample.time_ms = 0;
        }
        assert_eq!(utilization_permille(&still, 4, 10), None);
    }

    #[test]
    fn genesis_policy_creates_fixed_lanes_with_distinct_incarnations() {
        let mut state = SumeragiLaneState::default();
        let policy = policy();
        reconcile(&mut state, Some(&policy), &network(), 1, usize::MAX, pool);
        let record = state.lane(LaneId::new(2)).expect("fixed lane");
        assert_eq!(record.active_from, 3);
        assert_eq!(record.anchor_freshness, 4);
        assert_eq!(record.merged.height, 0);
        assert_eq!(state.incarnations, 1);
        let first = record.incarnation;
        // Removing it from the policy closes it; after retirement a relisting recreates it.
        let mut without = policy.clone();
        without.fixed.clear();
        reconcile(&mut state, Some(&without), &network(), 5, usize::MAX, pool);
        assert_eq!(state.lane(LaneId::new(2)).unwrap().closing, Some(6));
        retire(&mut state, 10);
        assert!(
            state.lane(LaneId::new(2)).is_some(),
            "retires at c + A + 1 = 11"
        );
        retire(&mut state, 11);
        assert!(state.lane(LaneId::new(2)).is_none());
        reconcile(&mut state, Some(&policy), &network(), 12, usize::MAX, pool);
        assert_ne!(state.lane(LaneId::new(2)).unwrap().incarnation, first);
        // Without a policy every lane closes.
        reconcile(&mut state, None, &network(), 13, usize::MAX, pool);
        assert_eq!(state.lane(LaneId::new(2)).unwrap().closing, Some(14));
    }

    #[test]
    fn autoscale_opens_under_load_and_closes_when_idle_with_cooldown() {
        let policy = policy();
        let mut state = SumeragiLaneState {
            samples: samples(9, 1, 5).try_into().unwrap(),
            ..SumeragiLaneState::default()
        };
        reconcile(&mut state, Some(&policy), &network(), 20, usize::MAX, pool);
        let opened = state.lane(LaneId::new(16)).expect("scaled out");
        assert_eq!(opened.committee.len(), 2);
        assert_eq!(state.last_transition, 20);
        // Within the cooldown nothing changes, even under load.
        reconcile(&mut state, Some(&policy), &network(), 22, usize::MAX, pool);
        assert!(state.lane(LaneId::new(17)).is_none());
        reconcile(&mut state, Some(&policy), &network(), 23, usize::MAX, pool);
        assert!(
            state.lane(LaneId::new(17)).is_some(),
            "the next free elastic id"
        );
        // The range is exhausted: no further lane.
        reconcile(&mut state, Some(&policy), &network(), 26, usize::MAX, pool);
        assert_eq!(state.lanes.len(), 3);
        // Idle: the highest active elastic lane closes.
        state.samples = samples(0, 3, 5).try_into().unwrap();
        reconcile(&mut state, Some(&policy), &network(), 29, usize::MAX, pool);
        assert_eq!(state.lane(LaneId::new(17)).unwrap().closing, Some(30));
        assert_eq!(state.lane(LaneId::new(16)).unwrap().closing, None);
    }

    #[test]
    fn merges_advance_frontiers_and_stalled_lanes_close() {
        let policy = policy();
        let mut state = SumeragiLaneState::default();
        reconcile(&mut state, Some(&policy), &network(), 1, usize::MAX, pool);
        let lane = LaneId::new(2);
        let incarnation = state.lane(lane).unwrap().incarnation;
        let merge = SumeragiLaneMerge {
            lane,
            incarnation,
            from: 1,
            to: 3,
            tip_hash: [7; 32],
            tip_result: [8; 32],
        };
        let input = LaneStepInput {
            merges: vec![merge],
            ..LaneStepInput::default()
        };
        apply_merges(&mut state, &input, 5).expect("merge");
        let record = state.lane(lane).unwrap();
        assert_eq!(record.merged.height, 3);
        assert_eq!(record.merged_at, 5);
        // Rescued load without merges for the stall window closes the lane.
        let rescued = LaneStepInput {
            rescued: [(lane, 2)].into_iter().collect(),
            ..LaneStepInput::default()
        };
        apply_merges(&mut state, &rescued, 6).expect("rescued");
        reconcile(&mut state, Some(&policy), &network(), 14, usize::MAX, pool);
        assert_eq!(state.lane(lane).unwrap().closing, None);
        reconcile(&mut state, Some(&policy), &network(), 15, usize::MAX, pool);
        assert_eq!(state.lane(lane).unwrap().closing, Some(16));
        // A merge naming a lane without a record is an error.
        let mut empty = SumeragiLaneState::default();
        assert_eq!(
            apply_merges(&mut empty, &input, 5),
            Err(LaneStepError::MissingLane(lane))
        );
    }

    #[test]
    fn policy_validation_checks_proofs_of_possession() {
        let valid = policy();
        assert_eq!(validate_policy(&valid), Ok(()));
        let mut forged = valid;
        forged.fixed[0].committee[0].pop = member(9).pop;
        assert!(validate_policy(&forged).is_err());
    }
}

#[cfg(test)]
#[path = "step/sample_owner_tests.rs"]
mod sample_owner_tests;
