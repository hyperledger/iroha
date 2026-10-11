//! Authenticated boundary source cuts and bounded equal-vote committee selection.
//!
//! Selection borrows one reconciled prestate. It cannot confer finality or mutate World.
//! The native boundary owner materializes the selected references with the original execution
//! allocation custody before any transaction runs, and only the incumbent-certified result
//! may publish that preparation.

mod owned;
mod plan;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
pub(crate) use owned::{
    BoundaryCaptureError, FrozenEpochBoundary, capture_continuation, retain_outcome_schedule,
    retain_schedule,
};
use plan::{BoundaryInputs, boundary_inputs};

impl From<String> for Attempt<BoundaryCaptureError> {
    fn from(message: String) -> Self {
        Self::Rejected(BoundaryCaptureError::Invalid(message))
    }
}
impl From<&str> for Attempt<BoundaryCaptureError> {
    fn from(message: &str) -> Self {
        Self::Rejected(BoundaryCaptureError::Invalid(message.into()))
    }
}

use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::Algorithm;
use iroha_data_model::sumeragi::epoch::{BeaconEpochBindingV1, InstalledBeaconEpochBindingV1};
use iroha_data_model::{
    NetworkId,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetId},
    consensus::{ConsensusKeyRecord, ConsensusKeyRole, GlobalThresholdBeaconChainAnchorV1},
    nexus::{PublicLaneValidatorRecord, ValidatorElectionPolicyV1},
    sumeragi::epoch::{MAX_VALIDATORS, ValidatorEpochContextV1, validator_seat_rank},
};
use iroha_model_base::{peer::PeerId, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;

use crate::{
    beacon::{
        GlobalThresholdBeaconSessionBindingV1,
        authenticated_global_threshold_beacon_roster_hash_iter_v1,
        global_threshold_beacon_npos_successor_seed_v1,
        validate_persisted_global_threshold_beacon_pulse_v1,
        verify_finalized_global_threshold_beacon_pulse_v1,
    },
    smartcontracts::isi::staking::{
        validator_election_eligible_at_height, validator_tenure_contains_height,
    },
    state::{
        BlockHashRead, GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, WorldReadOnly,
        validate_public_lane_stake_reserves,
    },
};

/// Immutable, once-reconciled custody source for selection or all-seat readiness.
///
/// The funded reference index rejects duplicate primary-lane peer bindings and never copies
/// account, stake, key or proof storage. Its exact backing remains charged until this view drops.
pub(super) struct CheckedElectionView<'a> {
    policy: &'a ValidatorElectionPolicyV1,
    primary: ChargedBuffer<CheckedSeat<'a>>,
    keys: ChargedBuffer<&'a ConsensusKeyRecord>,
}
#[derive(Clone, Copy)]
struct CheckedSeat<'a> {
    record: &'a PublicLaneValidatorRecord,
    custody: Option<&'a (AssetId, Quantity)>,
}

impl<'a> CheckedElectionView<'a> {
    /// Reconcile all source reserves once and authenticate the frozen XOR definition.
    /// Only XOR identity is compared with today's parameters: previously frozen floors,
    /// committee ceiling and target interval are never reinterpreted after selection.
    pub(super) fn new(
        world: &'a impl WorldReadOnly,
        policy: &'a ValidatorElectionPolicyV1,
        budget: &AllocationBudget,
    ) -> Result<Self, Attempt<BoundaryCaptureError>> {
        policy.validate()?;
        let parameters = world
            .sumeragi_npos_parameters()
            .map_err(|error| error.map_rejection(BoundaryCaptureError::Invalid))?
            .ok_or("validator selection lacks signed NPoS parameters")?;
        if parameters.xor_asset_definition_id != policy.xor_asset_definition_id {
            return Err("frozen election currency differs from network XOR".into());
        }
        let definition = world
            .asset_definitions()
            .get(&policy.xor_asset_definition_id)
            .ok_or("canonical XOR definition is absent")?;
        if definition.spec().scale() != Some(policy.asset_scale)
            || definition.balance_scope_policy() != AssetBalancePolicy::Global
        {
            return Err("canonical XOR must use global nine-decimal custody".into());
        }
        validate_public_lane_stake_reserves(world)
            .map_err(|error| error.map_rejection(BoundaryCaptureError::Invalid))?;
        for (_, (asset, held)) in world.public_lane_stake_custody().iter() {
            if asset.scope() != &AssetBalanceScope::Global
                || held.scale() > policy.asset_scale
                || world
                    .assets()
                    .get(asset)
                    .is_none_or(|balance| balance.as_ref().scale() > policy.asset_scale)
            {
                return Err("staking source contains scoped or over-precision XOR custody".into());
            }
        }
        let count = world
            .public_lane_validators()
            .iter()
            .filter(|(key, _)| key.0 == LaneId::SINGLE)
            .count();
        let mut primary = ChargedBuffer::new(count, budget).map_err(BoundaryCaptureError::from)?;
        let mut custody = world.public_lane_stake_custody().iter().peekable();
        for (key, record) in world
            .public_lane_validators()
            .iter()
            .filter(|(key, _)| key.0 == LaneId::SINGLE)
        {
            while custody.peek().is_some_and(|(held_key, _)| *held_key < key) {
                custody.next();
            }
            let held = custody
                .peek()
                .filter(|(held_key, _)| *held_key == key)
                .map(|(_, value)| *value);
            primary
                .try_push(CheckedSeat {
                    record,
                    custody: held,
                })
                .map_err(|_| "election source changed during capture")?;
        }
        primary
            .as_mut_slice()
            .sort_unstable_by(|a, b| a.record.peer_id.cmp(&b.record.peer_id));
        if primary
            .as_slice()
            .windows(2)
            .any(|pair| pair[0].record.peer_id == pair[1].record.peer_id)
        {
            return Err("canonical primary-lane custody repeats a consensus peer".into());
        }
        let key_count = world
            .consensus_keys()
            .iter()
            .filter(|(id, _)| id.role == ConsensusKeyRole::Validator)
            .count();
        let mut keys = ChargedBuffer::new(key_count, budget).map_err(BoundaryCaptureError::from)?;
        for (id, key) in world
            .consensus_keys()
            .iter()
            .filter(|(id, _)| id.role == ConsensusKeyRole::Validator)
        {
            if id != &key.id {
                return Err("candidate key has a noncanonical store identity".into());
            }
            keys.try_push(key)
                .map_err(|_| "candidate key source changed during capture")?;
        }
        keys.as_mut_slice()
            .sort_unstable_by(|a, b| a.public_key.cmp(&b.public_key));
        Ok(Self {
            policy,
            primary,
            keys,
        })
    }

    #[cfg(test)]
    /// Exact source for one peer, if it retains enough real XOR throughout the target tenure.
    /// Missing custody fails the target attempt; it never permits a smaller activation roster.
    pub(super) fn eligible(
        &self,
        peer: &PeerId,
        first: u64,
        last: u64,
    ) -> Option<&'a PublicLaneValidatorRecord> {
        let index = self
            .primary
            .as_slice()
            .binary_search_by(|seat| seat.record.peer_id.cmp(peer))
            .ok()?;
        let seat = &self.primary.as_slice()[index];
        self.eligible_record(seat, first, last)
            .then_some(seat.record)
    }

    #[cfg(test)]
    /// Readiness of an already frozen seat ignores a later voluntary election exit request.
    /// Its actual tenure, custody and frozen minimum remain binding through the target epoch.
    /// Mutable fresh BLS registration is deliberately not consulted here.
    pub(super) fn ready(
        &self,
        peer: &PeerId,
        first: u64,
        last: u64,
    ) -> Option<&'a PublicLaneValidatorRecord> {
        let index = self
            .primary
            .as_slice()
            .binary_search_by(|seat| seat.record.peer_id.cmp(peer))
            .ok()?;
        let seat = &self.primary.as_slice()[index];
        let record = seat.record;
        (first > 0
            && last >= first
            && validator_tenure_contains_height(record, first).is_ok_and(|contains| contains)
            && validator_tenure_contains_height(record, last).is_ok_and(|contains| contains)
            && self.has_custody(seat))
        .then_some(record)
    }

    /// Apply an existing attempt's immutable eligibility floors to the same reconciled source.
    pub(super) fn ready_under(
        &self,
        policy: &ValidatorElectionPolicyV1,
        peer: &PeerId,
        first: u64,
        last: u64,
    ) -> Option<&'a PublicLaneValidatorRecord> {
        if policy.validate().is_err()
            || policy.xor_asset_definition_id != self.policy.xor_asset_definition_id
        {
            return None;
        }
        let index = self
            .primary
            .as_slice()
            .binary_search_by(|seat| seat.record.peer_id.cmp(peer))
            .ok()?;
        let seat = &self.primary.as_slice()[index];
        (first > 0
            && last >= first
            && validator_tenure_contains_height(seat.record, first).is_ok_and(|contains| contains)
            && validator_tenure_contains_height(seat.record, last).is_ok_and(|contains| contains)
            && Self::has_custody_under(seat, policy))
        .then_some(seat.record)
    }

    fn eligible_record(&self, seat: &CheckedSeat<'_>, first: u64, last: u64) -> bool {
        let record = seat.record;
        if first == 0
            || last < first
            || !validator_election_eligible_at_height(record, first)
            || !validator_election_eligible_at_height(record, last)
        {
            return false;
        }
        self.has_custody(seat)
    }

    fn has_custody(&self, seat: &CheckedSeat<'_>) -> bool {
        Self::has_custody_under(seat, self.policy)
    }

    fn has_custody_under(seat: &CheckedSeat<'_>, policy: &ValidatorElectionPolicyV1) -> bool {
        if seat.record.self_stake < policy.min_self_bond
            || seat.record.total_stake.is_zero()
            || seat.record.self_stake.scale() > policy.asset_scale
            || seat.record.total_stake.scale() > policy.asset_scale
        {
            return false;
        }
        // new() already reconciled shares, aggregate reserve and additive reward backing.
        let Some((asset, held)) = seat.custody else {
            return false;
        };
        asset.definition() == &policy.xor_asset_definition_id
            && asset.scope() == &AssetBalanceScope::Global
            && !held.is_zero()
    }

    /// Rank every custody-eligible candidate without allocating a pool-sized ranking buffer.
    /// E+1 prepares the target beacon transcript after this E election; selection requires
    /// the exact consented BLS identity and real PoP, never future beacon-share readiness.
    pub(super) fn select(
        &self,
        network: NetworkId,
        selection_epoch: u64,
        election_seed: [u8; 32],
        first: u64,
        last: u64,
    ) -> Result<SelectedCommittee<'a>, String> {
        if last
            .checked_sub(first)
            .and_then(|distance| distance.checked_add(1))
            != Some(self.policy.epoch_length_blocks)
        {
            return Err("selection target differs from its frozen policy interval".into());
        }
        let preparation_delay = if cfg!(all(test, sumeragi_core_mutation = "HC100")) {
            1
        } else {
            2
        };
        let target_epoch = selection_epoch
            .checked_add(preparation_delay)
            .ok_or("target epoch overflows")?;
        let mut selected = SelectedCommittee::empty();
        for seat in self.primary.as_slice() {
            let record = seat.record;
            if !self.eligible_record(seat, first, last) {
                continue;
            }
            let Some(proof) = selection_pop(self.keys.as_slice(), &record.peer_id, first, last)?
            else {
                continue;
            };
            let rank = validator_seat_rank(
                network,
                selection_epoch,
                target_epoch,
                election_seed,
                &record.peer_id,
            )?;
            selected.insert(
                RankedSeat {
                    record,
                    proof,
                    rank,
                },
                self.policy.max_validators as usize,
            );
        }
        selected.finish();
        Ok(selected)
    }
}

/// An ordered borrowed target seat. The original prestate owns its identities and real proof.
#[derive(Clone, Copy)]
pub(super) struct RankedSeat<'a> {
    pub(super) record: &'a PublicLaneValidatorRecord,
    pub(super) proof: &'a [u8],
    rank: [u8; 32],
}

/// At most31 seats, all equal votes; no selected peer or proof is cloned here.
pub(super) struct SelectedCommittee<'a> {
    seats: [Option<RankedSeat<'a>>; MAX_VALIDATORS],
    count: usize,
}
impl<'a> SelectedCommittee<'a> {
    fn empty() -> Self {
        Self {
            seats: [None; MAX_VALIDATORS],
            count: 0,
        }
    }
    fn insert(&mut self, seat: RankedSeat<'a>, cap: usize) {
        let position = (0..self.count)
            .find(|index| {
                let current = self.seats[*index]
                    .as_ref()
                    .expect("initialized rank prefix");
                (seat.rank, &seat.record.peer_id) < (current.rank, &current.record.peer_id)
            })
            .unwrap_or(self.count);
        if position >= cap {
            return;
        }
        let count = (self.count + 1).min(cap);
        for index in (position + 1..count).rev() {
            self.seats[index] = self.seats[index - 1];
        }
        self.seats[position] = Some(seat);
        self.count = count;
    }
    fn finish(&mut self) {
        let count = if self.count < 4 {
            0
        } else {
            1 + 3 * ((self.count - 1) / 3)
        };
        self.seats[count..].fill(None);
        self.count = count;
        self.seats[..count].sort_unstable_by(|left, right| {
            left.as_ref()
                .expect("initialized selected prefix")
                .record
                .peer_id
                .cmp(
                    &right
                        .as_ref()
                        .expect("initialized selected prefix")
                        .record
                        .peer_id,
                )
        });
    }
    pub(super) fn seats(&self) -> impl ExactSizeIterator<Item = &RankedSeat<'a>> {
        self.seats[..self.count]
            .iter()
            .map(|seat| seat.as_ref().expect("initialized selected prefix"))
    }
}

/// Read only a complete, unbounded Validator-role key, with an actual proof of possession.
/// Invalid matching stored proofs refuse the source rather than silently altering the pool.
fn selection_pop<'a>(
    keys: &[&'a ConsensusKeyRecord],
    peer: &PeerId,
    first: u64,
    last: u64,
) -> Result<Option<&'a [u8]>, String> {
    if peer.public_key().algorithm() != Algorithm::BlsNormal {
        return Ok(None);
    }
    let mut found: Option<&[u8]> = None;
    let start = keys.partition_point(|key| key.public_key < *peer.public_key());
    for key in keys[start..]
        .iter()
        .copied()
        .take_while(|key| key.public_key == *peer.public_key())
    {
        if key.expiry_height.is_some()
            || !key.is_live_at(first, 0, 0)
            || !key.is_live_at(last, 0, 0)
        {
            continue;
        }
        let pop = key
            .pop
            .as_deref()
            .ok_or("candidate consensus key lacks its original PoP")?;
        iroha_crypto::bls_normal_pop_verify(peer.public_key(), pop)
            .map_err(|error| error.to_string())?;
        if found.is_some_and(|previous| previous != pop) {
            return Err("candidate key has conflicting original proofs".into());
        }
        found = Some(pop);
    }
    Ok(found)
}

/// Fresh entropy authenticated against the exact last committed pre-boundary block.
pub(super) struct BoundaryEntropy {
    pub(super) leader_seed: [u8; 32],
    pub(super) election_seed: [u8; 32],
    pub(super) beacon: InstalledBeaconEpochBindingV1,
}

/// Reverify the unique B−1 threshold pulse against its actual B−2 parent and incumbent session.
/// A decoded pulse or the latest-pointer alone is never authoritative randomness.
pub(super) fn authenticated_boundary_entropy(
    world: &impl WorldReadOnly,
    hashes: &(impl BlockHashRead + ?Sized),
    current: &ValidatorEpochContextV1,
    boundary_height: u64,
) -> Result<BoundaryEntropy, String> {
    current.validate()?;
    if current.mode != iroha_data_model::parameter::system::ConsensusMode::Npos
        || current.authorization.last_height != boundary_height
    {
        return Err("entropy is not requested at the current epoch boundary".into());
    }
    let pulse_height = boundary_height
        .checked_sub(1)
        .ok_or("boundary lacks pulse height")?;
    let anchor_height = pulse_height
        .checked_sub(1)
        .filter(|height| *height > 0)
        .ok_or("boundary lacks authenticated pulse parent")?;
    if u64::try_from(hashes.hash_count()).ok() != Some(pulse_height) {
        return Err("boundary source is not its exact committed prestate".into());
    }
    let anchor_index =
        usize::try_from(anchor_height - 1).map_err(|_| "pulse parent index overflows")?;
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: anchor_height,
        block_hash: *hashes
            .hash_at(anchor_index)
            .ok_or("pulse parent is absent")?,
    };
    let mut at_height = world
        .global_beacon_pulses()
        .iter()
        .filter(|(_, pulse)| pulse.height == pulse_height);
    let (key, pulse) = at_height
        .next()
        .ok_or("mandatory fresh preboundary pulse is absent")?;
    if at_height.next().is_some()
        || key != &pulse.pulse_id
        || world
            .global_beacon_pulses()
            .iter()
            .any(|(_, other)| other.height > pulse_height)
        || pulse.network_id != current.network_id
        || pulse.context.epoch != current.authorization.epoch
        || pulse.context.epoch_context_id != current.context_id()?
        || pulse.finalized_chain_anchor != anchor
        || world.active_global_beacon_key_session() != Some(pulse.session_id)
    {
        return Err("preboundary pulse differs from exact incumbent prestate".into());
    }
    let record = world
        .global_beacon_key_sessions()
        .get(&pulse.session_id)
        .ok_or("incumbent beacon is absent")?;
    record.validate().map_err(|error| error.to_string())?;
    if !record.is_active_at(pulse_height)
        || !record.is_active_at(boundary_height)
        || record.session.adaptive_dkg.session.authority_generation
            != current.authorization.authority_generation
    {
        return Err("incumbent beacon is not active through its boundary".into());
    }
    let peers = current.committee.iter().map(|member| &member.validator);
    let roster_hash =
        authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, peers)
            .map_err(|error| error.to_string())?;
    let beacon = InstalledBeaconEpochBindingV1 {
        session_id: pulse.session_id,
        transcript_hash: pulse.transcript_hash,
    };
    if current.authorization.beacon != BeaconEpochBindingV1::Bootstrap
        && current.authorization.beacon != BeaconEpochBindingV1::Installed(beacon)
    {
        return Err("fresh pulse changed the incumbent authorized beacon".into());
    }
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: current.network_id,
        session_id: pulse.session_id,
        roster_hash,
        transcript_hash: pulse.transcript_hash,
    };
    let session = &record.session;
    session
        .check_binding(&binding)
        .map_err(|error| error.to_string())?;
    // The stored pulse was inserted only by pristine native admission and its complete epoch
    // binding is checked above. Its native parent identities remain signed in that exact row.
    let verified =
        verify_finalized_global_threshold_beacon_pulse_v1(&session, pulse, anchor, &pulse.context)
            .map_err(|error| error.to_string())?;
    if validate_persisted_global_threshold_beacon_pulse_v1(pulse)
        .map_err(|error| error.to_string())?
        != verified
        || world
            .global_beacon_latest_pulse()
            .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
            != Some(&verified)
    {
        return Err("preboundary pulse is not the canonical authenticated history tail".into());
    }
    let next_epoch = current
        .authorization
        .epoch
        .checked_add(1)
        .ok_or("successor epoch overflows")?;
    let leader_seed =
        global_threshold_beacon_npos_successor_seed_v1(pulse, boundary_height, next_epoch);
    let election_seed = election_seed(current.network_id, current.authorization.epoch, pulse)?;
    if leader_seed == [0; 32] || election_seed == [0; 32] {
        return Err("boundary entropy is zero".into());
    }
    Ok(BoundaryEntropy {
        leader_seed,
        election_seed,
        beacon,
    })
}

/// Canonical independent election entropy projection from the genuinely certified B−1 pulse.
/// Runtime and history readers share this exact domain; the caller must authenticate the pulse.
pub(crate) use iroha_data_model::sumeragi_finality::election_seed;

/// Freeze the exact original-prestate boundary with complete retained allocation custody.
/// The returned sealed capability is the only input accepted by the native boundary finalizer.
pub(crate) fn freeze_boundary(
    world: &impl WorldReadOnly,
    hashes: &(impl BlockHashRead + ?Sized),
    current: &ValidatorEpochContextV1,
    policy: &ValidatorElectionPolicyV1,
    height: u64,
    original_budget: &AllocationBudget,
) -> Result<Option<FrozenEpochBoundary>, Attempt<BoundaryCaptureError>> {
    let Some(inputs) = boundary_inputs(world, hashes, current, policy, height, original_budget)?
    else {
        return Ok(None);
    };
    owned::materialize(&inputs, original_budget)
        .map(Some)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests;
