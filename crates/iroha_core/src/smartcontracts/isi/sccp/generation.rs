//! Native committee generations and the liability clock (`specs/sccp.md` §4.2, §4.8).
//!
//! A generation retains the exact ordered consensus keys and the staking registration
//! resolved at creation. A later peer lookup cannot change who backed that generation.
//! These records are Core-owned execution state, persisted through the SCCP snapshot.

use super::{height::SccpHeightInputsV1, store};
use crate::state::{
    StateTransaction, WorldReadOnly,
    sccp_generation_custody::{GenerationAdmissionError, MemberRef, RetainedGeneration},
};
use iroha_data_model::{
    account::AccountId,
    sccp::params::{
        SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1, SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1,
        SCCP_MAX_VALIDITY_MS_V1, SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1,
    },
    sumeragi_finality::certified_result::committee_root,
};
use iroha_data_model::{block::BlockHeader, sccp::params::SccpParametersV1};
use iroha_model_base::topology::LaneId;
use iroha_schema::IntoSchema;
use mv::storage::StorageReadOnly;
use norito::{
    codec::{Decode, Encode},
    json::{JsonDeserialize, JsonSerialize},
};

/// Maximum extra liability-clock step beyond the configured heartbeat (one hour).
pub const SCCP_LC_SLACK_MS: u64 = 3_600_000;

/// Why a native committee generation started (§4.2.2).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sccp::generation::SccpGenerationCauseV1")]
#[norito(tag = "kind", content = "value")]
pub enum SccpGenerationCauseV1 {
    /// The signed genesis's original committee.
    Genesis,
    /// An authenticated epoch boundary changed the ordered keys.
    KeyChange,
    /// A heartbeat renewed the same keys.
    Heartbeat,
    /// Authenticated inputs recovered after a missed boundary.
    Resync,
}

/// The immutable staking registration that backed one generation member (G6).
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sccp::generation::SccpGenerationMemberV1")]
pub struct SccpGenerationMemberV1 {
    /// Staking authority lane of this registration.
    pub lane_id: LaneId,
    /// Canonical, domainless validator account.
    pub validator: AccountId,
    /// Activation height distinguishing this registration from a later registration.
    pub activation_height: u64,
}

/// The final height of an ended generation and the successor it names.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sccp::generation::SccpGenerationEndV1")]
pub struct SccpGenerationEndV1 {
    /// Last height certified by this generation.
    pub end_height: u64,
    /// Canonical time of the last height.
    pub end_timestamp_ms: u64,
    /// Ordered-key root of the successor.
    pub next_committee_root: [u8; 32],
    /// Validity granted to the successor at this handoff.
    pub successor_validity_ms: u64,
}

/// An authenticated native committee and its captured liability window.
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::smartcontracts::isi::sccp::generation::SccpCommitteeGenerationV1"
)]
pub struct SccpCommitteeGenerationV1 {
    /// Monotonic generation number, starting at one.
    pub generation: u64,
    /// Root of `keys` in their canonical consensus order.
    pub committee_root: [u8; 32],
    /// Compressed BLS12-381 keys; bitmap index `i` names `keys[i]`.
    pub keys: Vec<[u8; 48]>,
    /// Captured staking registrations in the same order; unresolved entries stay absent.
    pub members: Vec<Option<SccpGenerationMemberV1>>,
    /// Cause of this generation's creation.
    pub cause: SccpGenerationCauseV1,
    /// First height certified by this generation.
    pub start_height: u64,
    /// Canonical handoff time, or the genesis/resync block time.
    pub start_timestamp_ms: u64,
    /// Liability clock at the handoff, genesis or resync.
    pub start_lc: u64,
    /// Captured destination validity.
    pub validity_ms: u64,
    /// Destination deadline, with addition saturating at the timestamp limit.
    pub deadline_ms: u64,
    /// Captured interval for submitting forgery evidence.
    pub grace_ms: u64,
    /// Captured maximum wait for destination progress.
    pub progress_cap_ms: u64,
    /// Inclusive end of the time-based liability leg.
    pub liable_until_lc: u64,
    /// Clock at which all relevant destinations passed the deadline, if observed.
    pub dest_cleared_lc: Option<u64>,
    /// Last certified height and handoff, once this generation ends.
    pub end: Option<SccpGenerationEndV1>,
}

impl SccpCommitteeGenerationV1 {
    /// Check the record's structural, ordering and captured-time invariants.
    ///
    /// This does not authenticate keys or a snapshot. Production keys must come from the
    /// independently authenticated consensus schedule; snapshot restoration has its own
    /// execution-authority boundary.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let count = self.keys.len();
        self.generation > 0
            && self.start_height > 0
            && (4..=31).contains(&count)
            && (count - 1) % 3 == 0
            && self.keys.windows(2).all(|pair| pair[0] < pair[1])
            && self.keys.iter().all(|key| *key != [0; 48])
            && self.members.len() == count
            && self.members.iter().flatten().all(|member| {
                member.activation_height > 0 && member.activation_height <= self.start_height
            })
            && committee_root(&self.keys) == Some(self.committee_root)
            && self.committee_root != [0; 32]
            && (1..=SCCP_MAX_VALIDITY_MS_V1).contains(&self.validity_ms)
            && (SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1..=SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1)
                .contains(&self.grace_ms)
            && self.progress_cap_ms <= SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1
            && self.start_lc <= self.start_timestamp_ms
            && self.deadline_ms == self.start_timestamp_ms.saturating_add(self.validity_ms)
            && self.liable_until_lc
                == self
                    .start_lc
                    .saturating_add(self.validity_ms)
                    .saturating_add(self.grace_ms)
            && self
                .dest_cleared_lc
                .is_none_or(|clock| self.end.is_some() && clock >= self.start_lc)
            && self.end.as_ref().is_none_or(|end| {
                end.end_height >= self.start_height
                    && end.end_timestamp_ms >= self.start_timestamp_ms
                    && end.next_committee_root != [0; 32]
                    && (1..=SCCP_MAX_VALIDITY_MS_V1).contains(&end.successor_validity_ms)
            })
    }

    /// The single inclusive liability predicate for evidence, stake release and pruning.
    ///
    /// The current generation always remains liable. Destination progress cannot shorten
    /// the time leg, and delayed progress keeps a full captured grace interval.
    #[must_use]
    pub fn is_liable(&self, current: u64, clock: u64) -> bool {
        self.generation == current
            || clock <= self.liable_until_lc
            || match self.dest_cleared_lc {
                None => clock <= self.liable_until_lc.saturating_add(self.progress_cap_ms),
                Some(cleared) => clock <= cleared.saturating_add(self.grace_ms),
            }
    }
}

/// Advance the liability clock without consuming a halt as elapsed liability (§4.8 S0).
///
/// Inputs are the parent clock and canonical parent/current times. Saturating arithmetic
/// makes the bookkeeping total at the timestamp limit; canonical monotonic time and
/// `previous_clock <= parent_time_ms` imply the result does not exceed `time_ms`.
#[must_use]
pub fn advance_liability_clock(
    previous_clock: u64,
    parent_time_ms: u64,
    time_ms: u64,
    heartbeat_ms: u64,
) -> u64 {
    previous_clock.saturating_add(
        time_ms
            .saturating_sub(parent_time_ms)
            .min(heartbeat_ms.saturating_add(SCCP_LC_SLACK_MS)),
    )
}

/// The exact generation fields to include in this block's finality header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpGenerationStepV1 {
    /// Generation certifying this block, after resync and before any new handoff.
    pub generation: u64,
    /// Authenticated ordered-key root of this block's committee.
    pub committee_root: [u8; 32],
    /// Successor validity when this block rotates; zero otherwise.
    pub successor_validity_ms: u64,
    /// Successor root when this block rotates; zero otherwise.
    pub next_committee_root: [u8; 32],
}

/// Whether a heartbeat is due against the committed parent generation (G2, G4).
#[must_use]
pub fn heartbeat_due(world: &(impl WorldReadOnly + ?Sized), time_ms: u64) -> bool {
    if *store::degraded_run::get(world) >= 2 {
        return false;
    }
    let Some(params) = store::parameters::get(world) else {
        return false;
    };
    let Some(current) =
        store::committee_generations::get(world, store::committee_current::get(world))
    else {
        return false;
    };
    time_ms >= current.start_timestamp_ms
        && time_ms - current.start_timestamp_ms >= params.committee_heartbeat_ms
}

fn keys_are_canonical(keys: &[[u8; 48]]) -> bool {
    (4..=31).contains(&keys.len())
        && (keys.len() - 1) % 3 == 0
        && keys.windows(2).all(|pair| pair[0] < pair[1])
        && keys.iter().all(|key| *key != [0; 48])
}

fn captured_members<'a>(
    stx: &'a StateTransaction<'_, '_>,
    keys: &[[u8; 48]],
    height: u64,
) -> [Option<MemberRef<'a>>; 31] {
    let mut members = [None; 31];
    for (slot, key) in members.iter_mut().zip(keys) {
        *slot =
            (|| {
                let mut found = stx.world.public_lane_validators().iter().filter(
                    |(stored_key, record)| {
                        crate::state::public_lane_validator_record_matches_key(stored_key, record)
                        && record.activation_height > 0
                        && stx.is_lane_active_for_authority(record.lane_id)
                        && stx.staking_authority_lane(record.lane_id) == Some(record.lane_id)
                        && crate::smartcontracts::isi::staking::validator_tenure_contains_height(
                            record, height,
                        )
                        .unwrap_or(false)
                        && record.peer_id.public_key().try_to_bytes().is_ok_and(
                            |(algorithm, bytes)| {
                                algorithm == iroha_crypto::Algorithm::BlsNormal
                                    && bytes == key
                            },
                        )
                    },
                );
                let (_, record) = found.next()?;
                // A conflicting registration is never resolved by map iteration order.
                if found.next().is_some() {
                    return None;
                }
                Some(MemberRef {
                    lane_id: record.lane_id,
                    validator: &record.validator,
                    activation_height: record.activation_height,
                })
            })();
    }
    members
}

struct GenerationStart<'a> {
    generation: u64,
    keys: &'a [[u8; 48]],
    cause: SccpGenerationCauseV1,
    height: u64,
    time_ms: u64,
    clock: u64,
}

fn new_generation(
    stx: &StateTransaction<'_, '_>,
    params: &SccpParametersV1,
    start: GenerationStart<'_>,
) -> Result<RetainedGeneration, GenerationAdmissionError> {
    let record = SccpCommitteeGenerationV1 {
        generation: start.generation,
        committee_root: committee_root(start.keys).ok_or(GenerationAdmissionError::Invalid)?,
        keys: Vec::new(),
        members: Vec::new(),
        cause: start.cause,
        start_height: start.height,
        start_timestamp_ms: start.time_ms,
        start_lc: start.clock,
        validity_ms: params.committee_validity_ms,
        deadline_ms: start.time_ms.saturating_add(params.committee_validity_ms),
        grace_ms: params.forgery_evidence_grace_ms,
        progress_cap_ms: params.destination_progress_cap_ms,
        liable_until_lc: start
            .clock
            .saturating_add(params.committee_validity_ms)
            .saturating_add(params.forgery_evidence_grace_ms),
        dest_cleared_lc: None,
        end: None,
    };
    let members = captured_members(stx, start.keys, start.height);
    RetainedGeneration::try_build(
        record,
        start.keys,
        &members[..start.keys.len()],
        stx.world.sccp_committee_generations.allocation_budget(),
    )
}

/// Fully checked generation changes, held until the corresponding active X is accepted.
///
/// Constructing or dropping this plan does not change World. Only the finalizer publishes
/// it, after the parent's anchor and the complete finality header have both been accepted.
pub(super) struct SccpGenerationPlanV1 {
    step: SccpGenerationStepV1,
    updates: [Option<RetainedGeneration>; 3],
    current: u64,
    genesis_clock: Option<u64>,
}

impl SccpGenerationPlanV1 {
    /// Return the outgoing generation fields for the candidate active header.
    pub(super) fn step(&self) -> SccpGenerationStepV1 {
        self.step
    }

    /// Publish all validated records after the caller has accepted their active header.
    pub(super) fn publish(
        self,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), GenerationAdmissionError> {
        for record in self.updates.into_iter().flatten() {
            store::committee_generations::insert_owned(stx, record.generation, record)?;
        }
        store::committee_current::set(stx, self.current);
        if let Some(clock) = self.genesis_clock {
            store::liability_clock::set(stx, clock);
        }
        // TODO: publish generation-created, resync and unresolved-member events with the
        // coordinated shared-model finality migration; do not reuse attestation events.
        Ok(())
    }
}

/// Plan G1/G7/G2 without publishing a handoff before its header is accepted.
///
/// Inconsistent bookkeeping returns `None` without writing. At a normal handoff the
/// returned header fields name the outgoing generation, even though publication advances
/// current. This plan is private to the SCCP finalizer.
pub(super) fn plan_generation_step(
    stx: &StateTransaction<'_, '_>,
    header: &BlockHeader,
    inputs: &SccpHeightInputsV1,
    parent_time_ms: Option<u64>,
) -> Result<Option<SccpGenerationPlanV1>, GenerationAdmissionError> {
    macro_rules! some {
        ($value:expr) => {
            match $value {
                Some(v) => v,
                None => return Ok(None),
            }
        };
    }
    macro_rules! built {
        ($value:expr) => {
            match $value {
                Ok(v) => v,
                Err(GenerationAdmissionError::Invalid) => return Ok(None),
                Err(e) => return Err(e),
            }
        };
    }
    let budget = stx.world.sccp_committee_generations.allocation_budget();
    let height = header.height().get();
    if inputs.height != height
        || !keys_are_canonical(&inputs.keys)
        || inputs.is_boundary() != inputs.next_keys.is_some()
    {
        return Ok(None);
    }
    let following = inputs.next_keys.as_deref().unwrap_or(&inputs.keys);
    if !keys_are_canonical(following) {
        return Ok(None);
    }
    let params = *some!(store::parameters::get(&*stx.world).as_ref());
    some!(params.validate().ok());
    let time_ms = header.creation_time_ms;
    let clock = *store::liability_clock::get(&*stx.world);
    let root = some!(committee_root(&inputs.keys));
    let next_root = some!(committee_root(following));
    let current_id = *store::committee_current::get(&*stx.world);
    let mut updates = std::array::from_fn(|_| None);
    let mut update_count = 0;
    let mut current = if current_id == 0 && header.is_genesis() {
        built!(new_generation(
            stx,
            &params,
            GenerationStart {
                generation: 1,
                keys: &inputs.keys,
                cause: SccpGenerationCauseV1::Genesis,
                height,
                time_ms,
                clock: time_ms,
            },
        ))
    } else {
        some!(store::committee_generations::get_retained(
            &*stx.world,
            &current_id
        ))
        .clone()
    };
    if !current.is_well_formed() || current.end.is_some() || current.start_height > height {
        return Ok(None);
    }
    if current.committee_root != root {
        current = built!(current.with_end(
            SccpGenerationEndV1 {
                end_height: some!(height.checked_sub(1)),
                end_timestamp_ms: some!(parent_time_ms),
                next_committee_root: root,
                successor_validity_ms: params.committee_validity_ms,
            },
            budget
        ));
        let generation = some!(current.generation.checked_add(1));
        updates[update_count] = Some(current);
        update_count += 1;
        current = built!(new_generation(
            stx,
            &params,
            GenerationStart {
                generation,
                keys: &inputs.keys,
                cause: SccpGenerationCauseV1::Resync,
                height,
                time_ms,
                clock,
            },
        ));
    }
    let mut step = SccpGenerationStepV1 {
        generation: current.generation,
        committee_root: root,
        successor_validity_ms: 0,
        next_committee_root: [0; 32],
    };
    let key_change = inputs.is_boundary() && next_root != current.committee_root;
    let beat = time_ms >= current.start_timestamp_ms
        && time_ms - current.start_timestamp_ms >= params.committee_heartbeat_ms;
    if key_change || beat {
        current = built!(current.with_end(
            SccpGenerationEndV1 {
                end_height: height,
                end_timestamp_ms: time_ms,
                next_committee_root: next_root,
                successor_validity_ms: params.committee_validity_ms,
            },
            budget
        ));
        let generation = some!(current.generation.checked_add(1));
        updates[update_count] = Some(current);
        update_count += 1;
        current = built!(new_generation(
            stx,
            &params,
            GenerationStart {
                generation,
                keys: following,
                cause: if key_change {
                    SccpGenerationCauseV1::KeyChange
                } else {
                    SccpGenerationCauseV1::Heartbeat
                },
                height: some!(height.checked_add(1)),
                time_ms,
                clock,
            },
        ));
        step.successor_validity_ms = current.validity_ms;
        step.next_committee_root = next_root;
    }
    let current_id = current.generation;
    updates[update_count] = Some(current);
    if updates
        .iter()
        .flatten()
        .any(|record| !record.is_well_formed())
    {
        return Ok(None);
    }
    Ok(Some(SccpGenerationPlanV1 {
        step,
        updates,
        current: current_id,
        genesis_clock: header.is_genesis().then_some(time_ms),
    }))
}

/// Record authenticated destination progress for at most 64 ended generations (L5).
///
/// Every non-retired route revision participates, including staged revisions. A missing or
/// frozen light client cannot clear a destination. Clearance is strictly after the captured
/// deadline and never changes the record's captured grace or time-based liability window.
pub fn clear_destination_progress(
    stx: &mut StateTransaction<'_, '_>,
) -> Result<(), GenerationAdmissionError> {
    use iroha_data_model::sccp::registry::SccpRouteActivationV1;
    let clock = *store::liability_clock::get(&*stx.world);
    let mut candidates: [Option<RetainedGeneration>; 64] = std::array::from_fn(|_| None);
    for (slot, (_, record)) in candidates.iter_mut().zip(
        stx.world
            .sccp_committee_generations
            .iter()
            .filter(|(_, record)| record.end.is_some() && record.dest_cleared_lc.is_none())
            .take(64),
    ) {
        let cleared = store::routes::iter(&*stx.world).all(|(network, route)| {
            !route
                .revisions
                .values()
                .any(|revision| revision.activation != SccpRouteActivationV1::Retired)
                || store::light_clients::get(&*stx.world, network).is_some_and(|client| {
                    !client.is_frozen()
                        && client.head.latest_finalized.source_time_ms > record.deadline_ms
                })
        });
        if cleared {
            *slot = Some(record.clone());
        }
    }
    for record in candidates.into_iter().flatten() {
        let record = match record.with_progress(
            clock,
            stx.world.sccp_committee_generations.allocation_budget(),
        ) {
            Ok(record) => record,
            // Preserve the previous skip of an inconsistent clearance clock.
            Err(GenerationAdmissionError::Invalid) => continue,
            Err(error) => return Err(error),
        };
        store::committee_generations::insert_owned(stx, record.generation, record)?;
    }
    // TODO: emit SccpGenerationDestinationCleared with the shared-model event migration.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SccpCommitteeGenerationV1 {
        let keys = (1..=4).map(|seed| [seed; 48]).collect::<Vec<_>>();
        let validity_ms = 86_400_000;
        let grace_ms = SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1;
        SccpCommitteeGenerationV1 {
            generation: 1,
            committee_root: committee_root(&keys).unwrap(),
            keys,
            members: vec![None; 4],
            cause: SccpGenerationCauseV1::Genesis,
            start_height: 1,
            start_timestamp_ms: 1_000,
            start_lc: 1_000,
            validity_ms,
            deadline_ms: 1_000 + validity_ms,
            grace_ms,
            progress_cap_ms: 100,
            liable_until_lc: 1_000 + validity_ms + grace_ms,
            dest_cleared_lc: None,
            end: None,
        }
    }

    #[test]
    fn structural_checks_bind_order_geometry_root_and_time() {
        let valid = sample();
        assert!(valid.is_well_formed());
        let mut bad = valid.clone();
        bad.keys.swap(0, 1);
        bad.committee_root = committee_root(&bad.keys).unwrap();
        assert!(!bad.is_well_formed());
        let mut bad = valid.clone();
        bad.keys.pop();
        bad.members.pop();
        bad.committee_root = committee_root(&bad.keys).unwrap();
        assert!(!bad.is_well_formed());
        let mut bad = valid.clone();
        bad.committee_root[0] ^= 1;
        assert!(!bad.is_well_formed());
        let mut bad = valid.clone();
        bad.members.pop();
        assert!(!bad.is_well_formed());
        let mut bad = valid.clone();
        bad.deadline_ms += 1;
        assert!(!bad.is_well_formed());
        let mut bad = valid;
        bad.liable_until_lc += 1;
        assert!(!bad.is_well_formed());
    }

    #[test]
    fn native_generation_roundtrips_norito_and_tagged_snapshot_json() {
        for cause in [
            SccpGenerationCauseV1::Genesis,
            SccpGenerationCauseV1::KeyChange,
            SccpGenerationCauseV1::Heartbeat,
            SccpGenerationCauseV1::Resync,
        ] {
            let mut record = sample();
            record.cause = cause;
            record.end = Some(SccpGenerationEndV1 {
                end_height: 3,
                end_timestamp_ms: 3_000,
                next_committee_root: record.committee_root,
                successor_validity_ms: record.validity_ms,
            });
            record.dest_cleared_lc = Some(2_000);
            let frame = norito::to_bytes(&record).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<SccpCommitteeGenerationV1>(&frame).unwrap(),
                record
            );
            let json = norito::json::to_json(&record).unwrap();
            assert_eq!(
                norito::json::from_json::<SccpCommitteeGenerationV1>(&json).unwrap(),
                record
            );
            assert!(json.contains("kind"));
        }
    }

    #[test]
    fn current_generation_never_releases_liability() {
        assert!(sample().is_liable(1, u64::MAX));
    }

    #[test]
    fn time_and_uncleared_progress_boundaries_are_inclusive() {
        let generation = sample();
        assert!(generation.is_liable(2, generation.liable_until_lc));
        assert!(generation.is_liable(2, generation.liable_until_lc + 100));
        assert!(!generation.is_liable(2, generation.liable_until_lc + 101));
    }

    #[test]
    fn early_and_late_destination_clearance_keep_both_legs() {
        let mut generation = sample();
        generation.dest_cleared_lc = Some(generation.start_lc);
        assert!(generation.is_liable(2, generation.liable_until_lc));
        assert!(!generation.is_liable(2, generation.liable_until_lc + 1));
        let cleared = generation.liable_until_lc + 50;
        generation.dest_cleared_lc = Some(cleared);
        assert!(generation.is_liable(2, cleared + generation.grace_ms));
        assert!(!generation.is_liable(2, cleared + generation.grace_ms + 1));
    }

    #[test]
    fn zero_progress_cap_does_not_add_an_extra_window() {
        let mut generation = sample();
        generation.progress_cap_ms = 0;
        assert!(generation.is_liable(2, generation.liable_until_lc));
        assert!(!generation.is_liable(2, generation.liable_until_lc + 1));
    }

    #[test]
    fn liability_arithmetic_cannot_wrap_and_release_stake() {
        let mut generation = sample();
        generation.liable_until_lc = u64::MAX - 1;
        assert!(generation.is_liable(2, u64::MAX));
        generation.liable_until_lc = 0;
        generation.dest_cleared_lc = Some(u64::MAX - 1);
        assert!(generation.is_liable(2, u64::MAX));
    }

    #[test]
    fn ordinary_clock_tracks_time_but_a_halt_consumes_only_one_step() {
        let heartbeat = 86_400_000;
        assert_eq!(
            advance_liability_clock(1_000, 1_000, 2_000, heartbeat),
            2_000
        );
        assert_eq!(
            advance_liability_clock(1_000, 2_000, 100_000_000_000, heartbeat),
            1_000 + heartbeat + SCCP_LC_SLACK_MS
        );
        assert_eq!(
            advance_liability_clock(1_000, 2_000, 1_999, heartbeat),
            1_000
        );
        assert_eq!(
            advance_liability_clock(u64::MAX - 1, u64::MAX - 1, u64::MAX, u64::MAX),
            u64::MAX
        );
    }
}

#[cfg(test)]
#[path = "generation/tests.rs"]
mod transition_tests;
