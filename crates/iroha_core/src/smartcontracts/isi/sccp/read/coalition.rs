//! Current-generation collateral from original captured registrations and borrowed custody.

use super::{
    native::{SccpNativeReadControl, SccpNativeReadError},
    store,
};
use crate::{
    smartcontracts::isi::staking::{
        ensure_canonical_pending_unbond, validator_tenure_contains_height,
    },
    state::{
        StateReadOnly, WorldReadOnly, public_lane_stake_share_matches_key,
        public_lane_validator_record_matches_key,
    },
};
use iroha_data_model::nexus::PublicLaneValidatorRecord;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::{Quantity, QuantityAccumulator};
use mv::storage::StorageReadOnly as _;

type Result<T> = core::result::Result<T, SccpNativeReadError>;
const MAX: usize = 31;

fn unavailable() -> SccpNativeReadError {
    SccpNativeReadError::Unavailable("current generation collateral provenance is unavailable")
}

fn add(sum: &mut QuantityAccumulator, value: &Quantity) -> Result<()> {
    sum.try_add(value).map_err(|_| unavailable())
}

fn matches(sum: &QuantityAccumulator, value: &Quantity) -> Result<bool> {
    let mut expected = QuantityAccumulator::zero();
    add(&mut expected, value)?;
    Ok(sum.cmp_value(&expected).is_eq())
}

/// At most 31 stack rows; no stake records, keys, or amount limbs are cloned.
pub(super) fn floor(
    view: &(impl StateReadOnly + ?Sized),
    control: SccpNativeReadControl<'_>,
) -> Result<Option<QuantityAccumulator>> {
    super::native::deadline_check(control)?;
    let world = view.world();
    let current = *store::committee_current::get(world);
    if current == 0 {
        return Ok(None);
    }
    let generation = store::committee_generations::get(world, &current).ok_or_else(unavailable)?;
    if !store::committee_generations::valid_entry(&current, generation) {
        return Err(unavailable());
    }
    let count = generation.keys.len();
    if !(4..=MAX).contains(&count) || (count - 1) % 3 != 0 || generation.members.len() != count {
        return Err(unavailable());
    }
    let mut records: [Option<&PublicLaneValidatorRecord>; MAX] = [None; MAX];
    for (index, member) in generation.members.iter().enumerate() {
        let member = member.as_ref().ok_or_else(unavailable)?;
        if member.lane_id != LaneId::SINGLE
            || generation.members[..index].iter().any(|previous| {
                previous.as_ref().is_some_and(|previous| {
                    previous.lane_id == member.lane_id && previous.validator == member.validator
                })
            })
        {
            return Err(unavailable());
        }
    }
    for (key, record) in world.public_lane_validators().iter() {
        super::native::deadline_check(control)?;
        let Some(index) = generation.members.iter().position(|member| {
            member
                .as_ref()
                .is_some_and(|member| member.lane_id == key.0 && member.validator == key.1)
        }) else {
            continue;
        };
        let member = generation.members[index].as_ref().ok_or_else(unavailable)?;
        let (algorithm, key_bytes) = record
            .peer_id
            .public_key()
            .borrowed_parts()
            .map_err(|_| unavailable())?;
        if algorithm != iroha_crypto::Algorithm::BlsNormal || key_bytes != generation.keys[index] {
            return Err(unavailable());
        }
        if !public_lane_validator_record_matches_key(key, record)
            || record.activation_height != member.activation_height
            || record.stake_account != record.validator
            || !validator_tenure_contains_height(record, generation.start_height)
                .map_err(|_| unavailable())?
            || records[index].is_some()
        {
            return Err(unavailable());
        }
        records[index] = Some(record);
    }
    if records[..count].iter().any(Option::is_none) {
        return Err(unavailable());
    }
    // Bonded, self-bonded, and generation-height-eligible pending amounts.
    let mut sums = [[QuantityAccumulator::zero(); 3]; MAX];
    for (key, share) in world.public_lane_stake_shares().iter() {
        super::native::deadline_check(control)?;
        let Some(index) = records[..count].iter().position(|record| {
            record.is_some_and(|record| record.lane_id == key.0 && record.validator == key.1)
        }) else {
            continue;
        };
        if !public_lane_stake_share_matches_key(key, share) {
            return Err(unavailable());
        }
        add(&mut sums[index][0], &share.bonded)?;
        if key.2 == records[index].ok_or_else(unavailable)?.stake_account {
            add(&mut sums[index][1], &share.bonded)?;
        }
        for (request, pending) in &share.pending_unbonds {
            super::native::deadline_check(control)?;
            ensure_canonical_pending_unbond(request, pending).map_err(|_| unavailable())?;
            if pending.slashable_through_height >= generation.start_height {
                add(&mut sums[index][2], &pending.amount)?;
            }
        }
    }
    let mut consumed = [false; MAX];
    for (key, _) in world.sccp_forgery_offences().iter() {
        super::native::deadline_check(control)?;
        if key.generation() != current {
            continue;
        }
        if let Some(index) = generation.members.iter().position(|member| {
            member
                .as_ref()
                .is_some_and(|member| member.lane_id == key.1 && member.validator == key.2)
        }) {
            consumed[index] = true;
        }
    }
    let mut seizable = [QuantityAccumulator::zero(); MAX];
    for index in 0..count {
        let record = records[index].ok_or_else(unavailable)?;
        if !matches(&sums[index][0], &record.total_stake)?
            || !matches(&sums[index][1], &record.self_stake)?
        {
            return Err(unavailable());
        }
        if consumed[index] {
            continue;
        }
        let mut exposure = sums[index][0];
        exposure
            .try_add_accumulator(&sums[index][2])
            .map_err(|_| unavailable())?;
        exposure
            .try_scale_basis_points(view.nexus().staking.max_slash_bps)
            .map_err(|_| unavailable())?;
        seizable[index] = exposure;
    }
    seizable[..count].sort_unstable_by(QuantityAccumulator::cmp_value);
    let mut floor = QuantityAccumulator::zero();
    for amount in &seizable[..=(count - 1) / 3] {
        floor
            .try_add_accumulator(amount)
            .map_err(|_| unavailable())?;
    }
    super::native::deadline_check(control)?;
    Ok(Some(floor))
}

pub(super) fn capabilities(
    view: &(impl StateReadOnly + ?Sized),
    budget: &iroha_allocation::AllocationBudget,
    control: SccpNativeReadControl<'_>,
    paths: impl ExactSizeIterator<Item = &'static str> + Clone,
) -> Result<super::native::SccpNativeDataV1<super::api::SccpCapabilitiesV1>> {
    use super::api::{SccpCapabilitiesV1, SccpChainProfileViewV1, SccpLcProfileStatusV1};
    use iroha_sccp::light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1};
    use std::mem::size_of;

    let floor = floor(view, control)?;
    let magnitude_bytes = floor
        .as_ref()
        .map(QuantityAccumulator::admission_layout)
        .transpose()
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?
        .map_or(0, |layout| layout.size());
    let path_bytes = paths
        .clone()
        .try_fold(0_usize, |sum, path| sum.checked_add(path.len()))
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let bytes = paths
        .len()
        .checked_mul(size_of::<String>())
        .and_then(|size| size.checked_add(path_bytes))
        .and_then(|size| size.checked_add(view.chain_id().as_str().len()))
        .and_then(|size| size.checked_add(magnitude_bytes))
        .and_then(|size| size.checked_add(size_of::<SccpCapabilitiesV1>()))
        .and_then(|size| {
            size.checked_add(
                3 * (size_of::<SccpLcProfileStatusV1>() + size_of::<SccpChainProfileViewV1>()),
            )
        })
        .ok_or(SccpNativeReadError::PhysicalAllocation)?;
    let charge = budget.try_reserve_bytes(bytes)?;
    let mut path_templates = Vec::new();
    path_templates
        .try_reserve_exact(paths.len())
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    for path in paths {
        super::native::deadline_check(control)?;
        path_templates.push(copy_text(path)?);
    }
    let mut profiles = Vec::new();
    let mut statuses = Vec::new();
    profiles
        .try_reserve_exact(3)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    statuses
        .try_reserve_exact(3)
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let catalog = SccpLcProfileCatalogV1::compiled();
    let active = active_profiles(view, control)?;
    for network in SCCP_LC_PROFILE_NETWORKS_V1 {
        profiles.push(SccpChainProfileViewV1 {
            network,
            supported_until_ms: super::compiled_supported_until_ms(network),
        });
        if let Some(profile) = active.get(network) {
            let record =
                store::light_client_profiles::get(view.world(), &(network, profile.version));
            let supported_until_ms = catalog
                .resolve(&catalog.genesis().with(network, profile))
                .ok()
                .and_then(|profiles| profiles.supported_until_ms(network));
            statuses.push(SccpLcProfileStatusV1 {
                network,
                version: profile.version,
                profile_hash: profile.profile_hash,
                activation_height: record.map(|record| record.activation_height),
                proposal_id: record.map(|record| record.proposal_id),
                supported_until_ms,
            });
        }
    }
    let floor = floor
        .map(QuantityAccumulator::try_into_quantity)
        .transpose()
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    let data = super::capabilities_fields(
        view,
        floor,
        copy_text(view.chain_id().as_str())?,
        profiles,
        statuses,
        active.policy_hash(),
        path_templates,
    );
    super::native::deadline_check(control)?;
    Ok(super::native::SccpNativeDataV1 {
        data,
        _charge: charge,
    })
}

pub(super) fn active_profiles(
    view: &(impl StateReadOnly + ?Sized),
    control: SccpNativeReadControl<'_>,
) -> Result<iroha_sccp::light_client::profile::SccpLcActiveProfilesV1> {
    use iroha_sccp::light_client::profile::{
        SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1, SccpLcProfileRefV1,
    };
    let height = u64::try_from(view.height())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let catalog = SccpLcProfileCatalogV1::compiled();
    let mut active = catalog.genesis();
    for network in SCCP_LC_PROFILE_NETWORKS_V1 {
        for ((_, version), activation) in
            store::light_client_profiles::range(view.world(), (network, 0)..=(network, u32::MAX))
                .rev()
        {
            super::native::deadline_check(control)?;
            if activation.activation_height <= height {
                active = active.with(
                    network,
                    SccpLcProfileRefV1 {
                        version: *version,
                        profile_hash: activation.profile_hash,
                    },
                );
                break;
            }
        }
    }
    Ok(active)
}

fn copy_text(source: &str) -> Result<String> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| SccpNativeReadError::PhysicalAllocation)?;
    value.push_str(source);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smartcontracts::isi::sccp::{
            generation_record::RetainedSccpGeneration,
            test_support::{authority, blank_state, header, sample_generation},
        },
        state::StateTransaction,
    };
    use iroha_allocation::AllocationBudget;
    use iroha_crypto::{Algorithm, Hash, PublicKey};
    use iroha_data_model::{
        nexus::{PublicLaneStakeShare, PublicLaneUnbonding, PublicLaneValidatorStatus},
        sccp::generation::SccpGenerationMemberV1,
    };
    use iroha_model_base::peer::PeerId;
    use std::{
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };

    fn control(stop: &AtomicBool) -> SccpNativeReadControl<'_> {
        SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(10),
            stop,
        }
    }
    fn seed(stx: &mut StateTransaction<'_, '_>, amounts: [&str; 4], bps: u16) {
        let mut generation = sample_generation(2);
        generation.members.clear();
        for (index, amount) in amounts.iter().enumerate() {
            let validator = authority(u8::try_from(index + 50).unwrap());
            generation.members.push(Some(SccpGenerationMemberV1 {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                activation_height: 1,
            }));
            let amount: Quantity = amount.parse().unwrap();
            stx.world.public_lane_validators.insert(
                (LaneId::SINGLE, validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    peer_id: PeerId::new(
                        PublicKey::from_bytes(Algorithm::BlsNormal, &generation.keys[index])
                            .unwrap(),
                    ),
                    stake_account: validator.clone(),
                    total_stake: amount.clone(),
                    self_stake: amount.clone(),
                    metadata: iroha_model_base::metadata::Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
            stx.world.public_lane_stake_shares.insert(
                (LaneId::SINGLE, validator.clone(), validator.clone()),
                PublicLaneStakeShare {
                    lane_id: LaneId::SINGLE,
                    validator: validator.clone(),
                    staker: validator,
                    bonded: amount,
                    pending_unbonds: std::collections::BTreeMap::default(),
                    metadata: iroha_model_base::metadata::Metadata::default(),
                },
            );
        }
        let retained = RetainedSccpGeneration::admit(
            &generation,
            stx.world.sccp_committee_generations.allocation_budget(),
        )
        .unwrap();
        store::committee_generations::insert(stx, 2, retained).unwrap();
        store::committee_current::set(stx, 2);
        stx.nexus.staking.max_slash_bps = bps;
    }
    fn value(stx: &StateTransaction<'_, '_>) -> Quantity {
        floor(stx, control(&AtomicBool::new(false)))
            .unwrap()
            .unwrap()
            .try_into_quantity()
            .unwrap()
    }
    #[test]
    fn per_member_rounding_precedes_coalition_selection_and_sum() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        seed(&mut stx, ["1", "1", "10", "10"], 5_000);
        assert_eq!(
            value(&stx),
            Quantity::zero(),
            "two 1-unit penalties round to zero individually"
        );
        seed(&mut stx, ["9", "8.9", "8.8", "100"], 5_000);
        assert_eq!(
            value(&stx),
            "8.4".parse().unwrap(),
            "sort actual rounded penalties, not raw exposure"
        );
        seed(&mut stx, ["0", "3.2", "40", "100"], 10_000);
        assert_eq!(
            value(&stx),
            "3.2".parse().unwrap(),
            "known zero remains a real zero"
        );
    }
    #[test]
    fn delegated_and_pending_custody_use_the_original_generation_height() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        seed(&mut stx, ["10", "100", "100", "100"], 10_000);
        let validator = authority(50);
        let key = (LaneId::SINGLE, validator.clone());
        stx.world
            .public_lane_validators
            .get_mut(&key)
            .unwrap()
            .total_stake = Quantity::from(30_u32);
        let staker = authority(90);
        let mut share = PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: staker.clone(),
            bonded: Quantity::from(20_u32),
            pending_unbonds: std::collections::BTreeMap::default(),
            metadata: iroha_model_base::metadata::Metadata::default(),
        };
        for (id, through, amount) in [(1_u8, 1_u64, 80_u32), (2, 2, 7), (3, 3, 8)] {
            let request_id = Hash::new([id]);
            share.pending_unbonds.insert(
                request_id,
                PublicLaneUnbonding {
                    request_id,
                    amount: Quantity::from(amount),
                    release_at_ms: 0,
                    slashable_through_height: through,
                    liability_release_height: 100,
                },
            );
        }
        stx.world
            .public_lane_stake_shares
            .insert((LaneId::SINGLE, validator, staker), share);
        assert_eq!(value(&stx), Quantity::from(145_u32));
    }
    #[test]
    fn malformed_original_registration_or_custody_is_unavailable() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let stop = AtomicBool::new(false);
        for mutation in 0..5 {
            seed(&mut stx, ["10", "20", "30", "40"], 10_000);
            let validator = authority(50);
            let key = (LaneId::SINGLE, validator.clone());
            match mutation {
                0 => {
                    stx.world.public_lane_validators.remove(key);
                }
                1 => {
                    stx.world
                        .public_lane_validators
                        .get_mut(&key)
                        .unwrap()
                        .activation_height = 2
                }
                2 => {
                    stx.world
                        .public_lane_validators
                        .get_mut(&key)
                        .unwrap()
                        .deactivation_height = Some(2)
                }
                3 => {
                    stx.world
                        .public_lane_validators
                        .get_mut(&key)
                        .unwrap()
                        .total_stake = Quantity::from(11_u32)
                }
                4 => {
                    let other = stx
                        .world
                        .public_lane_validators
                        .get(&(LaneId::SINGLE, authority(51)))
                        .unwrap()
                        .peer_id
                        .clone();
                    stx.world
                        .public_lane_validators
                        .get_mut(&key)
                        .unwrap()
                        .peer_id = other;
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    floor(&stx, control(&stop)),
                    Err(SccpNativeReadError::Unavailable(_))
                ),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn missing_captured_member_never_becomes_zero_collateral() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        seed(&mut stx, ["10", "20", "30", "40"], 10_000);
        let mut generation =
            crate::smartcontracts::isi::sccp::test_support::generation_fixture_data(
                store::committee_generations::get(&*stx.world, &2).unwrap(),
            );
        generation.members[3] = None;
        let retained = RetainedSccpGeneration::admit(
            &generation,
            stx.world.sccp_committee_generations.allocation_budget(),
        )
        .unwrap();
        store::committee_generations::insert(&mut stx, 2, retained).unwrap();
        assert!(matches!(
            floor(&stx, control(&AtomicBool::new(false))),
            Err(SccpNativeReadError::Unavailable(_))
        ));
    }

    #[test]
    fn recorded_offence_consumes_the_once_only_penalty_before_and_after_application() {
        use crate::state::sccp_forgery_custody::OffenceKey;
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        seed(&mut stx, ["10", "20", "30", "40"], 5_000);
        let validator = authority(50);
        let offence = OffenceKey::try_copy(
            2,
            LaneId::SINGLE,
            &validator,
            stx.world.sccp_forgery_offences.allocation_budget(),
        )
        .unwrap();
        store::forgery_offences::insert_new(&mut stx, offence, [8; 32]).unwrap();
        assert_eq!(
            value(&stx),
            Quantity::from(10_u32),
            "recorded but not yet applied is already consumed"
        );
        let key = (LaneId::SINGLE, validator.clone());
        let record = stx.world.public_lane_validators.get_mut(&key).unwrap();
        record.total_stake = Quantity::from(5_u32);
        record.self_stake = Quantity::from(5_u32);
        record.status = PublicLaneValidatorStatus::Slashed(Hash::new([8]));
        stx.world
            .public_lane_stake_shares
            .get_mut(&(LaneId::SINGLE, validator.clone(), validator))
            .unwrap()
            .bonded = Quantity::from(5_u32);
        assert_eq!(
            value(&stx),
            Quantity::from(10_u32),
            "residual custody cannot be seized twice for this generation"
        );
        stx.world
            .public_lane_validators
            .get_mut(&key)
            .unwrap()
            .activation_height = 2;
        assert!(
            matches!(
                floor(&stx, control(&AtomicBool::new(false))),
                Err(SccpNativeReadError::Unavailable(_))
            ),
            "consumed offence never skips original provenance validation"
        );
    }
    #[test]
    fn capabilities_retain_one_original_pool_charge_and_refuse_local_limits() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        seed(&mut stx, ["10", "20", "30", "40"], 10_000);
        let budget = AllocationBudget::new(32_768);
        let stop = AtomicBool::new(false);
        let response = capabilities(
            &stx,
            &budget,
            control(&stop),
            ["/v1/sccp/capabilities"].into_iter(),
        )
        .unwrap();
        assert_eq!(
            response.data().coalition_slashable_floor,
            Some(Quantity::from(30_u32))
        );
        assert!(budget.reserved_bytes() > 0);
        let json = norito::json::to_value(response.data()).unwrap();
        assert_eq!(
            norito::json::from_value::<super::super::api::SccpCapabilitiesV1>(json.clone())
                .unwrap(),
            *response.data()
        );
        let wire = norito::to_bytes(response.data()).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<super::super::api::SccpCapabilitiesV1>(&wire).unwrap(),
            *response.data()
        );
        let mut missing = json;
        missing
            .as_object_mut()
            .unwrap()
            .remove("coalition_slashable_floor");
        assert!(
            norito::json::from_value::<super::super::api::SccpCapabilitiesV1>(missing).is_err()
        );
        drop(response);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(matches!(
            capabilities(
                &stx,
                &AllocationBudget::new(0),
                control(&stop),
                std::iter::empty()
            ),
            Err(SccpNativeReadError::Allocation(_))
        ));
        let stopped = AtomicBool::new(true);
        assert!(matches!(
            capabilities(&stx, &budget, control(&stopped), std::iter::empty()),
            Err(SccpNativeReadError::Cancelled)
        ));
        let expired = SccpNativeReadControl {
            deadline: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            stop: &stop,
        };
        assert!(matches!(
            capabilities(&stx, &budget, expired, std::iter::empty()),
            Err(SccpNativeReadError::Deadline)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
