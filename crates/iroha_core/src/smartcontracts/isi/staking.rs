//! Public lane staking instruction handlers (NX-9).
use super::prelude::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::{
    smartcontracts::isi::asset::isi::assert_numeric_spec_with,
    state::{
        ConsensusKeyGate, EvidencePreparationError, WorldReadOnly, consensus_key_role_for_lane,
        peer_consensus_key_gate_for_lane, public_lane_stake_share_matches_key,
        public_lane_validator_record_matches_key,
    },
    status,
    telemetry::StateTelemetry,
};
use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    isi::{
        error::{InstructionExecutionError as Error, InvalidParameterError, MathError},
        staking::{
            BondPublicLaneStake, ClaimPublicLaneRewards, FinalizePublicLaneUnbond,
            PublicLaneCandidateAuthorization, PublicLanePeerBindingAuthorization,
            RebindPublicLaneValidatorPeer, RegisterPublicLaneCandidate,
            RegisterPublicLaneValidator, SchedulePublicLaneUnbond, SlashPublicLaneValidator,
        },
    },
    nexus::{
        PublicLaneMonetaryBondV1, PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
        PublicLaneMonetaryRegistrationV1, PublicLaneMonetarySlashV1, PublicLaneMonetaryUnbondV1,
        PublicLaneStakeShare, PublicLaneUnbonding, PublicLaneValidatorRecord,
        PublicLaneValidatorStatus, public_lane_unbonding_commitment,
    },
    prelude::AccountId,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::QuantityAccumulator;
use iroha_primitives::numeric::{Numeric, Quantity, RoundingMode};
use std::{alloc::Layout, collections::BTreeMap, ops::Range, time::Duration};
#[path = "staking_effects.rs"]
mod effects;
#[path = "staking_preparation.rs"]
pub mod preparation;
#[path = "staking_rewards.rs"]
mod rewards;
pub(crate) use rewards::ensure_public_lane_reserves_after_debit;
#[path = "staking_custody.rs"]
mod custody;
pub(crate) use custody::{
    prepare_stake_custody_credit, prepare_stake_custody_debit, retained_stake_custody_asset,
};
/// Canonical storage key for one public-lane stake share.
pub(crate) type PublicLaneStakeShareKey = (LaneId, AccountId, AccountId);

/// Borrowed, allocation-free preflight for the stake-index retained backings.
///
/// Canonical sums use bounded stack limbs. These counts admit every nested
/// account copy and all four final aggregate magnitudes before the index
/// starts allocating from the same original World and pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicLaneStakeIndexDemand {
    share_rows: usize,
    validator_groups: usize,
    account_clone_bytes: usize,
    account_clone_charges: usize,
    quantity_bytes: usize,
    quantity_charges: usize,
}

impl PublicLaneStakeIndexDemand {
    #[cfg(test)]
    fn from_rows<'a>(
        rows: impl Iterator<Item = (&'a PublicLaneStakeShareKey, &'a PublicLaneStakeShare)>,
        max_shares: usize,
        max_pending: usize,
    ) -> Result<Self, Error> {
        Self::from_rows_with_group_validator(rows, max_shares, max_pending, |_| Ok(()))
    }

    fn from_rows_with_group_validator<'a>(
        rows: impl Iterator<Item = (&'a PublicLaneStakeShareKey, &'a PublicLaneStakeShare)>,
        max_shares: usize,
        max_pending: usize,
        mut validate_group: impl FnMut(&PublicLaneStakeShareKey) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let mut demand = Self {
            share_rows: 0,
            validator_groups: 0,
            account_clone_bytes: 0,
            account_clone_charges: 0,
            quantity_bytes: 0,
            quantity_charges: 0,
        };
        let mut aggregates = [QuantityAccumulator::zero(); 3];
        let mut previous_key: Option<&PublicLaneStakeShareKey> = None;
        let mut shares_in_group = 0_usize;
        for (key, share) in rows {
            if !public_lane_stake_share_matches_key(key, share) {
                return Err(Error::InvariantViolation(
                    "public-lane stake share does not match its storage key".into(),
                ));
            }
            if share.pending_unbonds.len() > max_pending {
                return Err(Error::InvariantViolation(
                    "public-lane stake share exceeds pending-unbond capacity".into(),
                ));
            }
            if let Some(previous) = previous_key {
                if previous >= key {
                    return Err(Error::InvariantViolation(
                        "public-lane stake shares are not in canonical key order".into(),
                    ));
                }
            }
            if previous_key.is_none_or(|previous| previous.0 != key.0 || previous.1 != key.1) {
                if previous_key.is_some() {
                    demand.add_quantity_group(&aggregates)?;
                    aggregates = [QuantityAccumulator::zero(); 3];
                }
                validate_group(key)?;
                demand.validator_groups =
                    demand.validator_groups.checked_add(1).ok_or_else(|| {
                        Error::InvariantViolation(
                            "public-lane stake-index group count overflows".into(),
                        )
                    })?;
                shares_in_group = 0;
                demand.add_account_clone(&key.1)?;
            }
            shares_in_group = shares_in_group.checked_add(1).ok_or_else(|| {
                Error::InvariantViolation("public-lane stake-index group size overflows".into())
            })?;
            if shares_in_group > max_shares {
                return Err(Error::InvariantViolation(
                    "public-lane validator exceeds stake-share capacity".into(),
                ));
            }
            demand.share_rows = demand.share_rows.checked_add(1).ok_or_else(|| {
                Error::InvariantViolation("public-lane stake-index row count overflows".into())
            })?;
            demand.add_account_clone(&key.1)?;
            demand.add_account_clone(&key.2)?;
            aggregate_index_share(&mut aggregates, key, share)?;
            previous_key = Some(key);
        }
        if previous_key.is_some() {
            demand.add_quantity_group(&aggregates)?;
        }
        Ok(demand)
    }

    fn add_quantity_group(&mut self, aggregates: &[QuantityAccumulator; 3]) -> Result<(), Error> {
        // Overflow is preserved for the exposure read. It must not reject an
        // unrelated group's otherwise canonical bonded/pending index.
        let exposure = aggregate_index_exposure(aggregates).unwrap_or_default();
        for aggregate in [aggregates[0], aggregates[1], aggregates[2], exposure] {
            let layout = aggregate.admission_layout().map_err(|_| {
                Error::InvariantViolation(
                    "public-lane stake-index quantity layout overflows".into(),
                )
            })?;
            self.quantity_bytes =
                self.quantity_bytes
                    .checked_add(layout.size())
                    .ok_or_else(|| {
                        Error::InvariantViolation(
                            "public-lane stake-index quantity demand overflows".into(),
                        )
                    })?;
            self.quantity_charges = self.quantity_charges.checked_add(1).ok_or_else(|| {
                Error::InvariantViolation(
                    "public-lane stake-index quantity charge count overflows".into(),
                )
            })?;
        }
        Ok(())
    }

    fn add_account_clone(&mut self, account: &AccountId) -> Result<(), Error> {
        let mut overflow = false;
        account
            .for_each_admission_clone_layout(|layout| {
                if let (Some(bytes), Some(charges)) = (
                    self.account_clone_bytes.checked_add(layout.size()),
                    self.account_clone_charges.checked_add(1),
                ) {
                    self.account_clone_bytes = bytes;
                    self.account_clone_charges = charges;
                } else {
                    overflow = true;
                }
            })
            .map_err(|_| {
                Error::InvariantViolation("public-lane stake-index account key is malformed".into())
            })?;
        if overflow {
            return Err(Error::InvariantViolation(
                "public-lane stake-index account clone demand overflows".into(),
            ));
        }
        Ok(())
    }

    fn checked_fixed_layouts(self) -> Result<(Layout, Layout), Error> {
        let shares = Layout::array::<PublicLaneStakeShareKey>(self.share_rows).map_err(|_| {
            Error::InvariantViolation("public-lane stake-index share backing overflows".into())
        })?;
        let groups =
            Layout::array::<IndexedValidatorStake>(self.validator_groups).map_err(|_| {
                Error::InvariantViolation("public-lane stake-index group backing overflows".into())
            })?;
        Ok((shares, groups))
    }

    fn checked_retained_layouts(self) -> Result<(Layout, Layout, Layout, usize), Error> {
        let (shares, groups) = self.checked_fixed_layouts()?;
        let charge_count = self
            .account_clone_charges
            .checked_add(self.quantity_charges)
            .ok_or_else(|| {
                Error::InvariantViolation("public-lane stake-index charge count overflows".into())
            })?;
        let charges = Layout::array::<AllocationCharge>(charge_count).map_err(|_| {
            Error::InvariantViolation("public-lane stake-index charge backing overflows".into())
        })?;
        let bytes = shares
            .size()
            .checked_add(groups.size())
            .and_then(|sum| sum.checked_add(charges.size()))
            .and_then(|sum| sum.checked_add(self.account_clone_bytes))
            .and_then(|sum| sum.checked_add(self.quantity_bytes))
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "public-lane stake-index retained demand overflows".into(),
                )
            })?;
        Ok((shares, groups, charges, bytes))
    }

    fn validate_materialized(
        self,
        groups: &[IndexedValidatorStake],
        flat_keys: &[PublicLaneStakeShareKey],
    ) -> Result<(), Error> {
        if groups.len() != self.validator_groups {
            return Err(Error::InvariantViolation(
                "public-lane stake-index group count changed during construction".into(),
            ));
        }
        if flat_keys.len() != self.share_rows {
            return Err(Error::InvariantViolation(
                "public-lane stake-index row count changed during construction".into(),
            ));
        }
        if !groups.windows(2).all(|pair| pair[0].key() < pair[1].key()) {
            return Err(Error::InvariantViolation(
                "public-lane stake-index groups are not in canonical order".into(),
            ));
        }
        let mut next = 0_usize;
        for group in groups {
            let range = group.share_range();
            if range.start != next || range.start >= range.end || range.end > flat_keys.len() {
                return Err(Error::InvariantViolation(
                    "public-lane stake-index ranges do not partition the flat backing".into(),
                ));
            }
            let first = &flat_keys[range.start];
            let last = &flat_keys[range.end - 1];
            if first.0 != group.lane_id()
                || &first.1 != group.validator()
                || last.0 != group.lane_id()
                || &last.1 != group.validator()
            {
                return Err(Error::InvariantViolation(
                    "public-lane stake-index range differs from its validator group".into(),
                ));
            }
            next = range.end;
        }
        if next != flat_keys.len() {
            return Err(Error::InvariantViolation(
                "public-lane stake-index ranges do not cover the flat backing".into(),
            ));
        }
        Ok(())
    }
}

// The transparent tuple makes the exact group allocation layout available to
// iroha_config without making that lower layer depend on this Core module.
// The four Quantity magnitudes are admitted separately from the fixed tuple.
#[repr(transparent)]
struct IndexedValidatorStake(
    (
        LaneId,
        AccountId,
        Range<usize>,
        Quantity,
        Quantity,
        Quantity,
        Option<Quantity>,
    ),
);

impl IndexedValidatorStake {
    fn new(lane_id: LaneId, validator: AccountId, start: usize) -> Self {
        Self((
            lane_id,
            validator,
            start..start,
            Quantity::zero(),
            Quantity::zero(),
            Quantity::zero(),
            None,
        ))
    }

    fn lane_id(&self) -> LaneId {
        self.0.0
    }

    fn validator(&self) -> &AccountId {
        &self.0.1
    }

    fn key(&self) -> (LaneId, &AccountId) {
        (self.lane_id(), self.validator())
    }

    fn share_range(&self) -> &Range<usize> {
        &self.0.2
    }
}

/// Two-pass, bounded-work index over the complete public-lane stake-share table.
///
/// The borrowed demand pass checks the source geometry before allocation; the
/// second pass materializes and validates the current index. Consensus uses the
/// resulting key slices for point reads instead of rescanning the global share
/// table once per penalty.
pub(crate) struct PublicLaneStakeIndex {
    /// Original charged backing, including nested account clones below.
    share_keys: ChargedBuffer<PublicLaneStakeShareKey>,
    /// Original charged group backing, including exactly admitted Quantity owners.
    groups: ChargedBuffer<IndexedValidatorStake>,
    /// Every nested key and magnitude drops before its original charge.
    _nested_account_charges: ChargedBuffer<AllocationCharge>,
    /// Canonical zero for absent groups has no heap backing.
    zero: Quantity,
    #[cfg(test)]
    row_visits: usize,
}

impl PublicLaneStakeIndex {
    /// Build and validate an index from one exact world overlay.
    pub(crate) fn from_world(
        world: &impl WorldReadOnly,
        max_stake_shares_per_validator: u32,
        max_pending_unbonds_per_share: u32,
        budget: &AllocationBudget,
    ) -> eyre::Result<Self> {
        let max_shares = usize::try_from(max_stake_shares_per_validator)
            .expect("u32 stake-share cap fits usize on supported targets");
        let max_pending = usize::try_from(max_pending_unbonds_per_share)
            .expect("u32 pending-unbond cap fits usize on supported targets");
        // The validator cursor advances in the same borrowed demand pass. An
        // orphan or malformed group is refused before a pool charge or clone.
        let mut validators = world.public_lane_validators().iter();
        let mut current_validator = validators.next();
        let demand = PublicLaneStakeIndexDemand::from_rows_with_group_validator(
            world.public_lane_stake_shares().iter(),
            max_shares,
            max_pending,
            |share_key| {
                let group = (share_key.0, &share_key.1);
                while current_validator
                    .as_ref()
                    .is_some_and(|(validator_key, _)| (validator_key.0, &validator_key.1) < group)
                {
                    current_validator = validators.next();
                }
                let Some((validator_key, record)) = current_validator else {
                    return Err(Error::InvariantViolation(
                        "public-lane stake-share aggregate has no validator record".into(),
                    ));
                };
                if (validator_key.0, &validator_key.1) != group {
                    return Err(Error::InvariantViolation(
                        "public-lane stake-share aggregate has no validator record".into(),
                    ));
                }
                ensure_public_lane_validator_record_matches_key(validator_key, record)?;
                current_validator = validators.next();
                Ok(())
            },
        )?;
        // Reserve complete fixed, account and aggregate layouts atomically
        // before any retained key or magnitude allocation. The charge buffer is declared
        // before keys/groups so local error paths drop physical keys first.
        let (share_layout, group_layout, charges_layout, retained_bytes) =
            demand.checked_retained_layouts()?;
        let mut reservation = budget
            .try_reserve_bytes(retained_bytes)
            .map_err(EvidencePreparationError::Admission)?;
        let charges_charge = reservation
            .try_split(charges_layout)
            .expect("complete nested charge backing was reserved");
        let mut nested_account_charges: ChargedBuffer<AllocationCharge> =
            ChargedBuffer::try_from_charge(
                demand.account_clone_charges + demand.quantity_charges,
                charges_charge,
            )
            .map_err(|(_, error)| match error {
                iroha_allocation::ChargedBufferFromChargeError::Allocator { layout } => {
                    EvidencePreparationError::Allocator {
                        requested_bytes: layout.size(),
                    }
                }
                _ => EvidencePreparationError::Invariant,
            })?;
        let share_charge = reservation
            .try_split(share_layout)
            .expect("complete fixed stake-index demand was reserved");
        let group_charge = reservation
            .try_split(group_layout)
            .expect("complete fixed stake-index demand was reserved");
        let mut share_keys = ChargedBuffer::try_from_charge(demand.share_rows, share_charge)
            .map_err(|(_, error)| match error {
                iroha_allocation::ChargedBufferFromChargeError::Allocator { layout } => {
                    EvidencePreparationError::Allocator {
                        requested_bytes: layout.size(),
                    }
                }
                _ => EvidencePreparationError::Invariant,
            })?;
        let mut groups: ChargedBuffer<IndexedValidatorStake> =
            ChargedBuffer::try_from_charge(demand.validator_groups, group_charge).map_err(
                |(_, error)| match error {
                    iroha_allocation::ChargedBufferFromChargeError::Allocator { layout } => {
                        EvidencePreparationError::Allocator {
                            requested_bytes: layout.size(),
                        }
                    }
                    _ => EvidencePreparationError::Invariant,
                },
            )?;
        // Source rows and lookup results remain borrowed from the exact World.
        // All arithmetic scratch is bounded stack storage; only final canonical
        // magnitudes allocate, after splitting their original prepaid charges.
        let mut aggregates = [QuantityAccumulator::zero(); 3];
        #[cfg(test)]
        let mut row_visits = demand.share_rows;

        for (key, share) in world.public_lane_stake_shares().iter() {
            #[cfg(test)]
            {
                row_visits = row_visits
                    .checked_add(1)
                    .expect("checked stake-index backing bounds two source passes");
            }
            if !public_lane_stake_share_matches_key(key, share) {
                return Err(Error::InvariantViolation(
                    "public-lane stake share does not match its storage key".into(),
                )
                .into());
            }
            if share.pending_unbonds.len() > max_pending {
                return Err(Error::InvariantViolation(
                    "public-lane stake share exceeds pending-unbond capacity".into(),
                )
                .into());
            }
            let next = share_keys.as_slice().len();
            if groups
                .as_slice()
                .last()
                .is_none_or(|group| group.lane_id() != key.0 || group.validator() != &key.1)
            {
                if let Some(previous) = groups.as_mut_slice().last_mut() {
                    finish_index_group(
                        previous,
                        &aggregates,
                        &mut reservation,
                        &mut nested_account_charges,
                    )?;
                    aggregates = [QuantityAccumulator::zero(); 3];
                }
                let validator_key = (
                    key.0,
                    clone_index_account(&key.1, &mut reservation, &mut nested_account_charges)?,
                );
                let record = world
                    .public_lane_validators()
                    .get(&validator_key)
                    .ok_or_else(|| {
                        Error::InvariantViolation(
                            "public-lane stake-share aggregate has no validator record".into(),
                        )
                    })?;
                ensure_public_lane_validator_record_matches_key(&validator_key, record)?;
                if record.stake_account != record.validator {
                    return Err(Error::InvariantViolation(
                        "public-lane validator stake account must match the validator account"
                            .into(),
                    )
                    .into());
                }
                groups
                    .try_push(IndexedValidatorStake::new(key.0, validator_key.1, next))
                    .map_err(|_| EvidencePreparationError::Invariant)?;
            }
            let indexed = groups
                .as_mut_slice()
                .last_mut()
                .expect("each source share has a materialized group");
            if indexed.0.2.end != next {
                return Err(Error::InvariantViolation(
                    "public-lane stake-index group is not contiguous".into(),
                )
                .into());
            }
            if indexed.0.2.len() >= max_shares {
                return Err(Error::InvariantViolation(
                    "public-lane validator exceeds stake-share capacity".into(),
                )
                .into());
            }
            let copied_key = (
                key.0,
                clone_index_account(&key.1, &mut reservation, &mut nested_account_charges)?,
                clone_index_account(&key.2, &mut reservation, &mut nested_account_charges)?,
            );
            share_keys
                .try_push(copied_key)
                .map_err(|_| EvidencePreparationError::Invariant)?;
            indexed.0.2.end = share_keys.as_slice().len();
            aggregate_index_share(&mut aggregates, key, share)?;
        }
        if let Some(last) = groups.as_mut_slice().last_mut() {
            finish_index_group(
                last,
                &aggregates,
                &mut reservation,
                &mut nested_account_charges,
            )?;
        }

        for (key, record) in world.public_lane_validators().iter() {
            ensure_public_lane_validator_record_matches_key(key, record)?;
            if record.stake_account != record.validator {
                return Err(Error::InvariantViolation(
                    "public-lane validator stake account must match the validator account".into(),
                )
                .into());
            }
            let indexed = Self::find_group(groups.as_slice(), key.0, &key.1);
            if !indexed_validator_totals_match(indexed, &record.total_stake, &record.self_stake) {
                return Err(Error::InvariantViolation(
                    "public-lane validator totals do not match canonical stake shares".into(),
                )
                .into());
            }
        }

        demand.validate_materialized(groups.as_slice(), share_keys.as_slice())?;
        if nested_account_charges.as_slice().len()
            != demand.account_clone_charges + demand.quantity_charges
            || reservation.remaining_bytes() != 0
        {
            return Err(EvidencePreparationError::Invariant.into());
        }

        Ok(Self {
            share_keys,
            groups,
            _nested_account_charges: nested_account_charges,
            zero: Quantity::zero(),
            #[cfg(test)]
            row_visits,
        })
    }

    /// Return the complete canonical share-key slice for one validator.
    pub(crate) fn share_keys(
        &self,
        lane_id: LaneId,
        validator: &AccountId,
    ) -> &[PublicLaneStakeShareKey] {
        Self::find_group(self.groups.as_slice(), lane_id, validator).map_or(&[], |entry| {
            &self.share_keys.as_slice()[entry.share_range().clone()]
        })
    }

    /// Borrow the already funded total bonded and pending-unbond custody.
    /// Repeated penalty reads cannot create replacement magnitude allocations.
    pub(crate) fn total_exposure(
        &self,
        lane_id: LaneId,
        validator: &AccountId,
    ) -> Result<&Quantity, Error> {
        match Self::find_group(self.groups.as_slice(), lane_id, validator) {
            Some(indexed) => indexed.0.6.as_ref().ok_or(Error::Math(MathError::Overflow)),
            None => Ok(&self.zero),
        }
    }

    fn find_group<'a>(
        groups: &'a [IndexedValidatorStake],
        lane_id: LaneId,
        validator: &AccountId,
    ) -> Option<&'a IndexedValidatorStake> {
        groups
            .binary_search_by(|group| {
                group
                    .lane_id()
                    .cmp(&lane_id)
                    .then_with(|| group.validator().cmp(validator))
            })
            .ok()
            .map(|index| &groups[index])
    }

    #[cfg(test)]
    pub(crate) fn row_visits(&self) -> usize {
        self.row_visits
    }
}

/// Compare aggregate custody without cloning its originally funded Quantity limbs.
fn indexed_validator_totals_match(
    indexed: Option<&IndexedValidatorStake>,
    total_stake: &Quantity,
    self_stake: &Quantity,
) -> bool {
    match indexed {
        Some(entry) => &entry.0.3 == total_stake && &entry.0.4 == self_stake,
        None => {
            let zero = Quantity::zero();
            total_stake == &zero && self_stake == &zero
        }
    }
}

/// Accumulate one exact borrowed row while retaining all arithmetic scratch inline.
fn aggregate_index_share(
    aggregates: &mut [QuantityAccumulator; 3],
    key: &PublicLaneStakeShareKey,
    share: &PublicLaneStakeShare,
) -> Result<(), Error> {
    let add = |sum: &mut QuantityAccumulator, amount: &Quantity| {
        sum.try_add(amount)
            .map_err(|_| Error::Math(MathError::Overflow))
    };
    add(&mut aggregates[0], &share.bonded)?;
    if key.1 == key.2 {
        add(&mut aggregates[1], &share.bonded)?;
    }
    for (request_id, pending) in &share.pending_unbonds {
        ensure_canonical_pending_unbond(request_id, pending)?;
        add(&mut aggregates[2], &pending.amount)?;
    }
    Ok(())
}

/// Preserve the original bonded-plus-complete-pending grouping at the domain boundary.
fn aggregate_index_exposure(
    aggregates: &[QuantityAccumulator; 3],
) -> Result<QuantityAccumulator, Error> {
    let mut exposure = aggregates[0];
    exposure
        .try_add_accumulator(&aggregates[2])
        .map_err(|_| Error::Math(MathError::Overflow))?;
    Ok(exposure)
}

/// Materialize each final magnitude once under its exact original-pool charge.
fn finish_index_group(
    group: &mut IndexedValidatorStake,
    aggregates: &[QuantityAccumulator; 3],
    reservation: &mut AllocationReservation,
    charges: &mut ChargedBuffer<AllocationCharge>,
) -> Result<(), EvidencePreparationError> {
    let exposure = aggregate_index_exposure(aggregates).ok();
    group.0.3 = materialize_index_quantity(aggregates[0], reservation, charges)?;
    group.0.4 = materialize_index_quantity(aggregates[1], reservation, charges)?;
    group.0.5 = materialize_index_quantity(aggregates[2], reservation, charges)?;
    group.0.6 = match exposure {
        Some(exposure) => Some(materialize_index_quantity(exposure, reservation, charges)?),
        None => {
            // Preserve the same exact descriptor count without allocating a
            // replacement magnitude for an unrepresentable exposure.
            materialize_index_quantity(QuantityAccumulator::zero(), reservation, charges)?;
            None
        }
    };
    Ok(())
}

/// Preserve the charge until every physical aggregate owned by the index drops.
fn materialize_index_quantity(
    aggregate: QuantityAccumulator,
    reservation: &mut AllocationReservation,
    charges: &mut ChargedBuffer<AllocationCharge>,
) -> Result<Quantity, EvidencePreparationError> {
    let layout = aggregate
        .admission_layout()
        .map_err(|_| EvidencePreparationError::Invariant)?;
    let charge = reservation
        .try_split(layout)
        .map_err(|_| EvidencePreparationError::Invariant)?;
    #[cfg(all(test, feature = "mutation-testing", sumeragi_core_mutation = "HC87"))]
    let charge = {
        // Mutation: release the admitted original while the physical quantity lives.
        drop(charge);
        reservation
            .try_split(Layout::new::<()>())
            .expect("zero mutation charge")
    };
    charges
        .try_push(charge)
        .map_err(|_| EvidencePreparationError::Invariant)?;
    aggregate.try_into_quantity().map_err(|error| match error {
        iroha_primitives::bigint::BigIntAdmissionCloneError::Allocator { requested_bytes } => {
            EvidencePreparationError::Allocator { requested_bytes }
        }
        _ => EvidencePreparationError::Invariant,
    })
}

/// Copy one retained account only after every nested layout is split from the
/// original State reservation and retained beyond the physical key owner.
fn clone_index_account(
    source: &AccountId,
    reservation: &mut AllocationReservation,
    charges: &mut ChargedBuffer<AllocationCharge>,
) -> Result<AccountId, EvidencePreparationError> {
    let mut mismatch = false;
    source
        .for_each_admission_clone_layout(|layout| {
            if mismatch {
                return;
            }
            match reservation.try_split(layout) {
                Ok(charge) => {
                    if charges.try_push(charge).is_err() {
                        mismatch = true;
                    }
                }
                Err(_) => mismatch = true,
            }
        })
        .map_err(|_| EvidencePreparationError::Invariant)?;
    if mismatch {
        return Err(EvidencePreparationError::Invariant);
    }
    source
        .try_clone_for_admission()
        .map_err(|error| match error {
            norito::core::Error::AllocationFailed { bytes } => {
                EvidencePreparationError::Allocator {
                    requested_bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
                }
            }
            norito::core::Error::TotalAllocationExceeded { attempted, limit } => {
                EvidencePreparationError::DecodeScope {
                    attempted_bytes: attempted,
                    limit_bytes: limit,
                }
            }
            _ => EvidencePreparationError::Invariant,
        })
}

/// One-shot retained-state proof for an exact public-lane staking slash.
pub(in crate::smartcontracts::isi) struct VerifiedStakingSlashDebit {
    lane_id: LaneId,
    validator: AccountId,
    slash_id: Hash,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
    slashable_exposure: Quantity,
}
impl VerifiedStakingSlashDebit {
    fn new(
        lane_id: LaneId,
        validator: AccountId,
        slash_id: Hash,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
        slashable_exposure: Quantity,
    ) -> Self {
        Self {
            lane_id,
            validator,
            slash_id,
            source_id,
            destination_id,
            amount,
            slashable_exposure,
        }
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (
        LaneId,
        AccountId,
        Hash,
        AssetId,
        AssetId,
        Quantity,
        Quantity,
    ) {
        (
            self.lane_id,
            self.validator,
            self.slash_id,
            self.source_id,
            self.destination_id,
            self.amount,
            self.slashable_exposure,
        )
    }
}
fn current_epoch(block_height: u64, epoch_length_blocks: u64) -> Result<u64, Error> {
    if epoch_length_blocks == 0 {
        return Err(Error::InvariantViolation(
            "epoch_length_blocks must be greater than zero".into(),
        ));
    }
    Ok(block_height.saturating_sub(1) / epoch_length_blocks)
}

fn next_unfrozen_election_height(
    block_height: u64,
    epoch_length_blocks: u64,
) -> Result<u64, Error> {
    if epoch_length_blocks == 0 {
        return Err(Error::InvariantViolation(
            "epoch_length_blocks must be greater than zero".into(),
        ));
    }
    let epoch = block_height.saturating_sub(1) / epoch_length_blocks;
    let current_epoch_end = epoch
        .checked_add(1)
        .and_then(|value| value.checked_mul(epoch_length_blocks))
        .ok_or_else(|| Error::InvariantViolation("validator epoch boundary overflowed".into()))?;
    // A boundary at the end of E selects E+2. Its prestate is already frozen
    // when transactions in that boundary block execute.
    let next_epoch_start = current_epoch_end
        .checked_add(epoch_length_blocks)
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| Error::InvariantViolation("validator epoch boundary overflowed".into()))?;
    if block_height < current_epoch_end {
        return Ok(next_epoch_start);
    }
    next_epoch_start
        .checked_add(epoch_length_blocks)
        .ok_or_else(|| Error::InvariantViolation("validator epoch boundary overflowed".into()))
}

/// Select an unfrozen global tenure from authenticated interval boundaries.
/// Future lengths are projected only after the last immutable interval; they are
/// recomputed at execution and are never inferred from a genesis-height modulus.
fn global_eligibility_from_intervals(
    current_first: u64,
    current_last: u64,
    next_last: u64,
    future_last: u64,
    key_ready_height: u64,
    epoch_length: u64,
) -> Result<u64, Error> {
    let invalid =
        || Error::InvariantViolation("invalid authenticated validator epoch intervals".into());
    if current_first == 0
        || current_first > current_last
        || current_last >= next_last
        || next_last >= future_last
        || key_ready_height < current_first
        || epoch_length == 0
    {
        return Err(invalid());
    }
    if key_ready_height < current_last {
        return next_last.checked_add(1).ok_or_else(invalid);
    }
    let skipped = if key_ready_height < next_last {
        0
    } else if key_ready_height < future_last {
        1
    } else {
        key_ready_height
            .checked_sub(future_last)
            .and_then(|offset| (offset / epoch_length).checked_add(2))
            .ok_or_else(invalid)?
    };
    future_last
        .checked_add(1)
        .and_then(|height| {
            skipped
                .checked_mul(epoch_length)
                .and_then(|offset| height.checked_add(offset))
        })
        .ok_or_else(invalid)
}

fn read_staking_policy(
    state: &mut StateTransaction<'_, '_>,
) -> Result<Option<iroha_data_model::parameter::system::SumeragiNposParameters>, Error> {
    state.world.sumeragi_npos_parameters().map_err(|error| {
        retain_staking_attempt(
            state,
            error.map_rejection(|message| Error::InvariantViolation(message.into())),
        )
    })
}

fn retain_staking_attempt(state: &mut StateTransaction<'_, '_>, error: Attempt<Error>) -> Error {
    match error {
        Attempt::Rejected(error) => error,
        Attempt::Deferred(reason) => {
            if !cfg!(all(test, sumeragi_core_mutation = "HC48")) {
                let _ = state.defer_execution(reason);
            }
            Error::InvariantViolation("local validator scheduling did not complete".into())
        }
    }
}

fn validator_eligibility_height(
    state: &impl crate::state::StateReadOnly,
    lane_id: LaneId,
    execution_height: u64,
    key_ready_height: u64,
) -> Result<u64, Attempt<Error>> {
    let fail = |message: String| Error::InvariantViolation(message.into());
    let parameters = state
        .world()
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(fail))?
        .ok_or_else(|| fail("validator scheduling requires committed NPoS parameters".into()))?;
    parameters
        .validate()
        .map_err(|error| fail(error.to_string()))?;
    let length = parameters.epoch_length_blocks.get();
    if lane_id != LaneId::SINGLE {
        return next_unfrozen_election_height(key_ready_height, length).map_err(Attempt::Rejected);
    }
    let (generation, current) = crate::state::validator_committee::current_authority(state)
        .map_err(|error| error.map_rejection(fail))?;
    current
        .validate_against_generation(&generation)
        .map_err(|error| fail(error.to_string()))?;
    if execution_height < current.first_height
        || execution_height > current.last_height
        || key_ready_height < execution_height
    {
        return Err(fail(
            "validator scheduling height lies outside the authenticated current interval".into(),
        )
        .into());
    }
    let next_epoch = current
        .epoch
        .checked_add(1)
        .ok_or_else(|| fail("validator epoch overflow".into()))?;
    let future_epoch = next_epoch
        .checked_add(1)
        .ok_or_else(|| fail("validator epoch overflow".into()))?;
    let world = state.world();
    let next = world.validator_committee_transitions().get(&next_epoch);
    let future = world.validator_committee_transitions().get(&future_epoch);
    if let Some(next) = next {
        next.preparation
            .validate_against_preparing_authorization(&current)
            .map_err(fail)?;
    }
    if let Some(future) = future {
        future.preparation.validate().map_err(fail)?;
        if execution_height != current.last_height
            || future.preparation.network_id != current.network_id
            || future.preparation.selection_height != current.last_height
            || future.preparation.selection_epoch != current.epoch
            || future.preparation.target_epoch != future_epoch
        {
            return Err(fail(
                "future validator interval is not the current boundary's frozen preparation".into(),
            )
            .into());
        }
    }
    // At a boundary, the freshly staged preparation also fixes the complete
    // intervening epoch even when its roster had no previous selected attempt.
    let next_last = if let Some(next) = next {
        next.preparation.last_height
    } else if let Some(future) = future {
        future
            .preparation
            .first_height
            .checked_sub(1)
            .ok_or_else(|| fail("validator interval underflow".into()))?
    } else {
        current
            .last_height
            .checked_add(length)
            .ok_or_else(|| fail("validator interval overflow".into()))?
    };
    let future_last = if let Some(future) = future {
        if next_last.checked_add(1) != Some(future.preparation.first_height) {
            return Err(fail("frozen validator intervals are not contiguous".into()).into());
        }
        future.preparation.last_height
    } else {
        next_last
            .checked_add(length)
            .ok_or_else(|| fail("validator interval overflow".into()))?
    };
    Ok(global_eligibility_from_intervals(
        current.first_height,
        current.last_height,
        next_last,
        future_last,
        key_ready_height,
        length,
    )?)
}

fn scheduled_validator_eligibility_height(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
) -> Result<u64, Attempt<Error>> {
    let block_height = state_transaction.block_height();
    if state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty() {
        return Ok(block_height);
    }
    validator_eligibility_height(state_transaction, lane_id, block_height, block_height)
}

fn scheduled_validator_deactivation_height(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
) -> Result<u64, Attempt<Error>> {
    // Same-block genesis registration is an exception for admitting the
    // initial validator. It must not shorten an exit or pending unbond's
    // already-frozen voting and slashing obligation to the genesis height.
    let height = state_transaction.block_height();
    validator_eligibility_height(state_transaction, lane_id, height, height)
}

fn schedule_validator_deactivation(
    record: &mut PublicLaneValidatorRecord,
    boundary: u64,
    retained_committee_obligation: bool,
) -> Result<(), Error> {
    let activation = record.activation_height;
    record
        .election_exit_height
        .get_or_insert(boundary.max(activation));
    if retained_committee_obligation {
        // A request is not a certificate. Keep the tenure open until a boundary
        // actually releases both the current and already frozen target seat.
        return Ok(());
    }
    if let Some(existing) = record.deactivation_height {
        if existing < activation {
            return Err(Error::InvariantViolation(
                "validator deactivation boundary precedes activation".into(),
            ));
        }
        // The first terminal transition fixes the historical half-open tenure.
        // Later lifecycle labels must never rewrite that consensus fact.
        return Ok(());
    }
    let boundary = if matches!(
        record.status,
        PublicLaneValidatorStatus::PendingActivation(_)
    ) {
        // Cancelling a future activation creates an empty retained tenure;
        // its exclusive end cannot precede its scheduled inclusive start.
        boundary.max(activation)
    } else {
        boundary
    };
    if boundary < activation {
        return Err(Error::InvariantViolation(
            "validator deactivation boundary precedes activation".into(),
        ));
    }
    record.deactivation_height = Some(boundary);
    Ok(())
}

/// Check whether an offence height falls inside one exact retained tenure.
pub(crate) fn validator_tenure_contains_height(
    record: &PublicLaneValidatorRecord,
    height: u64,
) -> Result<bool, Error> {
    let activation = record.activation_height;
    if record
        .deactivation_height
        .is_some_and(|deactivation| deactivation < activation)
    {
        return Err(Error::InvariantViolation(
            "validator deactivation boundary precedes activation".into(),
        ));
    }
    if let PublicLaneValidatorStatus::PendingActivation(pending_height) = record.status
        && pending_height != activation
    {
        return Err(Error::InvariantViolation(
            "pending validator status disagrees with activation boundary".into(),
        ));
    }
    Ok(activation <= height
        && record
            .deactivation_height
            .is_none_or(|deactivation| height < deactivation))
}

/// Check whether a record may participate in an election for an exact height.
pub(crate) fn validator_election_eligible_at_height(
    record: &PublicLaneValidatorRecord,
    height: u64,
) -> bool {
    // This predicate selects new committees. Existing frozen contexts and
    // offence authentication use the actual retained tenure instead.
    validator_tenure_contains_height(record, height).unwrap_or(false)
        && record.election_exit_height.is_none_or(|end| height < end)
}

/// Preserve current and frozen peer bindings while allowing future candidate elections.
fn ensure_frozen_validator_binding_preserved(
    state_transaction: &StateTransaction<'_, '_>,
    replacement: &PublicLaneValidatorRecord,
    operation: &str,
) -> Result<(), Attempt<Error>> {
    let Some(existing) = state_transaction
        .world
        .public_lane_validators
        .get(&(replacement.lane_id, replacement.validator.clone()))
    else {
        return Ok(());
    };
    let immutable_binding_changed = replacement.peer_id != existing.peer_id
        || replacement.activation_height != existing.activation_height;
    if (has_global_committee_obligation(state_transaction, existing)
        && (immutable_binding_changed
            || replacement.deactivation_height != existing.deactivation_height))
        || (crate::sumeragi::lanes::custody::retains_registration(
            &state_transaction.world,
            existing,
            state_transaction.block_height(),
        )
        .map_err(|error| {
            error.map_rejection(|message| Error::InvariantViolation(message.into()))
        })? && immutable_binding_changed)
    {
        return Err((Error::InvariantViolation(
            format!("{operation} cannot revoke a current or frozen validator binding").into(),
        ))
        .into());
    }
    Ok(())
}

fn has_global_committee_obligation(
    state: &StateTransaction<'_, '_>,
    record: &PublicLaneValidatorRecord,
) -> bool {
    record.lane_id == LaneId::SINGLE
        && (state
            .native_epoch_boundary
            .is_some_and(|guard| guard.retains_peer(&record.peer_id))
            || crate::state::validator_committee::peer_has_committee_obligation(
                &state.world,
                state.commit_topology.iter(),
                &record.peer_id,
            ))
}

fn ensure_validator_deactivation_reached(
    record: &PublicLaneValidatorRecord,
    block_height: u64,
    operation: &str,
) -> Result<(), Error> {
    let deactivation = record.deactivation_height.ok_or_else(|| {
        Error::InvariantViolation(
            format!("{operation} requires a canonical validator deactivation height").into(),
        )
    })?;
    if deactivation < record.activation_height {
        return Err(Error::InvariantViolation(
            "validator deactivation boundary precedes activation".into(),
        ));
    }
    if block_height < deactivation {
        return Err(Error::InvariantViolation(
            format!(
                "{operation} cannot replace or prune a validator before deactivation height {deactivation}"
            )
            .into(),
        ));
    }
    Ok(())
}
fn ensure_lane_allows_staking(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
    context: &str,
) -> Result<(), Error> {
    if !state_transaction.is_lane_active_for_authority(lane_id) {
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_reject("lane_inactive");
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "{context} rejected: lane {lane_id} is not active at block height {}",
                state_transaction.block_height()
            )),
        ));
    }
    if !matches!(
        state_transaction.lane_validator_mode(lane_id),
        iroha_config::parameters::actual::LaneValidatorMode::StakeElected
    ) {
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_reject("lane_mode_admin");
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "{context} rejected: lane {lane_id} is admin-managed (validator_mode={})",
                state_transaction.lane_validator_mode(lane_id).as_str()
            )),
        ));
    }
    Ok(())
}
fn ensure_canonical_staking_owner(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
    context: &str,
) -> Result<(), Error> {
    let Some(owner_lane) = state_transaction.staking_authority_lane(lane_id) else {
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "{context} rejected: lane {lane_id} has no active staking owner"
            )),
        ));
    };
    if owner_lane != lane_id {
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "{context} rejected: lane {lane_id} shares a physical dataspace whose staking owner is lane {owner_lane}"
            )),
        ));
    }
    Ok(())
}
fn ensure_validator_authority(
    authority: &AccountId,
    validator: &AccountId,
    context: &str,
) -> Result<(), Error> {
    if authority != validator {
        return Err(Error::InvariantViolation(
            format!("{context} rejected: authority must match validator account").into(),
        ));
    }
    Ok(())
}
fn ensure_staker_authority(
    authority: &AccountId,
    staker: &AccountId,
    context: &str,
) -> Result<(), Error> {
    if authority != staker {
        return Err(Error::InvariantViolation(
            format!("{context} rejected: authority must match staker account").into(),
        ));
    }
    Ok(())
}
fn ensure_registration_uses_validator_stake(
    validator: &AccountId,
    stake_account: &AccountId,
    context: &str,
) -> Result<(), Error> {
    if validator != stake_account {
        return Err(Error::InvariantViolation(
            format!("{context} rejected: stake account must match validator account").into(),
        ));
    }
    Ok(())
}
fn ensure_public_lane_validator_record_matches_key(
    key: &(LaneId, AccountId),
    record: &PublicLaneValidatorRecord,
) -> Result<(), Error> {
    if !public_lane_validator_record_matches_key(key, record) {
        return Err(Error::InvariantViolation(
            "public-lane validator record does not match its storage key".into(),
        ));
    }
    if record.stake_account != record.validator {
        return Err(Error::InvariantViolation(
            "public-lane validator stake account must match the validator account".into(),
        ));
    }
    Ok(())
}
fn ensure_public_lane_stake_share_matches_key(
    key: &(LaneId, AccountId, AccountId),
    share: &PublicLaneStakeShare,
) -> Result<(), Error> {
    if public_lane_stake_share_matches_key(key, share) {
        Ok(())
    } else {
        Err(Error::InvariantViolation(
            "public-lane stake share does not match its storage key".into(),
        ))
    }
}
struct CandidateAdmission {
    activation_height: u64,
    prepared_peer: Option<iroha_data_model::consensus::ConsensusKeyRecord>,
}
impl Execute for RegisterPublicLaneValidator {
    #[iroha_logger::log(name = "register_public_lane_validator", skip_all)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        register_public_lane_validator(self, authority, state_transaction, None)
    }
}
impl Execute for RegisterPublicLaneCandidate {
    #[iroha_logger::log(name = "register_public_lane_candidate", skip_all)]
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let registration = self.registration;
        ensure_lane_allows_staking(
            state_transaction,
            registration.lane_id,
            "register_public_lane_candidate",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            registration.lane_id,
            "register_public_lane_candidate",
        )?;
        ensure_validator_authority(
            authority,
            &registration.validator,
            "register_public_lane_candidate",
        )?;
        ensure_registration_uses_validator_stake(
            &registration.validator,
            &registration.stake_account,
            "register_public_lane_candidate",
        )?;
        let parameters = read_staking_policy(state_transaction)?.ok_or_else(|| {
            Error::InvariantViolation(
                "candidate admission requires committed NPoS election parameters".into(),
            )
        })?;
        parameters.validate().map_err(|error| {
            Error::InvariantViolation(
                format!(
                    "candidate admission requires a valid committed NPoS election schedule: {error}"
                )
                .into(),
            )
        })?;
        let block_height = state_transaction.block_height();
        let registered = state_transaction
            .world
            .peers
            .iter()
            .any(|peer| peer == &registration.peer_id);
        let key_activation_height = if registered || state_transaction._curr_block.is_genesis() {
            block_height
        } else {
            block_height
                .checked_add(
                    state_transaction
                        .world
                        .parameters
                        .get()
                        .sumeragi
                        .key_activation_lead_blocks,
                )
                .ok_or_else(|| {
                    Error::InvariantViolation("candidate key activation height overflowed".into())
                })?
        };
        // Consent names one exact future tenure. It cannot authorize admission
        // after that election boundary, including after exit and custody release.
        let activation_height = if state_transaction._curr_block.is_genesis()
            && state_transaction.block_hashes.is_empty()
        {
            block_height
        } else {
            validator_eligibility_height(
                state_transaction,
                registration.lane_id,
                block_height,
                key_activation_height,
            )
            .map_err(|error| retain_staking_attempt(state_transaction, error))?
        };
        if self.activation_height != activation_height {
            return Err(Error::InvariantViolation(
                format!(
                    "candidate consent targets activation height {}, expected {activation_height}",
                    self.activation_height
                )
                .into(),
            ));
        }
        iroha_crypto::bls_normal_pop_verify(
            registration.peer_id.public_key(),
            &self.proof_of_possession,
        )
        .map_err(|_| {
            Error::InvariantViolation(
                "candidate has an invalid BLS-normal proof of possession".into(),
            )
        })?;
        let authorization = PublicLaneCandidateAuthorization::new(
            *state_transaction.network_id(),
            registration.clone(),
            activation_height,
        );
        self.peer_signature
            .verify(registration.peer_id.public_key(), &authorization)
            .map_err(|_| {
                Error::InvariantViolation(
                    "candidate peer signature does not authorize this network and registration"
                        .into(),
                )
            })?;
        let prepared_peer = if registered {
            // A consented pre-registered identity keeps its exact existing key
            // lifecycle and must already be live at admission.
            ensure_validator_peer_registered(
                state_transaction,
                registration.lane_id,
                &registration.validator,
                &registration.peer_id,
                activation_height,
            )?;
            let required_role = consensus_key_role_for_lane(registration.lane_id);
            let exact_live_pop =
                state_transaction
                    .world
                    .consensus_keys()
                    .iter()
                    .any(|(id, record)| {
                        record.id == *id
                            && id.role == required_role
                            && record.public_key == *registration.peer_id.public_key()
                            && record.pop.as_deref() == Some(self.proof_of_possession.as_slice())
                            && record.expiry_height.is_none()
                            && record.is_live_at(block_height, 0, 0)
                            && record.is_live_at(activation_height, 0, 0)
                    });
            if !exact_live_pop {
                return Err(Error::InvariantViolation(
                    "candidate proof of possession must match its live consensus key".into(),
                ));
            }
            None
        } else {
            let role = if registration.lane_id == LaneId::SINGLE {
                iroha_data_model::consensus::ConsensusKeyRole::Validator
            } else {
                iroha_data_model::consensus::ConsensusKeyRole::Committee
            };
            super::world::isi::prepare_peer_identity_with_pop(
                registration.peer_id.clone(),
                self.proof_of_possession,
                Some(key_activation_height),
                None,
                role,
                "RegisterPublicLaneCandidate",
                state_transaction,
            )?
        };
        // Peer preparation is read-only. Publish its identity only after the
        // stake transfer succeeds, even if a host catches an instruction error.
        register_public_lane_validator(
            registration,
            authority,
            state_transaction,
            Some(CandidateAdmission {
                activation_height,
                prepared_peer,
            }),
        )
    }
}
#[allow(clippy::too_many_lines)]
fn register_public_lane_validator(
    registration: RegisterPublicLaneValidator,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
    candidate_admission: Option<CandidateAdmission>,
) -> Result<(), Error> {
    ensure_lane_allows_staking(
        state_transaction,
        registration.lane_id,
        "register_public_lane_validator",
    )?;
    ensure_canonical_staking_owner(
        state_transaction,
        registration.lane_id,
        "register_public_lane_validator",
    )?;
    let is_genesis_bootstrap =
        state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty();
    if !is_genesis_bootstrap {
        ensure_validator_authority(
            authority,
            &registration.validator,
            "register_public_lane_validator",
        )?;
    }
    ensure_registration_uses_validator_stake(
        &registration.validator,
        &registration.stake_account,
        "register_public_lane_validator",
    )?;
    crate::validation_fee_rewards::ensure_reward_identity(&registration.validator)?;
    crate::validation_fee_rewards::ensure_reward_validator_capacity(
        state_transaction,
        registration.lane_id,
        &registration.validator,
    )?;
    finalize_validator_lifecycle(state_transaction)?;
    // Resolve the exact election boundary before validating the peer or
    // moving funds. An open-ended validator tenure requires a validator
    // key that remains live from this boundary onward.
    let activation_height = match &candidate_admission {
        Some(candidate) => candidate.activation_height,
        None => scheduled_validator_eligibility_height(state_transaction, registration.lane_id)
            .map_err(|error| retain_staking_attempt(state_transaction, error))?,
    };
    if let Some(prepared) = candidate_admission
        .as_ref()
        .and_then(|candidate| candidate.prepared_peer.as_ref())
    {
        if prepared.public_key != *registration.peer_id.public_key()
            || prepared.id.role != consensus_key_role_for_lane(registration.lane_id)
            || prepared.expiry_height.is_some()
            || !prepared.is_live_at(activation_height, 0, 0)
        {
            return Err(Error::InvariantViolation(
                "prepared candidate peer does not cover its exact election tenure".into(),
            ));
        }
    } else {
        ensure_validator_peer_registered(
            state_transaction,
            registration.lane_id,
            &registration.validator,
            &registration.peer_id,
            activation_height,
        )?;
    }
    ensure_positive_amount(&registration.initial_stake, "initial stake")?;
    let meets_min = meets_min_stake(
        &registration.initial_stake,
        &state_transaction.nexus.staking.min_validator_stake,
    )?;
    if !meets_min {
        return Err(Error::InvariantViolation(
            "initial stake below minimum configured amount".into(),
        ));
    }
    let stake_ctx = stake_context(
        &state_transaction.world,
        &state_transaction.nexus.dataspace_catalog,
        &state_transaction.nexus.staking,
        &registration.stake_account,
        state_transaction.block_unix_timestamp_ms(),
    )
    .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    assert_stake_amount_matches_spec(
        state_transaction,
        &stake_ctx.asset_definition,
        &registration.initial_stake,
    )?;
    let validator_key = validator_storage_key(registration.lane_id, &registration.validator);
    let replacing_exited = if let Some(existing) = state_transaction
        .world
        .public_lane_validators
        .get(&validator_key)
    {
        ensure_public_lane_validator_record_matches_key(&validator_key, existing)?;
        if !matches!(existing.status, PublicLaneValidatorStatus::Exited) {
            return Err(Error::InvariantViolation(
                "validator already registered for lane".into(),
            ));
        }
        ensure_validator_deactivation_reached(
            existing,
            state_transaction.block_height(),
            "register_public_lane_validator",
        )?;
        let retains_registration = match crate::sumeragi::lanes::custody::retains_registration(
            &state_transaction.world,
            existing,
            state_transaction.block_height(),
        ) {
            Ok(retained) => retained,
            Err(error) => {
                return Err(retain_staking_attempt(
                    state_transaction,
                    error.map_rejection(|message| Error::InvariantViolation(message.into())),
                ));
            }
        };
        if retains_registration {
            return Err(Error::InvariantViolation(
                "original lane custody must expire before validator re-registration".into(),
            ));
        }
        if !existing.total_stake.is_zero()
            || !existing.self_stake.is_zero()
            || state_transaction.world.public_lane_stake_shares.iter().any(
                |((lane, validator, _), _)| {
                    *lane == registration.lane_id && validator == &registration.validator
                },
            )
        {
            return Err(Error::InvariantViolation(
                    "exited validator retains slashable stake custody; finalize every unbond before re-registration"
                        .into(),
                ));
        }
        true
    } else {
        if state_transaction.world.public_lane_stake_shares.iter().any(
            |((lane, validator, _), _)| {
                *lane == registration.lane_id && validator == &registration.validator
            },
        ) {
            return Err(Error::InvariantViolation(
                "validator has orphaned public-lane stake shares".into(),
            ));
        }
        false
    };
    let existing = state_transaction
        .world
        .public_lane_validators
        .iter()
        .filter(|(key, record)| {
            public_lane_validator_record_matches_key(key, record)
                && key.0 == registration.lane_id
                && (!replacing_exited || key.1 != registration.validator)
        })
        .count();
    let max_validators =
        usize::try_from(state_transaction.nexus.staking.max_validators.get()).unwrap_or(usize::MAX);
    if existing >= max_validators {
        return Err(Error::InvariantViolation(
            "lane reached maximum validator capacity".into(),
        ));
    }
    if state_transaction
        .world
        .public_lane_validators
        .iter()
        .any(|(key, record)| {
            public_lane_validator_record_matches_key(key, record)
                && key.0 == registration.lane_id
                && key.1 != registration.validator
                && record.peer_id == registration.peer_id
        })
    {
        return Err(Error::InvariantViolation(
            "validator peer is already retained for lane".into(),
        ));
    }
    if candidate_admission.is_none() && !is_genesis_bootstrap {
        ensure_peer_binding_authority(state_transaction, authority, &registration.peer_id)?;
    }
    let initial_stake = registration.initial_stake.clone();
    // The exact height is assigned while scheduling, not when promotion
    // happens. Boundary-block transactions cannot alter the already-frozen
    // successor roster, so they target the following election instead.
    let pending_status = PublicLaneValidatorStatus::PendingActivation(activation_height);
    let record = PublicLaneValidatorRecord {
        lane_id: registration.lane_id,
        validator: registration.validator.clone(),
        peer_id: registration.peer_id.clone(),
        stake_account: registration.stake_account.clone(),
        total_stake: initial_stake.clone(),
        self_stake: initial_stake.clone(),
        metadata: registration.metadata.clone(),
        status: pending_status.clone(),
        activation_height,
        election_exit_height: None,
        deactivation_height: None,
    };
    ensure_frozen_validator_binding_preserved(
        state_transaction,
        &record,
        "register_public_lane_validator",
    )
    .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    effects::verify_transfer_plan(
        state_transaction,
        &registration.monetary_plan,
        &stake_ctx.staker_asset,
        &stake_ctx.escrow_asset,
        &initial_stake,
        &PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
            activation_height,
        }),
    )
    .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    crate::smartcontracts::isi::asset::isi::execute_staking_bond_transfer(
        state_transaction,
        authority,
        registration.lane_id,
        &registration.validator,
        &registration.stake_account,
        is_genesis_bootstrap,
        stake_ctx.staker_asset.clone(),
        stake_ctx.escrow_asset.clone(),
        initial_stake.clone(),
    )?;
    if replacing_exited {
        let removal_key = validator_key.clone();
        state_transaction
            .world
            .public_lane_validators
            .remove(removal_key);
    }
    state_transaction
        .world
        .public_lane_validators
        .insert(validator_key, record);
    let share = PublicLaneStakeShare {
        lane_id: registration.lane_id,
        validator: registration.validator.clone(),
        staker: registration.stake_account.clone(),
        bonded: initial_stake.clone(),
        pending_unbonds: BTreeMap::new(),
        metadata: Metadata::default(),
    };
    state_transaction.world.public_lane_stake_shares.insert(
        stake_key(
            registration.lane_id,
            &registration.validator,
            &registration.stake_account,
        ),
        share,
    );
    status::record_public_lane_bonded_delta(registration.lane_id, &initial_stake, true);
    #[cfg(feature = "telemetry")]
    {
        state_transaction
            .telemetry
            .record_public_lane_validator_status(registration.lane_id, None, &pending_status);
        state_transaction
            .telemetry
            .increase_public_lane_bonded(registration.lane_id, &initial_stake);
    }
    if let Some(prepared) = candidate_admission.and_then(|candidate| candidate.prepared_peer) {
        super::world::isi::commit_peer_identity_with_pop(
            registration.peer_id,
            prepared,
            state_transaction,
        );
    }
    Ok(())
}
impl Execute for ActivatePublicLaneValidator {
    #[iroha_logger::log(
        name = "activate_public_lane_validator",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(
            state_transaction,
            self.lane_id,
            "activate_public_lane_validator",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "activate_public_lane_validator",
        )?;
        if !state_transaction._curr_block.is_genesis() {
            ensure_validator_authority(
                authority,
                &self.validator,
                "activate_public_lane_validator",
            )?;
        }
        finalize_validator_lifecycle(state_transaction)?;
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let validator_record = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, validator_record)?;
        let validator_peer = validator_record.peer_id.clone();
        let activation_height = validator_record.activation_height;
        ensure_validator_peer_registered(
            state_transaction,
            self.lane_id,
            &self.validator,
            &validator_peer,
            activation_height,
        )?;
        let block_height = state_transaction.block_height();
        // Only the activation metric needs this epoch read. Local refusal is retained
        // by read_staking_policy so the transaction overlay cannot publish.
        #[cfg(feature = "telemetry")]
        let current_epoch = {
            let epoch_length = read_staking_policy(state_transaction)?
                .map_or(
                    iroha_config::parameters::defaults::sumeragi::npos::EPOCH_LENGTH_BLOCKS,
                    |params| params.epoch_length_blocks.get(),
                )
                .max(1);
            current_epoch(block_height, epoch_length)?
        };
        let validator = state_transaction
            .world
            .public_lane_validators
            .get_mut(&validator_key)
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        let previous_status = validator.status.clone();
        match previous_status {
            PublicLaneValidatorStatus::PendingActivation(pending_height) => {
                if block_height < pending_height {
                    return Err(Error::InvariantViolation(
                        "validator activation height not reached".into(),
                    ));
                }
                if validator.activation_height != pending_height {
                    return Err(Error::InvariantViolation(
                        "pending validator activation height is not canonical".into(),
                    ));
                }
                if validator.deactivation_height.is_some() {
                    return Err(Error::InvariantViolation(
                        "pending validator already has a deactivation boundary".into(),
                    ));
                }
                validator.status = PublicLaneValidatorStatus::Active;
            }
            PublicLaneValidatorStatus::Active => return Ok(()),
            _ => {
                return Err(Error::InvariantViolation(
                    "validator not pending activation".into(),
                ));
            }
        }
        #[cfg(feature = "telemetry")]
        {
            state_transaction
                .telemetry
                .record_public_lane_validator_status(
                    self.lane_id,
                    Some(&previous_status),
                    &validator.status,
                );
            state_transaction
                .telemetry
                .record_public_lane_validator_activation(self.lane_id, current_epoch);
        }
        Ok(())
    }
}
impl Execute for RebindPublicLaneValidatorPeer {
    #[iroha_logger::log(
        name = "rebind_public_lane_validator_peer",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, peer_id = %self.peer_id)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(
            state_transaction,
            self.lane_id,
            "rebind_public_lane_validator_peer",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "rebind_public_lane_validator_peer",
        )?;
        ensure_validator_authority(
            authority,
            &self.validator,
            "rebind_public_lane_validator_peer",
        )?;
        finalize_validator_lifecycle(state_transaction)?;
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let record = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, &record)?;
        if record.peer_id == self.peer_id {
            verify_rebind_peer_consent(&self, state_transaction, &record)?;
            return Ok(());
        }
        if !state_transaction._curr_block.is_genesis()
            && state_transaction.block_height().saturating_add(1) >= record.activation_height
        {
            return Err(Error::InvariantViolation(
                "validator peer binding is already frozen for its activation height".into(),
            ));
        }
        match record.status {
            PublicLaneValidatorStatus::PendingActivation(_) => {}
            PublicLaneValidatorStatus::Active
            | PublicLaneValidatorStatus::Exiting(_)
            | PublicLaneValidatorStatus::Exited
            | PublicLaneValidatorStatus::Slashed(_) => {
                return Err(Error::InvariantViolation(
                    "peer rebinding is allowed only before validator activation".into(),
                ));
            }
        }
        ensure_validator_peer_registered(
            state_transaction,
            self.lane_id,
            &self.validator,
            &self.peer_id,
            record.activation_height,
        )?;
        if state_transaction
            .world
            .public_lane_validators
            .iter()
            .any(|(key, record)| {
                public_lane_validator_record_matches_key(key, record)
                    && key.0 == self.lane_id
                    && key.1 != self.validator
                    && record.peer_id == self.peer_id
            })
        {
            return Err(Error::InvariantViolation(
                "validator peer is already registered for lane".into(),
            ));
        }
        verify_rebind_peer_consent(&self, state_transaction, &record)?;
        let mut replacement = record;
        replacement.peer_id = self.peer_id;
        ensure_frozen_validator_binding_preserved(
            state_transaction,
            &replacement,
            "rebind_public_lane_validator_peer",
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        state_transaction
            .world
            .public_lane_validators
            .insert(validator_key, replacement);
        Ok(())
    }
}
fn verify_rebind_peer_consent(
    instruction: &RebindPublicLaneValidatorPeer,
    state_transaction: &StateTransaction<'_, '_>,
    record: &PublicLaneValidatorRecord,
) -> Result<(), Error> {
    let payload = PublicLanePeerBindingAuthorization::new(
        *state_transaction.network_id(),
        instruction.lane_id,
        instruction.validator.clone(),
        instruction.peer_id.clone(),
        record.activation_height,
        record.peer_id.clone(),
    );
    instruction
        .peer_signature
        .verify(instruction.peer_id.public_key(), &payload)
        .map_err(|_| {
            Error::InvariantViolation(
                "replacement peer signature does not authorize this network and validator".into(),
            )
        })
}
impl Execute for ExitPublicLaneValidator {
    #[iroha_logger::log(
        name = "exit_public_lane_validator",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, release_at_ms = self.release_at_ms)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(
            state_transaction,
            self.lane_id,
            "exit_public_lane_validator",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "exit_public_lane_validator",
        )?;
        ensure_validator_authority(authority, &self.validator, "exit_public_lane_validator")?;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        if self.release_at_ms < now_ms {
            return Err(Error::InvariantViolation(
                "release_at_ms must not precede current block".into(),
            ));
        }
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let mut record = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, &record)?;
        let deactivation_height =
            scheduled_validator_deactivation_height(state_transaction, self.lane_id)
                .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        #[cfg(feature = "telemetry")]
        let previous_status = record.status.clone();
        match record.status {
            PublicLaneValidatorStatus::PendingActivation(_)
            | PublicLaneValidatorStatus::Active
            | PublicLaneValidatorStatus::Slashed(_) => {
                record.status = PublicLaneValidatorStatus::Exiting(self.release_at_ms);
            }
            PublicLaneValidatorStatus::Exiting(at) => {
                if now_ms < at {
                    return Err(Error::InvariantViolation(
                        "validator already exiting with a future release time".into(),
                    ));
                }
            }
            PublicLaneValidatorStatus::Exited => return Ok(()),
        }
        let obligated = record.lane_id == LaneId::SINGLE;
        schedule_validator_deactivation(&mut record, deactivation_height, obligated)?;
        ensure_frozen_validator_binding_preserved(
            state_transaction,
            &record,
            "exit_public_lane_validator",
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        state_transaction
            .world
            .public_lane_validators
            .insert(validator_key, record.clone());
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_status(
                self.lane_id,
                Some(&previous_status),
                &record.status,
            );
        prune_zero_custody_exited_validators(state_transaction)?;
        Ok(())
    }
}
impl Execute for BondPublicLaneStake {
    #[iroha_logger::log(
        name = "bond_public_lane_stake",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, staker = %self.staker)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(state_transaction, self.lane_id, "bond_public_lane_stake")?;
        ensure_canonical_staking_owner(state_transaction, self.lane_id, "bond_public_lane_stake")?;
        ensure_staker_authority(authority, &self.staker, "bond_public_lane_stake")?;
        crate::validation_fee_rewards::ensure_reward_identity(&self.validator)?;
        crate::validation_fee_rewards::ensure_reward_identity(&self.staker)?;
        finalize_validator_lifecycle(state_transaction)?;
        ensure_positive_amount(&self.amount, "stake amount")?;
        let stake_ctx = stake_context(
            &state_transaction.world,
            &state_transaction.nexus.dataspace_catalog,
            &state_transaction.nexus.staking,
            &self.staker,
            state_transaction.block_unix_timestamp_ms(),
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        assert_stake_amount_matches_spec(
            state_transaction,
            &stake_ctx.asset_definition,
            &self.amount,
        )?;
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let mut validator_record = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, &validator_record)?;
        if !matches!(
            validator_record.status,
            PublicLaneValidatorStatus::PendingActivation(_) | PublicLaneValidatorStatus::Active
        ) {
            return Err(Error::InvariantViolation(
                "validator status does not accept new stake".into(),
            ));
        }
        let amount = self.amount.clone();
        let available = state_transaction
            .world
            .assets
            .get(&stake_ctx.staker_asset)
            .map_or_else(Quantity::zero, |balance| balance.as_ref().clone());
        if available < amount {
            return Err(Error::Math(MathError::NotEnoughQuantity));
        }
        validator_record.total_stake =
            quantity_add(validator_record.total_stake.clone(), amount.clone())?;
        if is_self_stake_share_staker(
            &self.staker,
            &self.validator,
            &validator_record.stake_account,
        ) {
            validator_record.self_stake =
                quantity_add(validator_record.self_stake.clone(), amount.clone())?;
        }
        ensure_frozen_validator_binding_preserved(
            state_transaction,
            &validator_record,
            "bond_public_lane_stake",
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        let share_key = stake_key(self.lane_id, &self.validator, &self.staker);
        let mut share = if let Some(share) = state_transaction
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .cloned()
        {
            ensure_public_lane_stake_share_matches_key(&share_key, &share)?;
            share
        } else {
            let share_count = state_transaction
                .world
                .public_lane_stake_shares
                .iter()
                .filter(|(key, share)| {
                    (key.0 == self.lane_id && key.1 == self.validator)
                        || (share.lane_id == self.lane_id && share.validator == self.validator)
                })
                .count();
            let max_shares = usize::try_from(
                state_transaction
                    .nexus
                    .staking
                    .max_stake_shares_per_validator
                    .get(),
            )
            .expect("u32 stake-share cap fits usize on supported targets");
            if share_count >= max_shares {
                return Err(Error::InvariantViolation(
                    "validator reached maximum stake-share capacity".into(),
                ));
            }
            PublicLaneStakeShare {
                lane_id: self.lane_id,
                validator: self.validator.clone(),
                staker: self.staker.clone(),
                bonded: Quantity::zero(),
                pending_unbonds: BTreeMap::new(),
                metadata: Metadata::default(),
            }
        };
        share.metadata = self.metadata.clone();
        share.bonded = quantity_add(share.bonded.clone(), amount.clone())?;
        effects::verify_transfer_plan(
            state_transaction,
            &self.monetary_plan,
            &stake_ctx.staker_asset,
            &stake_ctx.escrow_asset,
            &amount,
            &PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
                activation_height: validator_record.activation_height,
                peer_id: validator_record.peer_id.clone(),
            }),
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        crate::smartcontracts::isi::asset::isi::execute_staking_bond_transfer(
            state_transaction,
            authority,
            self.lane_id,
            &self.validator,
            &self.staker,
            false,
            stake_ctx.staker_asset.clone(),
            stake_ctx.escrow_asset.clone(),
            amount.clone(),
        )?;
        state_transaction
            .world
            .public_lane_validators
            .insert(validator_key, validator_record);
        persist_share(state_transaction, share_key, share);
        status::record_public_lane_bonded_delta(self.lane_id, &amount, true);
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .increase_public_lane_bonded(self.lane_id, &amount);
        Ok(())
    }
}
impl Execute for SchedulePublicLaneUnbond {
    #[iroha_logger::log(
        name = "schedule_public_lane_unbond",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, staker = %self.staker)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(
            state_transaction,
            self.lane_id,
            "schedule_public_lane_unbond",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "schedule_public_lane_unbond",
        )?;
        ensure_staker_authority(authority, &self.staker, "schedule_public_lane_unbond")?;
        finalize_validator_lifecycle(state_transaction)?;
        ensure_positive_amount(&self.amount, "unbond amount")?;
        let block_timestamp_ms = state_transaction.block_unix_timestamp_ms();
        let unbonding_delay_ms = duration_millis(state_transaction.nexus.staking.unbonding_delay);
        if self.release_at_ms.saturating_sub(block_timestamp_ms) < unbonding_delay_ms {
            return Err(Error::InvariantViolation(
                "release_at_ms must respect the configured unbonding delay".into(),
            ));
        }
        if self.release_at_ms < block_timestamp_ms {
            return Err(Error::InvariantViolation(
                "release_at_ms must be in the future or equal to the current block".into(),
            ));
        }
        let stake_ctx = retained_stake_context(
            &state_transaction.world,
            self.lane_id,
            &self.validator,
            &self.staker,
        )?;
        assert_stake_amount_matches_spec(
            state_transaction,
            &stake_ctx.asset_definition,
            &self.amount,
        )?;
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let mut validator_snapshot = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, &validator_snapshot)?;
        let slashable_through_height =
            scheduled_validator_deactivation_height(state_transaction, self.lane_id)
                .map_err(|error| retain_staking_attempt(state_transaction, error))?
                .checked_sub(1)
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        "public-lane unbond slashable height underflowed".into(),
                    )
                })?;
        let liability_release_height =
            unbond_liability_release_height(state_transaction, slashable_through_height)?;
        let amount = self.amount.clone();
        let share_key = stake_key(self.lane_id, &self.validator, &self.staker);
        let mut share = state_transaction
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("stake position not found".into()))?;
        ensure_public_lane_stake_share_matches_key(&share_key, &share)?;
        if share.pending_unbonds.contains_key(&self.request_id) {
            return Err(Error::InvariantViolation(
                "unbond request already scheduled".into(),
            ));
        }
        let max_pending = usize::try_from(
            state_transaction
                .nexus
                .staking
                .max_pending_unbonds_per_share
                .get(),
        )
        .expect("u32 pending-unbond cap fits usize on supported targets");
        if share.pending_unbonds.len() >= max_pending {
            return Err(Error::InvariantViolation(
                "stake share reached maximum pending-unbond capacity".into(),
            ));
        }
        if share.bonded < amount {
            return Err(Error::InvariantViolation(
                "unbond exceeds bonded amount".into(),
            ));
        }
        if validator_snapshot.total_stake < amount {
            return Err(Error::InvariantViolation(
                "unbond exceeds validator total stake".into(),
            ));
        }
        validator_snapshot.total_stake =
            quantity_sub(validator_snapshot.total_stake.clone(), amount.clone())?;
        if is_self_stake_share_staker(
            &self.staker,
            &self.validator,
            &validator_snapshot.stake_account,
        ) {
            validator_snapshot.self_stake =
                quantity_sub(validator_snapshot.self_stake.clone(), amount.clone())?;
        }
        ensure_frozen_validator_binding_preserved(
            state_transaction,
            &validator_snapshot,
            "schedule_public_lane_unbond",
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        share.bonded = quantity_sub(share.bonded.clone(), amount.clone())?;
        share.pending_unbonds.insert(
            self.request_id,
            PublicLaneUnbonding {
                request_id: self.request_id,
                amount: amount.clone(),
                release_at_ms: self.release_at_ms,
                slashable_through_height,
                liability_release_height,
            },
        );
        state_transaction
            .world
            .public_lane_validators
            .insert(validator_key, validator_snapshot);
        persist_share(state_transaction, share_key, share);
        status::record_public_lane_bonded_delta(self.lane_id, &amount, false);
        status::record_public_lane_pending_unbond_delta(self.lane_id, &amount, true);
        #[cfg(feature = "telemetry")]
        {
            state_transaction
                .telemetry
                .decrease_public_lane_bonded(self.lane_id, &self.amount);
            state_transaction
                .telemetry
                .increase_public_lane_pending_unbond(self.lane_id, &self.amount);
        }
        Ok(())
    }
}
impl Execute for FinalizePublicLaneUnbond {
    #[iroha_logger::log(
        name = "finalize_public_lane_unbond",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, staker = %self.staker)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "finalize_public_lane_unbond",
        )?;
        ensure_staker_authority(authority, &self.staker, "finalize_public_lane_unbond")?;
        finalize_validator_lifecycle(state_transaction)?;
        let block_timestamp_ms = state_transaction.block_unix_timestamp_ms();
        let stake_ctx = retained_stake_context(
            &state_transaction.world,
            self.lane_id,
            &self.validator,
            &self.staker,
        )?;
        let validator_key = validator_storage_key(self.lane_id, &self.validator);
        let validator_record = state_transaction
            .world
            .public_lane_validators
            .get(&validator_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
        ensure_public_lane_validator_record_matches_key(&validator_key, &validator_record)?;
        if has_global_committee_obligation(state_transaction, &validator_record)
            || crate::sumeragi::lanes::custody::retains_registration(
                &state_transaction.world,
                &validator_record,
                state_transaction.block_height(),
            )
            .map_err(|error| {
                retain_staking_attempt(
                    state_transaction,
                    error.map_rejection(|message| Error::InvariantViolation(message.into())),
                )
            })?
        {
            return Err(Error::InvariantViolation(
                "unbond withdrawal requires authenticated release of current and frozen committee obligations".into(),
            ));
        }
        let share_key = stake_key(self.lane_id, &self.validator, &self.staker);
        let mut share = state_transaction
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .cloned()
            .ok_or_else(|| Error::InvariantViolation("stake position not found".into()))?;
        ensure_public_lane_stake_share_matches_key(&share_key, &share)?;
        let pending = share
            .pending_unbonds
            .remove(&self.request_id)
            .ok_or_else(|| Error::InvariantViolation("unbond request not found".into()))?;
        ensure_canonical_pending_unbond(&self.request_id, &pending)?;
        let current_height = state_transaction.block_height();
        let current_policy_release_height =
            unbond_liability_release_height(state_transaction, pending.slashable_through_height)?;
        let liability_release_height = pending
            .liability_release_height
            .max(current_policy_release_height);
        if current_height < liability_release_height {
            return Err(Error::InvariantViolation(
                format!(
                    "unbond request remains slashable through the pre-transaction effects at block height {liability_release_height}"
                )
                .into(),
            ));
        }
        if pending.release_at_ms > block_timestamp_ms {
            return Err(Error::InvariantViolation(
                "unbond request not yet releasable".into(),
            ));
        }
        assert_stake_amount_matches_spec(
            state_transaction,
            &stake_ctx.asset_definition,
            &pending.amount,
        )?;
        let request_hash = public_lane_unbonding_commitment(&pending).map_err(|error| {
            Error::InvariantViolation(format!("unbond monetary commitment failed: {error}").into())
        })?;
        effects::verify_transfer_plan(
            state_transaction,
            &self.monetary_plan,
            &stake_ctx.escrow_asset,
            &stake_ctx.staker_asset,
            &pending.amount,
            &PublicLaneMonetaryPreconditionV1::Unbond(PublicLaneMonetaryUnbondV1 {
                activation_height: validator_record.activation_height,
                request_hash,
            }),
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        crate::smartcontracts::isi::asset::isi::execute_staking_unbond_transfer(
            state_transaction,
            authority,
            self.lane_id,
            &self.validator,
            &self.staker,
            self.request_id,
            stake_ctx.escrow_asset,
            stake_ctx.staker_asset,
            pending.amount.clone(),
        )?;
        persist_share(state_transaction, share_key, share);
        status::record_public_lane_pending_unbond_delta(self.lane_id, &pending.amount, false);
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .decrease_public_lane_pending_unbond(self.lane_id, &pending.amount);
        prune_zero_custody_exited_validators(state_transaction)?;
        Ok(())
    }
}
impl Execute for SlashPublicLaneValidator {
    #[iroha_logger::log(
        name = "slash_public_lane_validator",
        skip_all,
        fields(lane_id = %self.lane_id, validator = %self.validator, slash_id = %self.slash_id)
    )]
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_lane_allows_staking(
            state_transaction,
            self.lane_id,
            "slash_public_lane_validator",
        )?;
        ensure_canonical_staking_owner(
            state_transaction,
            self.lane_id,
            "slash_public_lane_validator",
        )?;
        finalize_validator_lifecycle(state_transaction)?;
        ensure_positive_amount(&self.amount, "slash amount")?;
        let current_height = state_transaction.block_height();
        if self.offence_height == 0 || self.offence_height > current_height {
            return Err(Error::InvariantViolation(
                "slash offence height must identify a non-zero height no later than the current block"
                    .into(),
            ));
        }
        let recorded_at_ms = state_transaction.block_unix_timestamp_ms();
        apply_slash_to_validator(
            state_transaction,
            self.lane_id,
            &self.validator,
            self.offence_height,
            self.slash_id,
            &self.amount,
            recorded_at_ms,
            &self.monetary_plan,
        )
    }
}
impl Execute for ClaimPublicLaneRewards {
    #[iroha_logger::log(
        name = "claim_public_lane_rewards",
        skip_all,
        fields(lane_id = %self.lane_id, account = %self.account)
    )]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if &self.account != authority {
            return Err(Error::InvariantViolation(
                "reward claims must be submitted by the recipient account".into(),
            ));
        }
        effects::validate_plan_context(
            state_transaction,
            &self.claim_plan.network_scope,
            self.claim_plan.valid_until_height,
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
        if !self.claim_plan.has_canonical_shape(&self.account) {
            return Err(Error::InvariantViolation(
                "reward claim must authorize one exact positive funded payment".into(),
            ));
        }
        let fee_claim = crate::validation_fee_rewards::prepare_fee_reward_claim(
            state_transaction,
            &self.account,
            self.lane_id,
            &self.claim_plan.fee_claim,
        )?;
        crate::validation_fee_rewards::claim_fee_rewards(state_transaction, fee_claim)?;
        Ok(())
    }
}
fn validator_storage_key(lane_id: LaneId, validator: &AccountId) -> (LaneId, AccountId) {
    (lane_id, validator.clone())
}
fn finalize_validator_lifecycle(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    finalize_pending_activations(state_transaction)?;
    finalize_released_exits(state_transaction)?;
    prune_zero_custody_exited_validators(state_transaction)?;
    Ok(())
}

fn prune_zero_custody_exited_validators(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let retention_policy = read_staking_policy(state_transaction)?;
    let removable =
        state_transaction
            .world
            .public_lane_validators
            .iter()
            .filter(|(key, record)| {
                public_lane_validator_record_matches_key(key, record)
                    && matches!(record.status, PublicLaneValidatorStatus::Exited)
                    && ensure_validator_deactivation_reached(
                        record,
                        state_transaction.block_height(),
                        "validator pruning",
                    )
                    .is_ok()
                    && !crate::sumeragi::lanes::custody::retains_registration_with_parameters(
                        &state_transaction.world,
                        record,
                        state_transaction.block_height(),
                        retention_policy.as_ref(),
                    )
                    && record.total_stake.is_zero()
                    && record.self_stake.is_zero()
                    && !state_transaction.world.public_lane_stake_shares.iter().any(
                        |((lane_id, validator, _), _)| *lane_id == key.0 && validator == &key.1,
                    )
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
    for key in removable {
        state_transaction.world.public_lane_validators.remove(key);
    }
    Ok(())
}
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub(crate) fn promote_pending_validator(
    record: &mut PublicLaneValidatorRecord,
    lane_id: LaneId,
    block_height: u64,
    current_epoch: u64,
    previous_status: &PublicLaneValidatorStatus,
    telemetry: Option<&StateTelemetry>,
) -> Result<(), Error> {
    let pending_height = match record.status {
        PublicLaneValidatorStatus::PendingActivation(height) => height,
        _ => {
            return Err(Error::InvariantViolation(
                "only a pending validator can be promoted".into(),
            ));
        }
    };
    if block_height < pending_height {
        return Err(Error::InvariantViolation(
            "validator activation height has not been reached".into(),
        ));
    }
    if record.activation_height != pending_height {
        return Err(Error::InvariantViolation(
            "pending validator activation height is not canonical".into(),
        ));
    }
    if record.deactivation_height.is_some() {
        return Err(Error::InvariantViolation(
            "pending validator already has a deactivation boundary".into(),
        ));
    }
    record.status = PublicLaneValidatorStatus::Active;
    #[cfg(not(feature = "telemetry"))]
    let _ = telemetry;
    #[cfg(feature = "telemetry")]
    if let Some(tel) = telemetry {
        tel.record_public_lane_validator_status(lane_id, Some(previous_status), &record.status);
        tel.record_public_lane_validator_activation(lane_id, current_epoch);
    }
    Ok(())
}
fn finalize_pending_activations(
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let block_height = state_transaction.block_height();
    let epoch_length = read_staking_policy(state_transaction)?
        .map_or(
            iroha_config::parameters::defaults::sumeragi::npos::EPOCH_LENGTH_BLOCKS,
            |params| params.epoch_length_blocks.get(),
        )
        .max(1);
    let current_epoch = current_epoch(block_height, epoch_length)?;
    let to_activate: Vec<_> = state_transaction
        .world
        .public_lane_validators
        .iter()
        .filter(|(key, record)| {
            public_lane_validator_record_matches_key(key, record)
                && state_transaction.staking_authority_lane(key.0) == Some(key.0)
                && matches!(
                    record.status,
                    PublicLaneValidatorStatus::PendingActivation(pending) if pending <= block_height
            )
        })
        .map(|(key, record)| (key.clone(), record.status.clone()))
        .collect();
    for (key, previous_status) in to_activate {
        let Some(record) = state_transaction.world.public_lane_validators.get_mut(&key) else {
            continue;
        };
        let telemetry = {
            #[cfg(feature = "telemetry")]
            {
                Some(state_transaction.telemetry)
            }
            #[cfg(not(feature = "telemetry"))]
            {
                None
            }
        };
        promote_pending_validator(
            record,
            key.0,
            block_height,
            current_epoch,
            &previous_status,
            telemetry,
        )?;
    }
    Ok(())
}
fn finalize_released_exits(state_transaction: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
    let retention_policy = read_staking_policy(state_transaction)?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let exiting: Vec<_> = state_transaction
        .world
        .public_lane_validators
        .iter()
        .filter(|(key, record)| {
            public_lane_validator_record_matches_key(key, record)
                && record
                    .deactivation_height
                    .is_some_and(|end| end <= state_transaction.block_height())
                && !has_global_committee_obligation(state_transaction, record)
                && !crate::sumeragi::lanes::custody::retains_registration_with_parameters(
                    &state_transaction.world,
                    record,
                    state_transaction.block_height(),
                    retention_policy.as_ref(),
                )
                && matches!(
                    record.status,
                    PublicLaneValidatorStatus::Exiting(releases_at) if releases_at <= now_ms
                )
        })
        .map(|(key, record)| (key.clone(), record.status.clone()))
        .collect();
    for (key, previous_status) in exiting {
        if let Some(record) = state_transaction.world.public_lane_validators.get_mut(&key) {
            record.status = PublicLaneValidatorStatus::Exited;
        }
        #[cfg(not(feature = "telemetry"))]
        let _ = previous_status;
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_status(
                key.0,
                Some(&previous_status),
                &PublicLaneValidatorStatus::Exited,
            );
    }
    Ok(())
}
fn stake_key(
    lane_id: LaneId,
    validator: &AccountId,
    staker: &AccountId,
) -> (LaneId, AccountId, AccountId) {
    (lane_id, validator.clone(), staker.clone())
}
fn ensure_positive_amount(amount: &Quantity, label: &str) -> Result<(), Error> {
    if amount.is_zero() {
        return Err(Error::InvariantViolation(
            format!("{label} must be greater than zero").into(),
        ));
    }
    Ok(())
}
fn quantity_add(lhs: Quantity, rhs: Quantity) -> Result<Quantity, Error> {
    lhs.checked_add(&rhs)
        .map_err(|_| Error::Math(MathError::Overflow))
}
fn quantity_sub(lhs: Quantity, rhs: Quantity) -> Result<Quantity, Error> {
    lhs.checked_sub(&rhs)
        .map_err(|_| Error::Math(MathError::Overflow))
}
/// Distinct native evidence clocks. A lane proof names its creation-time registration;
/// its native subject height can never become a global tenure or withdrawal boundary.
#[derive(Clone, Copy, Debug)]
#[expect(
    variant_size_differences,
    reason = "original cut and tenure are fixed scalar custody; boxing creates an uncharged monetary authority owner"
)]
pub(crate) enum ConsensusSlashLiability {
    /// Root consensus subjects use the authenticated global offence height.
    Root(u64),
    /// Lane liability is limited to the exact original signer and retained escrow tenure.
    Lane {
        scope: iroha_data_model::block::consensus::LaneEvidenceScope,
        instance: [u8; 32],
        recorded_at: u64,
        signer: u32,
        binding: iroha_data_model::sumeragi_lanes::SumeragiLaneStakeBinding,
    },
}
impl ConsensusSlashLiability {
    /// Build the typed clock from an already authenticated committed attribution.
    /// An originally unbound lane member is forensic only, even if it later registers stake.
    pub(crate) fn from_attribution(
        attribution: &iroha_data_model::block::consensus::EvidenceAttribution,
        recorded_at: u64,
        signer: u32,
    ) -> Option<Self> {
        use iroha_data_model::block::consensus::EvidenceScope;
        let offender = attribution
            .offenders
            .iter()
            .find(|offender| offender.signer == signer)?;
        match attribution.scope {
            EvidenceScope::Root if offender.lane_stake.is_none() => {
                Some(Self::Root(attribution.height))
            }
            EvidenceScope::Root => None,
            EvidenceScope::Lane(scope) => Some(Self::Lane {
                scope,
                instance: attribution.instance,
                recorded_at,
                signer,
                binding: offender.lane_stake?,
            }),
        }
    }
    fn offence_height(self) -> Option<u64> {
        match self {
            Self::Root(height) => Some(height),
            Self::Lane { .. } => None,
        }
    }
    /// Revalidate the original World row, immutable policy, registration and actual escrow.
    /// No current route, later registration or native height supplies monetary authority.
    pub(crate) fn names_registration(
        self,
        world: &impl WorldReadOnly,
        record: &PublicLaneValidatorRecord,
    ) -> Result<bool, Attempt<Error>> {
        let Self::Lane {
            scope,
            instance,
            recorded_at,
            signer,
            binding,
        } = self
        else {
            return validator_tenure_contains_height(
                record,
                self.offence_height().expect("root clock"),
            )
            .map_err(Attempt::Rejected);
        };
        if cfg!(all(test, sumeragi_core_mutation = "HC2")) {
            return Ok(true);
        }
        let invalid = |reason: &str| Error::InvariantViolation(reason.into());
        let parameters = world
            .sumeragi_npos_parameters()
            .map_err(|error| {
                error.map_rejection(|message| Error::InvariantViolation(message.into()))
            })?
            .ok_or_else(|| invalid("lane slash lost immutable evidence policy"))?;
        let mut rows = world
            .sumeragi_lanes()
            .custody
            .iter()
            .filter(|row| row.incarnation == scope.incarnation);
        let row = rows
            .next()
            .ok_or_else(|| invalid("lane slash lost original custody obligation"))?;
        if rows.next().is_some()
            || row.validate().is_err()
            || row.lane != scope.lane
            || row.instance != instance
            || row.created_at != scope.created_at
            || scope.admission_parent_height.checked_add(1) != Some(recorded_at)
            || row
                .created_at
                .checked_add(2)
                .is_none_or(|active| active > scope.admission_parent_height)
            || row.evidence_horizon != parameters.evidence_horizon_blocks()
            || row.slashing_delay != parameters.slashing_delay_blocks()
            || row.admits_at(recorded_at) != Ok(true)
            || row
                .signers
                .as_slice()
                .iter()
                .find(|entry| entry.signer == signer)
                .map(|entry| entry.binding)
                != Some(binding)
        {
            return Err((invalid(
                "lane slash differs from its original admission and signer custody",
            ))
            .into());
        }
        if record.activation_height != binding.activation_height
            || !binding
                .names_account(record.lane_id, &record.validator)
                .map_err(|reason| Error::InvariantViolation(reason.into()))?
        {
            return Ok(false);
        }
        // Borrow the canonical composite key and actual escrow without constructing an
        // unfunded account clone solely for lookup. A fully consumed escrow has no exposure.
        let Some((_, (escrow, _))) = world
            .public_lane_stake_custody()
            .iter()
            .find(|((lane, account), _)| *lane == record.lane_id && account == &record.validator)
        else {
            return Ok(false);
        };
        let actual =
            iroha_data_model::sumeragi_lanes::SumeragiLaneStakeBinding::from_record(record, escrow)
                .map_err(|reason| Error::InvariantViolation(reason.into()))?;
        if actual != binding {
            return Err((invalid("original lane registration or escrow was substituted")).into());
        }
        Ok(true)
    }
}

/// Return offence-height-eligible custody using a complete indexed key slice.
pub(crate) fn indexed_slashable_validator_exposure(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    record: &PublicLaneValidatorRecord,
    liability: ConsensusSlashLiability,
    share_keys: &[PublicLaneStakeShareKey],
) -> Result<Quantity, Attempt<Error>> {
    if !liability.names_registration(world, record)? {
        return Ok(Quantity::zero());
    }
    if !share_keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err((Error::InvariantViolation(
            "indexed public-lane stake-share keys are not canonical".into(),
        ))
        .into());
    }
    // This read-only calculation borrows the owned ordered scratch overlay.
    // An earlier slash in that same bundle may have removed a fully consumed
    // indexed row. Such a missing row is valid only with the exact current
    // validator totals checked by slashable_exposure_from_shares below; no
    // external source or unordered replay may supply this overlay.
    // Neither path funds Quantity arithmetic or retained key copies here.
    let shares = share_keys.iter().filter_map(|key| {
        if key.0 != lane_id || &key.1 != validator {
            return Some(Err(Error::InvariantViolation(
                "indexed public-lane stake-share key belongs to another validator".into(),
            )));
        }
        let share = world.public_lane_stake_shares().get(key)?;
        if !public_lane_stake_share_matches_key(key, share) {
            return Some(Err(Error::InvariantViolation(
                "public-lane stake share does not match its storage key".into(),
            )));
        }
        Some(Ok((key, share)))
    });
    slashable_exposure_from_shares(record, shares, liability.offence_height())
        .map_err(Attempt::Rejected)
}

fn validator_share_updates(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    indexed_share_keys: Option<&[PublicLaneStakeShareKey]>,
) -> Result<Vec<(PublicLaneStakeShareKey, PublicLaneStakeShare)>, Error> {
    let mut shares = Vec::new();
    if let Some(keys) = indexed_share_keys {
        if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(Error::InvariantViolation(
                "indexed public-lane stake-share keys are not canonical".into(),
            ));
        }
        for key in keys {
            if key.0 != lane_id || &key.1 != validator {
                return Err(Error::InvariantViolation(
                    "indexed public-lane stake-share key belongs to another validator".into(),
                ));
            }
            let Some(share) = world.public_lane_stake_shares().get(key) else {
                // An earlier slash in the same ordered consensus bundle may
                // have consumed and removed this exact indexed share.
                continue;
            };
            if !public_lane_stake_share_matches_key(key, share) {
                return Err(Error::InvariantViolation(
                    "public-lane stake share does not match its storage key".into(),
                ));
            }
            shares.push((key.clone(), share.clone()));
        }
        return Ok(shares);
    }

    for (key, share) in world.public_lane_stake_shares().iter() {
        if key.0 != lane_id || &key.1 != validator {
            continue;
        }
        if !public_lane_stake_share_matches_key(key, share) {
            return Err(Error::InvariantViolation(
                "public-lane stake share does not match its storage key".into(),
            ));
        }
        shares.push((key.clone(), share.clone()));
    }
    Ok(shares)
}

fn pending_unbond_is_slashable_at(
    pending: &PublicLaneUnbonding,
    offence_height: Option<u64>,
) -> bool {
    offence_height.is_none_or(|height| height <= pending.slashable_through_height)
}

fn slashable_exposure_from_shares<'a>(
    record: &PublicLaneValidatorRecord,
    shares: impl IntoIterator<
        Item = Result<(&'a PublicLaneStakeShareKey, &'a PublicLaneStakeShare), Error>,
    >,
    offence_height: Option<u64>,
) -> Result<Quantity, Error> {
    if record.stake_account != record.validator {
        return Err(Error::InvariantViolation(
            "public-lane validator stake account must match the validator account".into(),
        ));
    }
    let mut bonded = Quantity::zero();
    let mut self_bonded = Quantity::zero();
    let mut pending_unbonds = Quantity::zero();
    for share in shares {
        let (key, share) = share?;
        bonded = quantity_add(bonded, share.bonded.clone())?;
        if key.2 == record.stake_account {
            self_bonded = quantity_add(self_bonded, share.bonded.clone())?;
        }
        for (request_id, pending) in &share.pending_unbonds {
            ensure_canonical_pending_unbond(request_id, pending)?;
            if pending_unbond_is_slashable_at(pending, offence_height) {
                pending_unbonds = quantity_add(pending_unbonds, pending.amount.clone())?;
            }
        }
    }
    if bonded != record.total_stake || self_bonded != record.self_stake {
        return Err(Error::InvariantViolation(
            "public-lane validator totals do not match canonical stake shares".into(),
        ));
    }
    quantity_add(bonded, pending_unbonds)
}
fn min_quantity(lhs: Quantity, rhs: Quantity) -> Quantity {
    if lhs <= rhs { lhs } else { rhs }
}
fn persist_share(
    state_transaction: &mut StateTransaction<'_, '_>,
    key: (LaneId, AccountId, AccountId),
    share: PublicLaneStakeShare,
) {
    if share.bonded.is_zero() && share.pending_unbonds.is_empty() {
        state_transaction.world.public_lane_stake_shares.remove(key);
        return;
    }
    state_transaction
        .world
        .public_lane_stake_shares
        .insert(key, share);
}
fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
fn unbond_liability_release_height(
    state_transaction: &mut StateTransaction<'_, '_>,
    slashable_through_height: u64,
) -> Result<u64, Error> {
    let parameters = read_staking_policy(state_transaction)?.ok_or_else(|| {
        Error::InvariantViolation("public-lane unbonding requires signed NPoS parameters".into())
    })?;
    slashable_through_height
        .checked_add(parameters.evidence_horizon_blocks())
        .and_then(|height| height.checked_add(parameters.slashing_delay_blocks()))
        .ok_or_else(|| {
            Error::InvariantViolation("public-lane unbond liability height overflows u64".into())
        })
}
fn ensure_canonical_pending_unbond(
    request_id: &Hash,
    pending: &PublicLaneUnbonding,
) -> Result<(), Error> {
    if request_id != &pending.request_id
        || pending.amount.is_zero()
        || pending.slashable_through_height == 0
        || pending.liability_release_height < pending.slashable_through_height
    {
        return Err(Error::InvariantViolation(
            "public-lane pending unbond is non-canonical".into(),
        ));
    }
    Ok(())
}
pub(crate) fn meets_min_stake(amount: &Quantity, minimum: &Quantity) -> Result<bool, Error> {
    Ok(amount >= minimum)
}
fn slash_within_limit(amount: &Quantity, total: &Quantity, max_bps: u16) -> Result<bool, Error> {
    Ok(!amount
        .cmp_mul_u64(10_000, total, u64::from(max_bps))
        .is_gt())
}
fn is_self_stake_share_staker(
    staker: &AccountId,
    validator: &AccountId,
    stake_account: &AccountId,
) -> bool {
    staker == validator || staker == stake_account
}
/// Compute the maximum slashable amount given a total bonded stake and max ratio.
pub(crate) fn max_slash_amount(total: &Quantity, max_bps: u16) -> Result<Quantity, Error> {
    if total.is_zero() || max_bps == 0 {
        return Ok(Quantity::zero());
    }
    if max_bps >= 10_000 {
        return Ok(total.clone());
    }
    let amount = total
        .try_mul_div_decimal_round(
            &Numeric::from(u64::from(max_bps)),
            &Numeric::from(10_000_u64),
            total.scale(),
            RoundingMode::TowardZero,
        )
        .map_err(|_| Error::Math(MathError::Overflow))?;
    Ok(amount)
}
fn ensure_peer_binding_authority(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    peer: &PeerId,
) -> Result<(), Error> {
    if authority
        .try_signatory()
        .is_some_and(|key| key == peer.public_key())
        || super::world::isi::has_exact_permission(
            &state_transaction.world,
            authority,
            &iroha_executor_data_model::permission::peer::CanManagePeers.into(),
        )
    {
        return Ok(());
    }
    Err(Error::InvariantViolation(
        "distinct consensus peer binding requires its network-bound consent or CanManagePeers"
            .into(),
    ))
}
fn ensure_validator_peer_registered(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    validator_peer: &PeerId,
    required_live_height: u64,
) -> Result<(), Error> {
    // Lane zero is global Sumeragi and requires a Validator key. Participant
    // lanes require their purpose-specific Committee key.
    let required_role = consensus_key_role_for_lane(lane_id);
    let role_label = if lane_id == LaneId::SINGLE {
        "validator"
    } else {
        "committee"
    };
    if !state_transaction
        .world
        .peers
        .iter()
        .any(|peer| peer == validator_peer)
    {
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_reject("missing_peer");
        iroha_logger::warn!(
            lane_id = %lane_id,
            validator = %validator,
            peer = %validator_peer,
            "public-lane validator action rejected: peer not registered in topology"
        );
        return Err(Error::InvariantViolation(
            "validator peer must be registered before staking".into(),
        ));
    }
    let block_height = state_transaction.block_height();
    let gate = peer_consensus_key_gate_for_lane(
        &state_transaction.world,
        validator_peer,
        block_height,
        lane_id,
    );
    if gate != ConsensusKeyGate::Live {
        let (telemetry_reason, message) = match gate {
            ConsensusKeyGate::Live => ("consensus_key_live", "unexpected live consensus key"),
            ConsensusKeyGate::Missing => (
                "consensus_key_missing",
                "validator peer must register the required consensus key before staking",
            ),
            ConsensusKeyGate::NotYetActive => (
                "consensus_key_pending",
                "validator peer consensus key is not yet active for this block",
            ),
            ConsensusKeyGate::Expired => (
                "consensus_key_expired",
                "validator peer consensus key expired before this block",
            ),
            ConsensusKeyGate::Disabled => (
                "consensus_key_disabled",
                "validator peer consensus key is disabled",
            ),
        };
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_reject(telemetry_reason);
        iroha_logger::warn!(
            lane_id = %lane_id,
            validator = %validator,
            peer = %validator_peer,
            height = block_height,
            reason = telemetry_reason,
            "public-lane validator action rejected: {message}"
        );
        return Err(Error::InvariantViolation(message.into()));
    }
    let peer_public_key = validator_peer.public_key();
    let has_unbounded_lane_key = state_transaction
        .world
        .consensus_keys_by_pk()
        .get(&peer_public_key.to_string())
        .is_some_and(|ids| {
            ids.iter().any(|id| {
                id.role == required_role
                    && state_transaction
                        .world
                        .consensus_keys()
                        .get(id)
                        .is_some_and(|record| {
                            record.id == *id
                                && record.public_key == *peer_public_key
                                && record.expiry_height.is_none()
                                && record.is_live_at(required_live_height, 0, 0)
                        })
            })
        });
    if !has_unbounded_lane_key {
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_public_lane_validator_reject("consensus_key_not_unbounded");
        iroha_logger::warn!(
            lane_id = %lane_id,
            validator = %validator,
            peer = %validator_peer,
            required_live_height,
            required_roles = role_label,
            "public-lane validator action rejected: no unbounded required-role consensus key covers the scheduled activation height"
        );
        return Err(Error::InvariantViolation(
            format!(
                "validator peer requires an unbounded {role_label} consensus key live at its scheduled activation height"
            )
            .into(),
        ));
    }
    // Only lane-zero staking records are global election candidates. A
    // participant peer's other registered key roles do not grant a global seat.
    if lane_id == LaneId::SINGLE
        && !state_transaction.commit_topology.is_empty()
        && !state_transaction
            .commit_topology
            .iter()
            .any(|peer| peer == validator_peer)
    {
        return Err(Error::InvariantViolation(
            "global validator peer must be present in the commit topology; a prepared epoch key transition is required for a fresh peer".into(),
        ));
    }
    Ok(())
}
fn slash_bonded_share_group(
    shares: &mut [((LaneId, AccountId, AccountId), PublicLaneStakeShare)],
    validator: &AccountId,
    stake_account: &AccountId,
    self_stake_group: bool,
    amount: &Quantity,
) -> Result<(), Error> {
    let mut remaining = amount.clone();
    for ((_, _, staker), share) in shares {
        if remaining.is_zero() {
            break;
        }
        if is_self_stake_share_staker(staker, validator, stake_account) != self_stake_group
            || share.bonded.is_zero()
        {
            continue;
        }
        let slash_part = min_quantity(share.bonded.clone(), remaining.clone());
        share.bonded = quantity_sub(share.bonded.clone(), slash_part.clone())?;
        remaining = quantity_sub(remaining, slash_part)?;
    }
    if !remaining.is_zero() {
        return Err(Error::InvariantViolation(
            "slash could not be satisfied by bonded stake shares".into(),
        ));
    }
    Ok(())
}
fn slash_pending_unbond_group(
    shares: &mut [((LaneId, AccountId, AccountId), PublicLaneStakeShare)],
    validator: &AccountId,
    stake_account: &AccountId,
    self_stake_group: bool,
    amount: &Quantity,
    offence_height: Option<u64>,
) -> Result<(), Error> {
    let mut remaining = amount.clone();
    for ((_, _, staker), share) in shares {
        if remaining.is_zero() {
            break;
        }
        if is_self_stake_share_staker(staker, validator, stake_account) != self_stake_group {
            continue;
        }
        let request_ids = share.pending_unbonds.keys().copied().collect::<Vec<_>>();
        for request_id in request_ids {
            if remaining.is_zero() {
                break;
            }
            let pending = share
                .pending_unbonds
                .get_mut(&request_id)
                .expect("request id was collected from this exact share");
            ensure_canonical_pending_unbond(&request_id, pending)?;
            if !pending_unbond_is_slashable_at(pending, offence_height) {
                continue;
            }
            let slash_part = min_quantity(pending.amount.clone(), remaining.clone());
            pending.amount = quantity_sub(pending.amount.clone(), slash_part.clone())?;
            remaining = quantity_sub(remaining, slash_part)?;
            if pending.amount.is_zero() {
                share.pending_unbonds.remove(&request_id);
            }
        }
    }
    if !remaining.is_zero() {
        return Err(Error::InvariantViolation(
            "slash could not be satisfied by pending unbond custody".into(),
        ));
    }
    Ok(())
}
fn pending_unbond_group_total(
    shares: &[((LaneId, AccountId, AccountId), PublicLaneStakeShare)],
    validator: &AccountId,
    stake_account: &AccountId,
    self_stake_group: bool,
    offence_height: Option<u64>,
) -> Result<Quantity, Error> {
    let mut total = Quantity::zero();
    for ((_, _, staker), share) in shares {
        if is_self_stake_share_staker(staker, validator, stake_account) != self_stake_group {
            continue;
        }
        for (request_id, pending) in &share.pending_unbonds {
            ensure_canonical_pending_unbond(request_id, pending)?;
            if pending_unbond_is_slashable_at(pending, offence_height) {
                total = quantity_add(total, pending.amount.clone())?;
            }
        }
    }
    Ok(total)
}
/// Apply a slash to a validator through the central retained-movement path.
pub(crate) fn apply_slash_to_validator(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    offence_height: u64,
    slash_id: Hash,
    amount: &Quantity,
    now_ms: u64,
    monetary_plan: &PublicLaneMonetaryPlanV1,
) -> Result<(), Error> {
    apply_slash_to_validator_inner(
        state_transaction,
        lane_id,
        validator,
        slash_id,
        amount,
        now_ms,
        Some(ConsensusSlashLiability::Root(offence_height)),
        None,
        true,
        true,
        Some(monetary_plan),
    )
}
/// Apply a slash in a disposable validation transaction without external observability effects.
#[cfg(test)]
pub(crate) fn apply_slash_to_validator_without_observability(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    slash_id: Hash,
    amount: &Quantity,
    now_ms: u64,
) -> Result<(), Error> {
    apply_slash_to_validator_inner(
        state_transaction,
        lane_id,
        validator,
        slash_id,
        amount,
        now_ms,
        None,
        None,
        false,
        false,
        None,
    )
}
/// Apply a finality-owned slash using a complete key slice from one indexed overlay.
pub(crate) fn apply_indexed_consensus_slash_to_validator(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    slash_id: Hash,
    amount: &Quantity,
    now_ms: u64,
    liability: ConsensusSlashLiability,
    share_keys: &[PublicLaneStakeShareKey],
) -> Result<(), Error> {
    apply_slash_to_validator_inner(
        state_transaction,
        lane_id,
        validator,
        slash_id,
        amount,
        now_ms,
        Some(liability),
        Some(share_keys),
        false,
        true,
        None,
    )
}
/// Validate a finality-owned slash using a complete key slice without external effects.
pub(crate) fn apply_indexed_slash_to_validator_without_observability(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    slash_id: Hash,
    amount: &Quantity,
    now_ms: u64,
    liability: ConsensusSlashLiability,
    share_keys: &[PublicLaneStakeShareKey],
) -> Result<(), Error> {
    apply_slash_to_validator_inner(
        state_transaction,
        lane_id,
        validator,
        slash_id,
        amount,
        now_ms,
        Some(liability),
        Some(share_keys),
        false,
        false,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
fn apply_slash_to_validator_inner(
    state_transaction: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    slash_id: Hash,
    amount: &Quantity,
    now_ms: u64,
    liability: Option<ConsensusSlashLiability>,
    indexed_share_keys: Option<&[PublicLaneStakeShareKey]>,
    record_execution_evidence: bool,
    record_operational_observability: bool,
    monetary_plan: Option<&PublicLaneMonetaryPlanV1>,
) -> Result<(), Error> {
    if !matches!(liability, Some(ConsensusSlashLiability::Lane { .. })) {
        ensure_canonical_staking_owner(state_transaction, lane_id, "apply_slash_to_validator")?;
    }
    let offence_height = liability.and_then(ConsensusSlashLiability::offence_height);
    let deactivation_height = scheduled_validator_deactivation_height(state_transaction, lane_id)
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    let dataspace_catalog = state_transaction.nexus.dataspace_catalog.clone();
    let staking_cfg = state_transaction.nexus.staking.clone();
    let validator_key = validator_storage_key(lane_id, validator);
    let validator_snapshot = state_transaction
        .world
        .public_lane_validators
        .get(&validator_key)
        .map(|record| {
            ensure_public_lane_validator_record_matches_key(&validator_key, record)?;
            Ok::<PublicLaneValidatorRecord, Error>(record.clone())
        })
        .transpose()?
        .ok_or_else(|| Error::InvariantViolation("validator not registered".into()))?;
    if let Some(liability) = liability
        && !liability
            .names_registration(&state_transaction.world, &validator_snapshot)
            .map_err(|error| retain_staking_attempt(state_transaction, error))?
    {
        return Err(Error::InvariantViolation(
            match liability {
                ConsensusSlashLiability::Root(_) => {
                    "consensus slash offence falls outside the validator tenure"
                }
                _ => "consensus slash differs from the original validator liability",
            }
            .into(),
        ));
    }
    let stake_account = validator_snapshot.stake_account.clone();
    let stake_ctx =
        retained_stake_context(&state_transaction.world, lane_id, validator, &stake_account)?;
    let slash_sink = parse_staking_account_literal(
        &state_transaction.world,
        &dataspace_catalog,
        &staking_cfg.slash_sink_account_id,
        "slash_sink_account_id",
        now_ms,
    )
    .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    let world = &state_transaction.world;
    let slash_sink_asset = AssetId::with_scope(
        stake_ctx.asset_definition.clone(),
        slash_sink,
        *stake_ctx.escrow_asset.scope(),
    );
    let spec = world
        .asset_definitions
        .get(&stake_ctx.asset_definition)
        .ok_or_else(|| Error::InvariantViolation("stake asset definition missing".into()))?
        .spec();
    assert_numeric_spec_with(amount.as_numeric(), spec)?;
    let slashed_status = PublicLaneValidatorStatus::Slashed(slash_id);
    let previous_status = validator_snapshot.status.clone();
    if indexed_share_keys.is_some_and(|keys| {
        keys.len()
            > usize::try_from(staking_cfg.max_stake_shares_per_validator.get())
                .expect("u32 stake-share cap fits usize on supported targets")
    }) {
        return Err(Error::InvariantViolation(
            "indexed public-lane stake-share slice exceeds configured capacity".into(),
        ));
    }
    let mut share_updates = validator_share_updates(world, lane_id, validator, indexed_share_keys)?;
    let slashable_exposure = slashable_exposure_from_shares(
        &validator_snapshot,
        share_updates.iter().map(|(key, share)| Ok((key, share))),
        offence_height,
    )?;
    let allowed = slash_within_limit(amount, &slashable_exposure, staking_cfg.max_slash_bps)?;
    if !allowed {
        return Err(Error::InvariantViolation(
            "slash exceeds configured maximum ratio".into(),
        ));
    }
    if slashable_exposure < amount.clone() {
        return Err(Error::InvariantViolation(
            "slash exceeds stake still held in protocol custody".into(),
        ));
    }
    if record_execution_evidence != monetary_plan.is_some() {
        return Err(Error::InvariantViolation(
            "transaction slashing requires its exact signed monetary plan".into(),
        ));
    }
    if let Some(plan) = monetary_plan {
        effects::verify_transfer_plan(
            state_transaction,
            plan,
            &stake_ctx.escrow_asset,
            &slash_sink_asset,
            amount,
            &PublicLaneMonetaryPreconditionV1::Slash(PublicLaneMonetarySlashV1 {
                activation_height: validator_snapshot.activation_height,
                slashable_exposure: slashable_exposure.clone(),
            }),
        )
        .map_err(|error| retain_staking_attempt(state_transaction, error))?;
    }
    let self_pending = pending_unbond_group_total(
        &share_updates,
        validator,
        &validator_snapshot.stake_account,
        true,
        offence_height,
    )?;
    let self_exposure = quantity_add(validator_snapshot.self_stake.clone(), self_pending)?;
    let self_slash = min_quantity(self_exposure, amount.clone());
    let self_bonded_slash = min_quantity(validator_snapshot.self_stake.clone(), self_slash.clone());
    let self_pending_slash = quantity_sub(self_slash.clone(), self_bonded_slash.clone())?;
    let delegated_slash = quantity_sub(amount.clone(), self_slash)?;
    let delegated_bonded = quantity_sub(
        validator_snapshot.total_stake.clone(),
        validator_snapshot.self_stake.clone(),
    )?;
    let delegated_bonded_slash = min_quantity(delegated_bonded, delegated_slash.clone());
    let delegated_pending_slash = quantity_sub(delegated_slash, delegated_bonded_slash.clone())?;
    let bonded_slash = quantity_add(self_bonded_slash.clone(), delegated_bonded_slash.clone())?;
    let pending_slash_amount =
        quantity_add(self_pending_slash.clone(), delegated_pending_slash.clone())?;
    let new_total_stake =
        quantity_sub(validator_snapshot.total_stake.clone(), bonded_slash.clone())?;
    let new_self_stake = quantity_sub(
        validator_snapshot.self_stake.clone(),
        self_bonded_slash.clone(),
    )?;
    let mut validator_update = validator_snapshot.clone();
    validator_update.total_stake = new_total_stake;
    validator_update.self_stake = new_self_stake;
    let obligated = validator_snapshot.lane_id == LaneId::SINGLE;
    schedule_validator_deactivation(&mut validator_update, deactivation_height, obligated)?;
    validator_update.status = slashed_status.clone();
    slash_bonded_share_group(
        &mut share_updates,
        validator,
        &validator_snapshot.stake_account,
        true,
        &self_bonded_slash,
    )?;
    slash_pending_unbond_group(
        &mut share_updates,
        validator,
        &validator_snapshot.stake_account,
        true,
        &self_pending_slash,
        offence_height,
    )?;
    slash_bonded_share_group(
        &mut share_updates,
        validator,
        &validator_snapshot.stake_account,
        false,
        &delegated_bonded_slash,
    )?;
    slash_pending_unbond_group(
        &mut share_updates,
        validator,
        &validator_snapshot.stake_account,
        false,
        &delegated_pending_slash,
        offence_height,
    )?;
    let movement = VerifiedStakingSlashDebit::new(
        lane_id,
        validator.clone(),
        slash_id,
        stake_ctx.escrow_asset.clone(),
        slash_sink_asset,
        amount.clone(),
        slashable_exposure,
    );
    // A consensus slash is a finality effect rather than a transaction
    // entrypoint. Its balance movement must not enter the transaction FASTPQ
    // transcript or process-global execution witness. Commit mode publishes
    // only the slash-specific status and telemetry below.
    if record_execution_evidence {
        crate::smartcontracts::isi::asset::isi::execute_verified_staking_slash_transfer(
            state_transaction,
            movement,
        )?;
    } else {
        crate::smartcontracts::isi::asset::isi::execute_verified_consensus_staking_slash_transfer(
            state_transaction,
            movement,
        )?;
    }
    let world = &mut state_transaction.world;
    world
        .public_lane_validators
        .insert(validator_key, validator_update);
    for (key, share) in share_updates {
        if !share.bonded.is_zero() || !share.pending_unbonds.is_empty() {
            world.public_lane_stake_shares.insert(key, share);
        } else {
            world.public_lane_stake_shares.remove(key);
        }
    }
    if record_operational_observability {
        state_transaction.stage_public_lane_slash_observability(
            lane_id,
            previous_status,
            slashed_status,
            bonded_slash,
            pending_slash_amount,
        );
    }
    Ok(())
}
#[derive(Debug)]
struct StakeEscrowContext {
    asset_definition: AssetDefinitionId,
    staker_asset: AssetId,
    escrow_asset: AssetId,
}
/// A withdrawal's exact retained source and recipient assets.
struct RetainedStakeContext {
    asset_definition: AssetDefinitionId,
    staker_asset: AssetId,
    escrow_asset: AssetId,
}

fn retained_stake_context(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    validator: &AccountId,
    staker: &AccountId,
) -> Result<RetainedStakeContext, Error> {
    let escrow_asset = retained_stake_custody_asset(world, lane_id, validator)?;
    crate::state::validate_xor_custody_shape(world, &escrow_asset)?;
    Ok(RetainedStakeContext {
        asset_definition: escrow_asset.definition().clone(),
        staker_asset: AssetId::with_scope(
            escrow_asset.definition().clone(),
            staker.clone(),
            *escrow_asset.scope(),
        ),
        escrow_asset,
    })
}

/// Check a matured withdrawal against retained custody, independently of alias drift.
pub(in crate::smartcontracts::isi) fn is_retained_staking_unbond_movement(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    staker: &AccountId,
    source_id: &AssetId,
    destination_id: &AssetId,
) -> Result<bool, Error> {
    let context = retained_stake_context(&state_transaction.world, lane_id, validator, staker)?;
    Ok(source_id == &context.escrow_asset && destination_id == &context.staker_asset)
}

/// Check a slash against its retained source and the governed slash receiver.
pub(in crate::smartcontracts::isi) fn is_retained_staking_slash_movement(
    state_transaction: &StateTransaction<'_, '_>,
    lane_id: LaneId,
    validator: &AccountId,
    source_id: &AssetId,
    destination_id: &AssetId,
) -> Result<bool, Attempt<Error>> {
    let pinned = retained_stake_custody_asset(&state_transaction.world, lane_id, validator)?;
    let slash_sink = parse_staking_account_literal(
        &state_transaction.world,
        &state_transaction.nexus.dataspace_catalog,
        &state_transaction.nexus.staking.slash_sink_account_id,
        "slash_sink_account_id",
        state_transaction.block_unix_timestamp_ms(),
    )?;
    Ok(source_id == &pinned
        && destination_id
            == &AssetId::with_scope(pinned.definition().clone(), slash_sink, *pinned.scope()))
}
fn stake_context(
    world: &impl WorldReadOnly,
    dataspace_catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    staking_cfg: &iroha_config::parameters::actual::NexusStaking,
    staker: &AccountId,
    now_ms: u64,
) -> Result<StakeEscrowContext, Attempt<Error>> {
    let asset_definition = resolve_configured_asset_definition(
        world,
        &staking_cfg.stake_asset_id,
        "nexus.staking.stake_asset_id",
        now_ms,
    )?;
    ensure_committed_xor_asset(world, &asset_definition)?;
    let escrow_account = parse_staking_account_literal(
        world,
        dataspace_catalog,
        &staking_cfg.stake_escrow_account_id,
        "stake_escrow_account_id",
        now_ms,
    )?;
    Ok(StakeEscrowContext {
        asset_definition: asset_definition.clone(),
        staker_asset: AssetId::new(asset_definition.clone(), staker.clone()),
        escrow_asset: AssetId::new(asset_definition.clone(), escrow_account),
    })
}
fn parse_staking_account_literal(
    world: &impl WorldReadOnly,
    dataspace_catalog: &iroha_data_model::nexus::DataSpaceCatalog,
    literal: &str,
    field: &'static str,
    now_ms: u64,
) -> Result<AccountId, Attempt<Error>> {
    if let Some(account) =
        crate::block::parse_account_literal_with_world(world, dataspace_catalog, literal, now_ms)
            .map_err(|error| {
                error
                    .into_attempt_error(|error| Error::InvariantViolation(error.to_string().into()))
            })?
    {
        return Ok(account);
    }
    let reason = match AccountId::parse_encoded(literal) {
        Ok(_) => "literal resolved to no matching account in world state".to_owned(),
        Err(err) => format!("decode failed: {err}"),
    };
    Err(Error::InvariantViolation(
        format!(
            "invalid nexus.staking.{field}; expected canonical I105 account id or on-chain alias ({reason})"
        )
        .into(),
    ).into())
}
fn resolve_configured_asset_definition(
    world: &impl WorldReadOnly,
    literal: &str,
    field: &'static str,
    now_ms: u64,
) -> Result<AssetDefinitionId, Error> {
    crate::block::parse_asset_definition_literal_with_world(world, literal, now_ms).ok_or_else(
        || {
            Error::InvariantViolation(
                format!(
                    "invalid {field}; expected canonical Base58 asset definition id or active asset alias"
                )
                .into(),
            )
        },
    )
}
/// Staking and rewards use the signed, immutable network currency identity.
fn ensure_committed_xor_asset(
    world: &impl WorldReadOnly,
    asset: &AssetDefinitionId,
) -> Result<(), Attempt<Error>> {
    crate::state::validate_network_xor_asset(world, asset)
}
fn assert_stake_amount_matches_spec(
    state_transaction: &mut StateTransaction<'_, '_>,
    asset_definition: &AssetDefinitionId,
    amount: &Quantity,
) -> Result<(), Error> {
    let spec = state_transaction
        .numeric_spec_for(asset_definition)
        .map_err(Error::from)?;
    assert_numeric_spec_with(amount.as_numeric(), spec)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::ValidBlock,
        query::store::LiveQueryStore,
        state::{State, StateTransaction, World},
    };
    use core::num::NonZeroU64;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::query::error::FindError;
    use iroha_data_model::{
        account::{Account, MultisigMember, MultisigPolicy},
        asset::{AssetDefinition, AssetDefinitionId},
        consensus::{ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
        domain::Domain,
        isi::error::InvalidParameterError,
        nexus::{
            AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, LaneCatalog, LaneConfig,
            LaneVisibility, PublicLaneMonetaryScopeV1,
        },
        parameter::{Parameter, system::SumeragiNposParameters},
        peer::Peer,
        prelude::*,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use iroha_test_samples::{ALICE_ID, gen_account_in};
    use nonzero_ext::nonzero;
    use std::time::Duration;
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("staking fixture key generation should succeed")
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("staking algorithm-specific fixture key generation should succeed")
    }
    fn checked_peer_id() -> iroha_model_base::peer::PeerId {
        iroha_model_base::peer::PeerId::from(checked_keypair().public_key().clone())
    }
    fn rebind_for_test(
        stx: &StateTransaction<'_, '_>,
        lane_id: LaneId,
        validator: &AccountId,
        peer_id: &PeerId,
        signing_key: &KeyPair,
    ) -> RebindPublicLaneValidatorPeer {
        let record = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("fixture validator binding");
        let payload = PublicLanePeerBindingAuthorization::new(
            *stx.network_id(),
            lane_id,
            validator.clone(),
            peer_id.clone(),
            record.activation_height,
            record.peer_id.clone(),
        );
        let signature = iroha_crypto::SignatureOf::try_new(signing_key.private_key(), &payload)
            .expect("fixture peer consent");
        RebindPublicLaneValidatorPeer::new(lane_id, validator.clone(), peer_id.clone(), signature)
    }
    include!("staking_monetary_fixture_tests.rs");
    include!("staking_core_tests.rs");
    include!("staking_monetary_tests.rs");
    include!("staking_borrowed_exposure_tests.rs");
    include!("staking_admission_tests.rs");
    include!("staking_reward_tests.rs");
    include!("staking_preparation_tests.rs");
    include!("staking_custody_tests.rs");
    include!("staking_index_demand_tests.rs");
    #[test]
    fn stake_context_accepts_i105_account_literals() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut stx, &asset_def_id);
        stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        stx.nexus.staking.slash_sink_account_id = escrow.to_string();
        let stake_ctx = stake_context(
            &stx.world,
            &stx.nexus.dataspace_catalog,
            &stx.nexus.staking,
            &validator,
            stx.block_unix_timestamp_ms(),
        )
        .expect("stake context should accept i105 literals");
        assert_eq!(
            stake_ctx.escrow_asset.account(),
            &escrow,
            "escrow account should resolve from literal"
        );
        assert_eq!(
            parse_staking_account_literal(
                &stx.world,
                &stx.nexus.dataspace_catalog,
                &stx.nexus.staking.slash_sink_account_id,
                "slash_sink_account_id",
                stx.block_unix_timestamp_ms()
            )
            .unwrap(),
            escrow,
            "slash sink account should resolve from literal"
        );
    }
    #[test]
    fn register_stores_validator_and_share() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(1),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(1),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(1), validator.clone()))
                .is_some(),
            "validator not stored before apply"
        );
        stx.apply();
        assert_eq!(
            block.as_ref().header().height().get(),
            1,
            "first block height must start at 1 for snapshot"
        );
        state_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let record = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(1), validator.clone()))
            .expect("validator record");
        assert_eq!(record.total_stake, Quantity::from(1_000_u64));
        assert_eq!(record.self_stake, Quantity::from(1_000_u64));
        let share = view
            .world
            .public_lane_stake_shares()
            .get(&(LaneId::new(1), validator.clone(), validator.clone()))
            .expect("share record");
        assert_eq!(share.bonded, Quantity::from(1_000_u64));
        let stake_asset = AssetId::new(asset_def_id.clone(), validator.clone());
        let escrow_asset = AssetId::new(asset_def_id, escrow.clone());
        let stake_balance = view
            .world
            .assets()
            .get(&stake_asset)
            .expect("validator stake balance");
        let escrow_balance = view
            .world
            .assets()
            .get(&escrow_asset)
            .expect("escrow balance");
        assert_eq!(stake_balance.as_ref(), &Quantity::from(9_000_u64));
        assert_eq!(escrow_balance.as_ref(), &Quantity::from(1_000_u64));
    }
    #[test]
    fn register_allows_genesis_bootstrap_authority() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(81),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(81),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("genesis authority may bootstrap validator registration");
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(81), validator))
                .is_some(),
            "genesis bootstrap registration must create a validator record"
        );
    }
    #[test]
    fn register_rejects_non_validator_authority() {
        let state = setup_state();
        let block = new_block_with_height(2);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(81),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(81),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-validator authority must not register validator stake");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("register_public_lane_validator rejected: authority must match validator account")
        ));
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(81), validator))
                .is_none(),
            "rejected registration must not create a validator record"
        );
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(asset_def_id, escrow))
                .is_none(),
            "rejected registration must not touch escrow"
        );
    }
    #[test]
    fn register_rejects_non_validator_stake_account() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(82),
                &delegator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(82),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: delegator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("registration must not pull initial self-stake from another account");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("register_public_lane_validator rejected: stake account must match validator account")
        ));
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(82), validator))
                .is_none(),
            "rejected registration must not create a validator record"
        );
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(asset_def_id.clone(), escrow))
                .is_none(),
            "rejected registration must not touch escrow"
        );
        let delegator_stake = stx
            .world
            .assets
            .get(&AssetId::new(asset_def_id, delegator))
            .expect("delegator stake balance remains present");
        assert_eq!(delegator_stake.as_ref(), &Quantity::from(10_000_u64));
    }
    #[test]
    fn register_rejects_without_live_consensus_key() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        seed_validator_consensus_key(&mut stx, &validator_peer, ConsensusKeyStatus::Disabled);
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(14),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(14),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            result.is_err(),
            "validator registration should be rejected without an active consensus key"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected registration must not touch escrow"
        );
    }
    #[test]
    fn register_rejects_when_consensus_key_pending_activation() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        let activation_height = stx.block_height().saturating_add(5);
        seed_validator_consensus_key_with_heights(
            &mut stx,
            &validator_peer,
            ConsensusKeyStatus::Pending,
            activation_height,
            None,
        );
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(22),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(22),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            matches!(&result, Err(Error::InvariantViolation(msg)) if msg.contains("not yet active")),
            "unexpected result: {result:?}"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected registration must not touch escrow"
        );
    }
    #[test]
    fn register_rejects_when_consensus_key_expired() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        let expiry_height = stx.block_height();
        seed_validator_consensus_key_with_heights(
            &mut stx,
            &validator_peer,
            ConsensusKeyStatus::Active,
            0,
            Some(expiry_height),
        );
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(23),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(23),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            matches!(&result, Err(Error::InvariantViolation(msg)) if msg.contains("expired")),
            "unexpected result: {result:?}"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected registration must not touch escrow"
        );
    }
    #[test]
    fn register_rejects_finite_consensus_key_for_open_ended_tenure() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let mut state_block = state.block(block_header_with_height(4));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = validator_peer_id(&validator);
        seed_consensus_key_for_role_with_heights(
            &mut stx,
            &validator_peer,
            ConsensusKeyRole::Committee,
            ConsensusKeyStatus::Active,
            1,
            Some(8),
        );

        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(24),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(24),
            peer_id: validator_peer,
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);

        assert!(
            matches!(&result, Err(Error::InvariantViolation(msg)) if msg.contains("unbounded committee consensus key")),
            "unexpected result: {result:?}"
        );
        assert!(
            stx.world
                .assets
                .get(&AssetId::new(asset_def_id, escrow))
                .is_none(),
            "rejected registration must not touch escrow"
        );
    }
    #[test]
    fn register_rejects_on_admin_managed_lane() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::new(7);
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(
                nonzero!(8_u32),
                vec![LaneConfig {
                    id: lane_id,
                    alias: "restricted".to_string(),
                    dataspace_id: DataSpaceId::new(7),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                }],
            )
            .expect("lane catalog"),
        );
        stx.nexus.staking.public_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
        stx.nexus.staking.restricted_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("admin-managed lanes must reject staking");
        assert!(matches!(
            result,
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg))
                if msg.contains("admin-managed")
        ));
        assert!(
            stx.world
                .public_lane_validators
                .iter()
                .all(|((lane, _), _)| lane != &lane_id)
        );
    }
    #[test]
    fn staking_rejects_future_created_autoscale_lane_before_creation_height() {
        let state = setup_state();
        let block = new_block_with_height(6);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let future_lane = LaneId::new(1);
        let mut autoscale_lane = LaneConfig {
            id: future_lane,
            alias: "elastic-lane-1".to_string(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        };
        autoscale_lane
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        autoscale_lane
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_owned(), "7".to_owned());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut autoscale_lane);
        stx.nexus.autoscale.enabled = true;
        stx.nexus.autoscale.min_lane_id = nonzero!(1_u32);
        stx.nexus.autoscale.max_lane_id_exclusive = nonzero!(2_u32);
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), autoscale_lane])
                .expect("future-created autoscale catalog"),
        );
        stx.nexus.staking.public_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                future_lane,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: future_lane,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("future-created autoscale lane must reject staking before creation height");
        assert!(matches!(
            err,
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg))
                if msg.contains("not active at block height 6")
        ));
        assert!(
            stx.world
                .public_lane_validators
                .iter()
                .all(|((lane, _), _)| lane != &future_lane),
            "rejected future-created autoscale lane must not create validator records"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected future-created autoscale lane must not touch escrow"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn mixed_mode_respects_lane_validator_modes() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height(1);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let stake_lane = LaneId::new(0);
        let admin_lane = LaneId::new(1);
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(
                nonzero!(2_u32),
                vec![
                    LaneConfig {
                        id: stake_lane,
                        alias: "public-stake".to_string(),
                        dataspace_id: DataSpaceId::UNIVERSAL,
                        visibility: LaneVisibility::Public,
                        ..LaneConfig::default()
                    },
                    LaneConfig {
                        id: admin_lane,
                        alias: "restricted-admin".to_string(),
                        dataspace_id: DataSpaceId::new(1),
                        visibility: LaneVisibility::Restricted,
                        ..LaneConfig::default()
                    },
                ],
            )
            .expect("lane catalog"),
        );
        stx.nexus.staking.public_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
        stx.nexus.staking.restricted_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
        let (validator, delegator, _, _) = prepare_accounts(&mut stx);
        let stake_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                stake_lane,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: stake_lane,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("stake-elected lane should accept staking");
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                admin_lane,
                &delegator,
                Quantity::from(1_000_u64),
            ),
            lane_id: admin_lane,
            peer_id: validator_peer_id(&delegator),
            validator: delegator.clone(),
            stake_account: delegator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect_err("admin-managed lane must reject staking");
        assert!(matches!(
            err,
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg))
                if msg.contains("admin-managed")
        ));
        complete_staking_committee(&mut stx, stake_lane);
        stx.apply();
        assert_eq!(
            block.as_ref().header().height().get(),
            1,
            "first block height must start at 1 for snapshot"
        );
        state_block.commit_empty_block_for_testing().unwrap();
        let block = new_block_with_height(2);
        let mut activation_block = state.block(block.as_ref().header());
        let mut activation_tx = activation_block.transaction_for_callback_testing();
        ActivatePublicLaneValidator {
            lane_id: stake_lane,
            validator: validator.clone(),
        }
        .execute(&validator, &mut activation_tx)
        .unwrap();
        activation_tx.apply();
        activation_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let roster = view
            .epoch_validator_peer_ids_for_testing(0)
            .expect("stake-elected roster should be present");
        assert_eq!(
            roster.len(),
            4,
            "stake-elected roster has an exact four-validator committee"
        );
        assert!(
            roster.contains(&stake_peer),
            "the original stake-elected validator remains selected"
        );
        assert!(
            !roster.contains(&validator_peer_id(&delegator)),
            "the admin-managed lane contributes no stake-elected validator"
        );
        assert!(
            view.world
                .public_lane_validators()
                .get(&(stake_lane, validator.clone()))
                .is_some(),
            "stake-elected lane should retain the registered validator"
        );
        assert!(
            view.world
                .public_lane_validators()
                .get(&(admin_lane, delegator.clone()))
                .is_none(),
            "admin-managed lane must remain free of staking records"
        );
    }
    #[test]
    fn admin_multisig_register_peer_allowed_in_permissioned_mode() {
        let mut state = setup_state();
        let mut pipeline = state.view().pipeline().clone();
        pipeline.signature_batch_max_bls = 4;
        state.set_pipeline(pipeline);
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(
                nonzero!(2_u32),
                vec![LaneConfig {
                    id: LaneId::new(1),
                    alias: "restricted".to_string(),
                    dataspace_id: DataSpaceId::new(1),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                }],
            )
            .expect("lane catalog"),
        );
        stx.nexus.staking.restricted_validator_mode =
            iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
        let domain_id: DomainId = DomainId::try_new("council", "universal").expect("domain id");
        let selector = crate::sns::selector_for_domain(&domain_id).expect("selector");
        let address =
            iroha_data_model::account::AccountAddress::from_account_id(&ALICE_ID).expect("address");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            ALICE_ID.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        stx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register domain");
        let member_a = checked_keypair_with_algorithm(Algorithm::Ed25519);
        let member_b = checked_keypair_with_algorithm(Algorithm::Ed25519);
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(member_a.public_key().clone(), 1).expect("member_a"),
                MultisigMember::new(member_b.public_key().clone(), 1).expect("member_b"),
            ],
        )
        .expect("policy");
        let admin_id = AccountId::new_multisig(policy);
        Register::account(Account::new(admin_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register multisig admin");
        let bls = checked_keypair_with_algorithm(Algorithm::BlsNormal);
        let peer_id = iroha_model_base::peer::PeerId::new(bls.public_key().clone());
        let pop = iroha_crypto::bls_normal_pop_prove(bls.private_key()).expect("pop");
        iroha_data_model::isi::register::RegisterPeerWithPop::new(peer_id.clone(), pop)
            .execute(&admin_id, &mut stx)
            .expect("admin multisig should register peer");
        assert!(stx.world.peers().iter().any(|peer| peer == &peer_id));
        Unregister::<Peer>::peer(peer_id.clone())
            .execute(&admin_id, &mut stx)
            .expect("admin multisig should unregister peer");
        assert!(stx.world.peers().iter().all(|peer| peer != &peer_id));
    }
    #[test]
    fn register_rejects_global_peer_without_prepared_epoch_transition() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        let foreign_peer = checked_peer_id();
        stx.commit_topology.get_mut().clear();
        stx.commit_topology.get_mut().push(foreign_peer);
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::SINGLE,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::SINGLE,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            result.is_err(),
            "global committee changes require prepared epoch keys"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected global admission must not escrow stake"
        );
        assert!(
            !stx.commit_topology
                .iter()
                .any(|peer| peer == &validator_peer),
            "candidate admission must not grant current voting rights"
        );
    }
    #[test]
    fn participant_lane_accepts_committee_peer_outside_global_topology() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let peer = validator_peer_id(&validator);
        let height = stx.block_height();
        clear_consensus_keys_for_peer(&mut stx, &peer);
        seed_consensus_key_for_role_with_heights(
            &mut stx,
            &peer,
            ConsensusKeyRole::Committee,
            ConsensusKeyStatus::Active,
            height,
            None,
        );
        stx.commit_topology.get_mut().clear();
        stx.commit_topology.get_mut().push(checked_peer_id());
        let lane_id = LaneId::new(42);

        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: peer.clone(),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("participant committee peer need not join the global commit topology");

        assert!(
            stx.world
                .public_lane_validators
                .get(&(lane_id, validator))
                .is_some()
        );
        assert!(!stx.commit_topology.iter().any(|voter| voter == &peer));
    }
    #[test]
    fn lane_registration_rejects_consensus_key_from_the_other_lane_role() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, _, _) = prepare_accounts(&mut stx);

        let participant_peer = validator_peer_id(&validator);
        let height = stx.block_height();
        clear_consensus_keys_for_peer(&mut stx, &participant_peer);
        seed_consensus_key_for_role_with_heights(
            &mut stx,
            &participant_peer,
            ConsensusKeyRole::Validator,
            ConsensusKeyStatus::Active,
            height,
            None,
        );
        let participant_error = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(43),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(43),
            peer_id: participant_peer.clone(),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("Validator-role key cannot authorize participant-lane validation");
        assert!(matches!(
            participant_error,
            Error::InvariantViolation(message)
                if message.contains("required consensus key")
                    || message.contains("committee consensus key")
        ));
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(43), validator.clone()))
                .is_none()
        );

        let global_peer = validator_peer_id(&delegator);
        clear_consensus_keys_for_peer(&mut stx, &global_peer);
        seed_consensus_key_for_role_with_heights(
            &mut stx,
            &global_peer,
            ConsensusKeyRole::Committee,
            ConsensusKeyStatus::Active,
            height,
            None,
        );
        stx.commit_topology.get_mut().push(global_peer.clone());
        let global_error = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::SINGLE,
                &delegator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::SINGLE,
            peer_id: global_peer,
            validator: delegator.clone(),
            stake_account: delegator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect_err("Committee-role key cannot authorize global validation");
        assert!(matches!(
            global_error,
            Error::InvariantViolation(message)
                if message.contains("required consensus key")
                    || message.contains("validator consensus key")
        ));
    }
    #[test]
    fn register_accepts_distinct_validator_peer_binding() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let foreign_peer = checked_peer_id();
        let _ = stx.world.peers.push(foreign_peer.clone());
        seed_validator_consensus_key(&mut stx, &foreign_peer, ConsensusKeyStatus::Active);
        stx.commit_topology.get_mut().clear();
        stx.commit_topology.get_mut().push(foreign_peer.clone());
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(43),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(43),
            peer_id: foreign_peer.clone(),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("registration should accept a distinct peer binding");
        let record = stx
            .world
            .public_lane_validators()
            .get(&(LaneId::new(43), validator.clone()))
            .expect("validator record should be stored");
        assert_eq!(record.peer_id, foreign_peer);
        assert_ne!(record.peer_id, validator_peer_id(&validator));
    }
    #[test]
    fn register_rejects_peer_binding_retained_by_exited_custody() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, replacement, _, _) = prepare_accounts(&mut stx);
        let shared_peer = validator_peer_id(&validator);
        stx.commit_topology.get_mut().clear();
        stx.commit_topology.get_mut().push(shared_peer.clone());
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(44),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(44),
            peer_id: shared_peer.clone(),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("first validator should bind the shared peer");
        stx.world
            .public_lane_validators
            .get_mut(&(LaneId::new(44), validator.clone()))
            .expect("first validator record")
            .status = PublicLaneValidatorStatus::Exited;
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(44),
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(44),
            peer_id: shared_peer,
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx)
        .expect_err("exited custody must continue reserving its peer binding");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("validator peer is already retained for lane")
        ));
    }
    #[test]
    fn register_ignores_mismatched_public_lane_validator_rows_for_capacity_and_peer_binding() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, stale_validator, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(144);
        let shared_peer = validator_peer_id(&validator);
        stx.nexus.staking.max_validators = nonzero!(1u32);
        stx.world.public_lane_validators.insert(
            (lane_id, stale_validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::new(145),
                validator: stale_validator.clone(),
                peer_id: shared_peer.clone(),
                stake_account: stale_validator,
                total_stake: Quantity::from(10_000_u64),
                self_stake: Quantity::from(10_000_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: shared_peer,
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("mismatched stale row must not consume capacity or peer binding");
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("valid validator should be registered");
        assert_eq!(record.lane_id, lane_id);
        assert!(matches!(
            record.status,
            PublicLaneValidatorStatus::PendingActivation(_)
        ));
    }
    #[test]
    fn rebind_updates_pending_validator_peer_and_preserves_record_fields() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height(4);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        seed_participant_consensus_key(&mut stx, &validator_peer_id(&validator));
        let replacement_key = checked_keypair();
        let replacement_peer = PeerId::new(replacement_key.public_key().clone());
        let _ = stx.world.peers.push(replacement_peer.clone());
        seed_participant_consensus_key(&mut stx, &replacement_peer);
        let lane_id = LaneId::new(45);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let original = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("validator record")
            .clone();
        rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &replacement_peer,
            &replacement_key,
        )
        .execute(&validator, &mut stx)
        .expect("rebind should succeed before validator activation");
        rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &replacement_peer,
            &replacement_key,
        )
        .execute(&validator, &mut stx)
        .expect("same-peer rebind with exact consent remains idempotent");
        let updated = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator.clone()))
            .expect("updated validator record");
        assert_eq!(updated.peer_id, replacement_peer);
        assert_eq!(updated.validator, original.validator);
        assert_eq!(updated.stake_account, original.stake_account);
        assert_eq!(updated.total_stake, original.total_stake);
        assert_eq!(updated.self_stake, original.self_stake);
        assert_eq!(updated.status, original.status);
        assert_eq!(updated.activation_height, original.activation_height);
        assert_eq!(updated.deactivation_height, original.deactivation_height);
    }
    #[test]
    fn rebind_is_allowed_before_but_not_during_activation_roster_freeze() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let mut registration_block = state.block(block_header_with_height(4));
        let mut registration_stx = registration_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut registration_stx);
        let first_key = checked_keypair();
        let second_key = checked_keypair();
        let first_replacement = PeerId::new(first_key.public_key().clone());
        let second_replacement = PeerId::new(second_key.public_key().clone());
        for peer in [&first_replacement, &second_replacement] {
            let _ = registration_stx.world.peers.push(peer.clone());
            seed_validator_consensus_key(&mut registration_stx, peer, ConsensusKeyStatus::Active);
        }
        let lane_id = LaneId::new(145);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &registration_stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut registration_stx)
        .expect("register validator for height ten");
        registration_stx.apply();
        registration_block
            .commit_world_overlay_for_testing()
            .unwrap();

        let mut safe_block = state.block(block_header_with_height(5));
        let mut safe_stx = safe_block.transaction_for_callback_testing();
        rebind_for_test(
            &safe_stx,
            lane_id,
            &validator,
            &first_replacement,
            &first_key,
        )
        .execute(&validator, &mut safe_stx)
        .expect("height five is before the height-ten roster freeze");
        safe_stx.apply();
        safe_block.commit_world_overlay_for_testing().unwrap();

        let mut frozen_block = state.block(block_header_with_height(9));
        let mut frozen_stx = frozen_block.transaction_for_callback_testing();
        let err = rebind_for_test(
            &frozen_stx,
            lane_id,
            &validator,
            &second_replacement,
            &second_key,
        )
        .execute(&validator, &mut frozen_stx)
        .expect_err("height nine has already frozen the height-ten roster");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("already frozen")
        ));
        let record = frozen_stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("validator record remains present");
        assert_eq!(record.peer_id, first_replacement);
    }
    #[test]
    fn rebind_same_peer_rejects_invalid_consent_before_idempotent_return() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(46);
        let peer_id = validator_peer_id(&validator);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: peer_id.clone(),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        stx.commit_topology.get_mut().clear();
        if let Some(index) = stx.world.peers.iter().position(|peer| peer == &peer_id) {
            let _ = stx.world.peers.remove(index);
        }
        let err = rebind_for_test(&stx, lane_id, &validator, &peer_id, &checked_keypair())
            .execute(&validator, &mut stx)
            .expect_err("same-peer rebind still requires replacement-peer consent");
        assert!(err.to_string().contains("replacement peer signature"));
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("validator record remains present");
        assert_eq!(record.peer_id, peer_id);
    }
    #[test]
    fn rebind_rejects_duplicate_peer_binding_on_same_lane() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height(4);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, replacement, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(47);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register primary validator");
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx)
        .expect("register replacement validator");
        let err = rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &validator_peer_id(&replacement),
            &checked_keypair(),
        )
        .execute(&validator, &mut stx)
        .expect_err("duplicate binding should be rejected");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("validator peer is already registered for lane")
        ));
    }
    #[test]
    fn rebind_ignores_mismatched_public_lane_validator_rows_for_peer_binding() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height(4);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, stale_validator, _, _) = prepare_accounts(&mut stx);
        seed_participant_consensus_key(&mut stx, &validator_peer_id(&validator));
        let lane_id = LaneId::new(147);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register primary validator");
        let replacement_key = checked_keypair();
        let replacement_peer = PeerId::new(replacement_key.public_key().clone());
        let _ = stx.world.peers.push(replacement_peer.clone());
        seed_participant_consensus_key(&mut stx, &replacement_peer);
        stx.world.public_lane_validators.insert(
            (lane_id, stale_validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::new(148),
                validator: stale_validator.clone(),
                peer_id: replacement_peer.clone(),
                stake_account: stale_validator,
                total_stake: Quantity::from(10_000_u64),
                self_stake: Quantity::from(10_000_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &replacement_peer,
            &replacement_key,
        )
        .execute(&validator, &mut stx)
        .expect("mismatched stale row must not reserve the replacement peer");
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("validator record remains present");
        assert_eq!(record.peer_id, replacement_peer);
    }
    #[test]
    fn rebind_rejects_mismatched_public_lane_validator_row() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(152);
        let replacement_peer = checked_peer_id();
        let _ = stx.world.peers.push(replacement_peer.clone());
        seed_validator_consensus_key(&mut stx, &replacement_peer, ConsensusKeyStatus::Active);
        stx.commit_topology.get_mut().push(replacement_peer.clone());
        insert_validator_record_for_key(
            &mut stx,
            lane_id,
            LaneId::new(153),
            &validator,
            PublicLaneValidatorStatus::Active,
            Quantity::from(1_000_u64),
        );
        let err = rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &replacement_peer,
            &checked_keypair(),
        )
        .execute(&validator, &mut stx)
        .expect_err("mismatched validator row must reject peer rebinding");
        assert!(
            matches!(err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key"))
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert_eq!(record.lane_id, LaneId::new(153));
        assert_eq!(record.peer_id, validator_peer_id(&record.validator));
    }
    #[test]
    fn rebind_requires_validator_authority() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        seed_participant_consensus_key(&mut stx, &validator_peer_id(&validator));
        let replacement_peer = checked_peer_id();
        let _ = stx.world.peers.push(replacement_peer.clone());
        seed_participant_consensus_key(&mut stx, &replacement_peer);
        let lane_id = LaneId::new(48);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let err = rebind_for_test(
            &stx,
            lane_id,
            &validator,
            &replacement_peer,
            &checked_keypair(),
        )
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-validator authority should be rejected");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("authority must match validator account")
        ));
    }
    #[test]
    fn rebind_rejects_disallowed_validator_statuses() {
        let statuses = [
            PublicLaneValidatorStatus::Active,
            PublicLaneValidatorStatus::Exiting(5),
            PublicLaneValidatorStatus::Exited,
            PublicLaneValidatorStatus::Slashed(Hash::new("slash-rebind")),
        ];
        for (index, status) in statuses.into_iter().enumerate() {
            let state = setup_state();
            let block = new_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction_for_callback_testing();
            let (validator, _, _, _) = prepare_accounts(&mut stx);
            seed_participant_consensus_key(&mut stx, &validator_peer_id(&validator));
            let replacement_peer = checked_peer_id();
            let _ = stx.world.peers.push(replacement_peer.clone());
            seed_participant_consensus_key(&mut stx, &replacement_peer);
            let lane_id = LaneId::new(49 + u32::try_from(index).expect("index fits in u32"));
            RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &stx,
                    lane_id,
                    &validator,
                    Quantity::from(1_000_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&validator),
                validator: validator.clone(),
                stake_account: validator.clone(),
                initial_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
            }
            .execute(&validator, &mut stx)
            .expect("register validator");
            stx.world
                .public_lane_validators
                .get_mut(&(lane_id, validator.clone()))
                .expect("validator record")
                .status = status;
            let err = rebind_for_test(
                &stx,
                lane_id,
                &validator,
                &replacement_peer,
                &checked_keypair(),
            )
            .execute(&validator, &mut stx)
            .expect_err("disallowed status should reject peer rebinding");
            assert!(matches!(
                err,
                Error::InvariantViolation(msg) if msg.contains("only before validator activation")
            ));
        }
    }
    #[test]
    fn register_rejects_when_peer_unregistered() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        // Drop the validator peer from the WSV to emulate an unregistered topology entry.
        if let Some(pos) = stx
            .world
            .peers
            .iter()
            .position(|peer| peer == &validator_peer)
        {
            stx.world.peers.remove(pos);
        }
        stx.commit_topology
            .get_mut()
            .retain(|peer| peer != &validator_peer);
        let result = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(99),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(99),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            matches!(&result, Err(Error::InvariantViolation(msg)) if msg.contains("peer must be registered")),
            "unregistered peer should be rejected: {result:?}"
        );
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            stx.world.assets.get(&escrow_asset).is_none(),
            "rejected registration must not move stake into escrow"
        );
    }
    #[test]
    fn finalize_pending_activations_ignores_mismatched_public_lane_validator_rows() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let mut state_block = state.block(block_header_with_height(7));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, mismatched_validator, _, _) = prepare_accounts(&mut stx);
        let valid_lane = LaneId::new(149);
        let mismatched_key_lane = LaneId::new(150);
        let mismatched_record_lane = LaneId::new(151);
        stx.world.public_lane_validators.insert(
            (valid_lane, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: valid_lane,
                validator: validator.clone(),
                peer_id: validator_peer_id(&validator),
                stake_account: validator.clone(),
                total_stake: Quantity::from(1_000_u64),
                self_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::PendingActivation(7),
                activation_height: 7,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        stx.world.public_lane_validators.insert(
            (mismatched_key_lane, mismatched_validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: mismatched_record_lane,
                validator: mismatched_validator.clone(),
                peer_id: validator_peer_id(&mismatched_validator),
                stake_account: mismatched_validator.clone(),
                total_stake: Quantity::from(9_000_u64),
                self_stake: Quantity::from(9_000_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::PendingActivation(7),
                activation_height: 7,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        finalize_pending_activations(&mut stx).expect("activation pass should complete");
        let valid = stx
            .world
            .public_lane_validators()
            .get(&(valid_lane, validator))
            .expect("valid pending validator remains present");
        assert!(matches!(valid.status, PublicLaneValidatorStatus::Active));
        assert_eq!(valid.activation_height, 7);
        assert_eq!(valid.deactivation_height, None);
        let mismatched = stx
            .world
            .public_lane_validators()
            .get(&(mismatched_key_lane, mismatched_validator))
            .expect("mismatched pending validator remains present");
        assert!(
            matches!(
                mismatched.status,
                PublicLaneValidatorStatus::PendingActivation(7)
            ),
            "mismatched key/record rows must not auto-promote to Active"
        );
        assert_eq!(mismatched.activation_height, 7);
        assert_eq!(mismatched.deactivation_height, None);
    }
    #[test]
    fn finalize_pending_activations_skips_non_owner_same_dataspace_rows() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);

        let mut state_block = state.block(block_header_with_height(7));
        let mut stx = state_block.transaction_for_callback_testing();
        let (owner_validator, sibling_validator, _, _) = prepare_accounts(&mut stx);
        let owner_lane = LaneId::SINGLE;
        let sibling_lane = LaneId::new(1);
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(
                nonzero!(2_u32),
                vec![
                    LaneConfig::default(),
                    LaneConfig {
                        id: sibling_lane,
                        alias: "pending-shared-staking-sibling".to_owned(),
                        dataspace_id: DataSpaceId::UNIVERSAL,
                        visibility: LaneVisibility::Public,
                        ..LaneConfig::default()
                    },
                ],
            )
            .expect("shared-dataspace lane catalog"),
        );
        insert_validator_record_for_key(
            &mut stx,
            owner_lane,
            owner_lane,
            &owner_validator,
            PublicLaneValidatorStatus::PendingActivation(7),
            Quantity::from(1_000_u64),
        );
        insert_validator_record_for_key(
            &mut stx,
            sibling_lane,
            sibling_lane,
            &sibling_validator,
            PublicLaneValidatorStatus::PendingActivation(7),
            Quantity::from(1_000_u64),
        );

        finalize_pending_activations(&mut stx).expect("activation pass should complete");

        let owner = stx
            .world
            .public_lane_validators()
            .get(&(owner_lane, owner_validator))
            .expect("canonical owner validator remains present");
        assert!(matches!(owner.status, PublicLaneValidatorStatus::Active));
        let sibling = stx
            .world
            .public_lane_validators()
            .get(&(sibling_lane, sibling_validator))
            .expect("non-owner sibling validator remains present");
        assert!(matches!(
            sibling.status,
            PublicLaneValidatorStatus::PendingActivation(7)
        ));
        assert_eq!(sibling.activation_height, 7);
        assert_eq!(sibling.deactivation_height, None);
    }

    #[test]
    fn activate_public_lane_validator_rejects_mismatched_public_lane_validator_row() {
        let state = setup_state();
        let mut state_block = state.block(block_header_with_height(1));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(154);
        insert_validator_record_for_key(
            &mut stx,
            lane_id,
            LaneId::new(155),
            &validator,
            PublicLaneValidatorStatus::PendingActivation(0),
            Quantity::from(1_000_u64),
        );
        let err = ActivatePublicLaneValidator {
            lane_id,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .expect_err("mismatched validator row must reject explicit activation");
        assert!(
            matches!(err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key"))
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert!(matches!(
            record.status,
            PublicLaneValidatorStatus::PendingActivation(0)
        ));
        assert_eq!(record.activation_height, 0);
        assert_eq!(record.deactivation_height, None);
    }
    #[test]
    fn finalize_released_exits_ignores_mismatched_public_lane_validator_rows() {
        let state = setup_state();
        let block = new_block_with_height_and_time(2, 1_000);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, mismatched_validator, _, _) = prepare_accounts(&mut stx);
        let valid_lane = LaneId::new(156);
        let mismatched_key_lane = LaneId::new(157);
        insert_validator_record_for_key(
            &mut stx,
            valid_lane,
            valid_lane,
            &validator,
            PublicLaneValidatorStatus::Exiting(999),
            Quantity::from(1_000_u64),
        );
        insert_validator_record_for_key(
            &mut stx,
            mismatched_key_lane,
            LaneId::new(158),
            &mismatched_validator,
            PublicLaneValidatorStatus::Exiting(999),
            Quantity::from(1_000_u64),
        );
        stx.world
            .public_lane_validators
            .get_mut(&(valid_lane, validator.clone()))
            .expect("valid exit fixture")
            .deactivation_height = Some(2);
        stx.world
            .public_lane_validators
            .get_mut(&(mismatched_key_lane, mismatched_validator.clone()))
            .expect("mismatched exit fixture")
            .deactivation_height = Some(2);
        finalize_released_exits(&mut stx).unwrap();
        let valid = stx
            .world
            .public_lane_validators()
            .get(&(valid_lane, validator))
            .expect("valid exiting validator remains present");
        assert!(matches!(valid.status, PublicLaneValidatorStatus::Exited));
        let mismatched = stx
            .world
            .public_lane_validators()
            .get(&(mismatched_key_lane, mismatched_validator))
            .expect("mismatched exiting validator remains present");
        assert!(matches!(
            mismatched.status,
            PublicLaneValidatorStatus::Exiting(999)
        ));
    }
    #[test]
    fn pending_activation_advances_on_epoch_boundary() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        // Start in epoch 1 to avoid genesis, which allows immediate activation.
        let mut state_block = state.block(block_header_with_height(4));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(1),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(1),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let pending = stx
            .world
            .public_lane_validators
            .get(&(LaneId::new(1), validator.clone()))
            .expect("pending record");
        assert!(matches!(
            pending.status,
            PublicLaneValidatorStatus::PendingActivation(10)
        ));
        assert_eq!(pending.activation_height, 10);
        assert_eq!(pending.deactivation_height, None);
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let mut activate_block = state.block(block_header_with_height(5));
        let mut activate_stx = activate_block.transaction_for_callback_testing();
        let err = ActivatePublicLaneValidator {
            lane_id: LaneId::new(1),
            validator: validator.clone(),
        }
        .execute(&validator, &mut activate_stx)
        .expect_err("activation should wait for the next epoch");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("activation height not reached")
        ));
        activate_stx.apply();
        activate_block.commit_world_overlay_for_testing().unwrap();
        let mut intermediate_block = state.block(block_header_with_height(6));
        let intermediate_stx = intermediate_block.transaction_for_callback_testing();
        intermediate_stx.apply();
        intermediate_block
            .commit_world_overlay_for_testing()
            .unwrap();
        let mut activate_block = state.block(block_header_with_height(10));
        let mut activate_stx = activate_block.transaction_for_callback_testing();
        ActivatePublicLaneValidator {
            lane_id: LaneId::new(1),
            validator: validator.clone(),
        }
        .execute(&validator, &mut activate_stx)
        .expect("activate once pending epoch reached");
        let record = activate_stx
            .world
            .public_lane_validators
            .get(&(LaneId::new(1), validator.clone()))
            .cloned()
            .expect("record present");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
        assert_eq!(record.activation_height, 10);
        assert_eq!(record.deactivation_height, None);
        activate_stx.apply();
        activate_block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let stored = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(1), validator.clone()))
            .expect("stored record");
        assert_eq!(stored.activation_height, 10);
        assert_eq!(stored.deactivation_height, None);
        let escrow_asset = AssetId::new(asset_def_id, escrow.clone());
        assert!(
            view.world.assets().get(&escrow_asset).is_some(),
            "staking assets must remain bonded"
        );
    }
    #[test]
    fn boundary_block_registration_targets_the_following_election() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let mut state_block = state.block(block_header_with_height(6));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);

        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(1),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(1),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator in the epoch-ending block");

        let record = stx
            .world
            .public_lane_validators
            .get(&(LaneId::new(1), validator))
            .expect("pending validator record");
        assert_eq!(
            record.status,
            PublicLaneValidatorStatus::PendingActivation(13),
            "height ten's roster is already frozen before height-six transactions execute"
        );
        assert_eq!(record.activation_height, 13);
        assert_eq!(record.deactivation_height, None);
    }
    #[test]
    fn genesis_activation_allows_same_block() {
        let state = setup_state();
        let mut state_block = state.block(block_header_with_height(1));
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _delegator, _escrow, _asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::SINGLE,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::SINGLE,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator in genesis");
        let pending = stx
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator.clone()))
            .expect("pending record");
        assert!(matches!(
            pending.status,
            PublicLaneValidatorStatus::PendingActivation(1)
        ));
        assert_eq!(pending.activation_height, 1);
        assert_eq!(pending.deactivation_height, None);
        ActivatePublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .expect("activate validator in genesis");
        let record = stx
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator))
            .cloned()
            .expect("record present");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
        assert_eq!(record.activation_height, 1);
        assert_eq!(record.deactivation_height, None);
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
    }
    #[test]
    fn pending_activation_auto_promotes_at_epoch_boundary() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        // Start in epoch 1 to avoid genesis, which allows immediate activation.
        let block1 = new_block_with_height(4);
        let mut state_block = state.block(block1.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(1),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(1),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let block2 = new_block_with_height(5);
        let mut state_block2 = state.block(block2.as_ref().header());
        let stx2 = state_block2.transaction_for_callback_testing();
        stx2.apply();
        state_block2.commit_world_overlay_for_testing().unwrap();
        let block3 = new_block_with_height(6);
        let view = state.view();
        let pending_record = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(1), validator.clone()))
            .cloned()
            .expect("record present after scheduling");
        assert!(
            matches!(
                pending_record.status,
                PublicLaneValidatorStatus::PendingActivation(10)
            ),
            "validator should remain pending during the full key-preparation epoch"
        );
        drop(view);
        let mut state_block3 = state.block(block3.as_ref().header());
        let stx3 = state_block3.transaction_for_callback_testing();
        stx3.apply();
        state_block3.commit_world_overlay_for_testing().unwrap();
        for height in 7..=9 {
            let mut intermediate_block = state.block(block_header_with_height(height));
            intermediate_block
                .transaction_for_callback_testing()
                .apply();
            intermediate_block
                .commit_world_overlay_for_testing()
                .unwrap();
        }
        let block4 = new_block_with_height(10);
        let state_block4 = state.block(block4.as_ref().header());
        let record = state_block4
            .world
            .public_lane_validators
            .get(&(LaneId::new(1), validator.clone()))
            .cloned()
            .expect("record present after scheduling");
        assert!(
            matches!(record.status, PublicLaneValidatorStatus::Active),
            "validator should auto-activate after a full preparation epoch"
        );
        assert_eq!(record.activation_height, 10);
        assert_eq!(record.deactivation_height, None);
        state_block4.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let stored = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(1), validator.clone()))
            .expect("stored record");
        assert!(
            matches!(stored.status, PublicLaneValidatorStatus::Active),
            "persistent record should remain active"
        );
        assert_eq!(stored.activation_height, 10);
        assert_eq!(stored.deactivation_height, None);
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        assert!(
            view.world.assets().get(&escrow_asset).is_some(),
            "staking assets must remain bonded"
        );
    }
    #[test]
    fn pending_activation_rejects_regressing_activation_height() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block1 = new_block_with_height(1);
        let mut state_block = state.block(block1.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(11),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(11),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let key = (LaneId::new(11), validator.clone());
        stx.world
            .public_lane_validators
            .get_mut(&key)
            .expect("pending record")
            .activation_height = 99;
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        // Insert an intermediate block to keep heights monotonic before the activation block.
        let block2 = new_block_with_height(2);
        let mut mid_block = state.block(block2.as_ref().header());
        let mid_tx = mid_block.transaction_for_callback_testing();
        mid_tx.apply();
        mid_block.commit_world_overlay_for_testing().unwrap();
        let block3 = new_block_with_height(3);
        let mut activation_block = state.block(block3.as_ref().header());
        let mut stx3 = activation_block.transaction_for_callback_testing();
        let err = finalize_pending_activations(&mut stx3)
            .expect_err("regressing activation height must be rejected");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("activation height is not canonical")
        ));
    }
    #[test]
    fn unregister_peer_retains_validator_capacity_while_custody_exists() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (validator, _, _escrow, asset_def_id) = prepare_accounts(&mut stx);
        seed_participant_consensus_key(&mut stx, &validator_peer_id(&validator));
        let (replacement, _kp) = gen_account_in("nexus");
        Register::account(Account::new(replacement.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        register_peer_for_account(&mut stx, &replacement);
        seed_participant_consensus_key(&mut stx, &validator_peer_id(&replacement));
        Mint::asset_quantity(
            10_000u32,
            AssetId::new(asset_def_id.clone(), replacement.clone()),
        )
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(7),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(7),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("first validator should register");
        let second_attempt = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(7),
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(7),
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx);
        assert!(
            matches!(&second_attempt, Err(Error::InvariantViolation(msg)) if msg.contains("maximum validator capacity")),
            "capacity guard should reject second validator: {second_attempt:?}"
        );
        let validator_peer = validator_peer_id(&validator);
        stx.commit_topology
            .get_mut()
            .retain(|peer| peer != &validator_peer);
        let unregister_error = Unregister::<Peer>::peer(validator_peer)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("retained validator tenure must reject peer unregistration");
        assert!(
            matches!(&unregister_error, Error::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("wait for its deactivation height")),
            "unexpected unregistration rejection: {unregister_error}"
        );
        let error = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(7),
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(7),
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx)
        .expect_err("retained custody must continue to consume validator capacity");
        assert!(matches!(
            error,
            Error::InvariantViolation(message)
                if message.contains("maximum validator capacity")
        ));
        let former = stx
            .world
            .public_lane_validators
            .get(&(LaneId::new(7), validator.clone()))
            .expect("former validator record");
        assert!(
            matches!(former.status, PublicLaneValidatorStatus::Active),
            "rejected peer removal must leave the validator active"
        );
        let remaining_shares: Vec<_> = stx
            .world
            .public_lane_stake_shares
            .iter()
            .filter(|((lane, val, _), _)| *lane == LaneId::new(7) && val == &validator)
            .collect();
        assert_eq!(
            remaining_shares.len(),
            1,
            "peer removal must preserve slashable stake custody"
        );
    }
    #[test]
    fn exited_validator_retains_capacity_while_custody_exists() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(1, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (validator, _delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(7);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: stx.block_unix_timestamp_ms().saturating_add(5),
        }
        .execute(&validator, &mut stx)
        .expect("mark exiting validator");
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let block2 = new_block_with_height_and_time(7, 10);
        let mut state_block = state.block(block2.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (replacement, _kp) = gen_account_in("nexus");
        Register::account(Account::new(replacement.clone()))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        register_peer_for_account(&mut stx, &replacement);
        stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut stx, &asset_def_id);
        stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        stx.nexus.staking.slash_sink_account_id = escrow.to_string();
        finalize_validator_lifecycle(&mut stx).expect("finalize lifecycle before replacement");
        Mint::asset_quantity(
            10_000u32,
            AssetId::new(asset_def_id.clone(), replacement.clone()),
        )
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        let error = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx)
        .expect_err("released exit with retained custody must consume capacity");
        assert!(matches!(
            error,
            Error::InvariantViolation(message)
                if message.contains("maximum validator capacity")
        ));
        let stale_record = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()));
        assert!(
            matches!(stale_record, Some(record) if matches!(record.status, PublicLaneValidatorStatus::Exited)),
            "exited validator custody record must remain after replacement admission"
        );
        let remaining_shares: Vec<_> = stx
            .world
            .public_lane_stake_shares
            .iter()
            .filter(|((lane, val, _), _)| *lane == lane_id && val == &validator)
            .collect();
        assert_eq!(
            remaining_shares.len(),
            1,
            "exit finalization must preserve slashable stake custody"
        );
    }
    #[test]
    fn final_unbond_prunes_exited_record_and_frees_validator_capacity() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(1, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (validator, _, escrow, asset_definition) = prepare_accounts(&mut stx);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        let (replacement, _) = gen_account_in("nexus");
        Register::account(Account::new(replacement.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register replacement account");
        register_peer_for_account(&mut stx, &replacement);
        Mint::asset_quantity(
            10_000_u32,
            AssetId::new(asset_definition.clone(), replacement.clone()),
        )
        .execute(&ALICE_ID, &mut stx)
        .expect("fund replacement stake account");
        let lane_id = LaneId::new(13);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register original validator");
        let request_id = Hash::new("final-exit-unbond");
        SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: Quantity::from(500_u64),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("schedule complete self-unbond");
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("exit zero-bonded validator while pending custody remains");
        assert!(
            stx.world
                .public_lane_validators
                .get(&(lane_id, validator.clone()))
                .is_some(),
            "pending unbond custody must retain the exited validator record"
        );
        stx.apply();
        state_block
            .commit_world_overlay_for_testing()
            .expect("commit exited validator custody");

        let block = new_block_with_height_and_time(8, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        stx.nexus.staking.stake_asset_id = asset_definition.to_string();
        set_fixture_xor_identity(&mut stx, &asset_definition);
        stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        stx.nexus.staking.slash_sink_account_id = escrow.to_string();
        FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(&stx, lane_id, &validator, &validator, request_id),
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
        }
        .execute(&validator, &mut stx)
        .expect("final liability height releases complete custody");
        assert!(
            stx.world
                .public_lane_validators
                .get(&(lane_id, validator))
                .is_none(),
            "zero-custody exited records must be pruned at the deactivation boundary"
        );
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &replacement,
                Quantity::from(500_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut stx)
        .expect("released terminal custody must free validator capacity");
    }
    #[test]
    fn slashed_validator_cannot_reregister_until_custody_is_released() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(1, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (validator, _delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(12);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let block2 = new_block_with_height_and_time(2, 5);
        let mut state_block = state.block(block2.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        stx.nexus.staking.slash_sink_account_id = escrow.to_string();
        SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &stx,
                lane_id,
                &validator,
                1,
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: 1,
            slash_id: Hash::new("slash-reenter"),
            amount: Quantity::from(100_u64),
            reason_code: "violation".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("slash validator");
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("exit slashed validator");
        finalize_validator_lifecycle(&mut stx).expect("finalize exit lifecycle");
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let exited = state
            .view()
            .world
            .public_lane_validators()
            .get(&(lane_id, validator.clone()))
            .cloned()
            .expect("exited record retained");
        assert!(
            matches!(exited.status, PublicLaneValidatorStatus::Exiting(_)),
            "validator must keep its tenure until the frozen election boundary"
        );
        let block3 = new_block_with_height_and_time(7, 10);
        let mut state_block = state.block(block3.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        stx.nexus.staking.slash_sink_account_id = escrow.to_string();
        finalize_validator_lifecycle(&mut stx).expect("finish the certified election interval");
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("exited validator must not overwrite retained slashable custody");
        assert!(
            matches!(&err, Error::InvariantViolation(message) if message.contains("retains slashable stake custody")),
            "re-registration after deactivation must still retain slashable custody: {err:?}"
        );
        let record = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("exited record remains");
        assert!(
            matches!(record.status, PublicLaneValidatorStatus::Exited),
            "rejected re-registration must retain the exited lifecycle state"
        );
        let shares: Vec<_> = stx
            .world
            .public_lane_stake_shares
            .iter()
            .filter(|((lane, val, _), _)| *lane == lane_id && val == &validator)
            .collect();
        assert_eq!(
            shares.len(),
            1,
            "rejected re-registration must preserve the original stake share"
        );
        assert_eq!(shares[0].1.bonded, Quantity::from(900_u64));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn exiting_and_exited_validator_block_capacity_while_custody_exists() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(1, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let (validator, _delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(10);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let release_at_ms = stx.block_unix_timestamp_ms().saturating_add(50);
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms,
        }
        .execute(&validator, &mut stx)
        .expect("mark validator exiting");
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        // Prepare a replacement validator with bonded stake and a registered peer.
        let block2 = new_block_with_height_and_time(2, 10);
        let mut state_block = state.block(block2.as_ref().header());
        let replacement = {
            let mut stx = state_block.transaction_for_callback_testing();
            let (replacement, _kp) = gen_account_in("nexus");
            Register::account(Account::new(replacement.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let replacement_peer = register_peer_for_account(&mut stx, &replacement);
            stx.commit_topology.get_mut().push(replacement_peer.clone());
            stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
            set_fixture_xor_identity(&mut stx, &asset_def_id);
            stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
            stx.nexus.staking.slash_sink_account_id = escrow.to_string();
            Mint::asset_quantity(
                10_000u32,
                AssetId::new(asset_def_id.clone(), replacement.clone()),
            )
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            stx.apply();
            replacement
        };
        state_block.commit_empty_block_for_testing().unwrap();
        // Capacity is still consumed while the original validator is exiting.
        let block3 = new_block_with_height_and_time(3, 10);
        let mut state_block = state.block(block3.as_ref().header());
        {
            let mut stx = state_block.transaction_for_callback_testing();
            stx.nexus.staking.max_validators = nonzero!(1u32);
            stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
            set_fixture_xor_identity(&mut stx, &asset_def_id);
            stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
            stx.nexus.staking.slash_sink_account_id = escrow.to_string();
            let err = RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &stx,
                    lane_id,
                    &replacement,
                    Quantity::from(1_000_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&replacement),
                validator: replacement.clone(),
                stake_account: replacement.clone(),
                initial_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
            }
            .execute(&replacement, &mut stx)
            .expect_err("capacity should remain consumed until exit finalizes");
            assert!(matches!(
                err,
                Error::InvariantViolation(msg) if msg.contains("maximum validator capacity")
            ));
            drop(stx);
        }
        state_block.commit_empty_block_for_testing().unwrap();
        // The release timestamp only finalizes lifecycle status; bonded custody
        // continues to consume the bounded validator slot.
        for height in 4..7 {
            let filler = new_block_with_height_and_time(height, height * 5);
            state
                .block(filler.as_ref().header())
                .commit_empty_block_for_testing()
                .expect("commit each intermediate height before the exit boundary");
        }
        let block4 = new_block_with_height_and_time(7, 60);
        let mut state_block = state.block(block4.as_ref().header());
        {
            let mut stx = state_block.transaction_for_callback_testing();
            stx.nexus.staking.max_validators = nonzero!(1u32);
            stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
            set_fixture_xor_identity(&mut stx, &asset_def_id);
            stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
            stx.nexus.staking.slash_sink_account_id = escrow.to_string();
            finalize_validator_lifecycle(&mut stx)
                .expect("finalize the elapsed exit before replacement admission");
            let error = RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &stx,
                    lane_id,
                    &replacement,
                    Quantity::from(1_000_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&replacement),
                validator: replacement.clone(),
                stake_account: replacement.clone(),
                initial_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
            }
            .execute(&replacement, &mut stx)
            .expect_err("exited custody must retain validator capacity");
            assert!(matches!(
                error,
                Error::InvariantViolation(message)
                    if message.contains("maximum validator capacity")
            ));
            stx.apply();
        }
        state_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let roster = view
            .world
            .public_lane_validators()
            .iter()
            .filter(|((lane, _), _)| *lane == lane_id)
            .map(|((_, id), record)| (id.clone(), record.status.clone()))
            .collect::<Vec<_>>();
        assert!(
            roster.iter().all(|(id, _)| id != &replacement),
            "replacement must remain excluded while exited custody is retained"
        );
        assert!(
            roster.iter().any(|(id, status)| id == &validator
                && matches!(status, PublicLaneValidatorStatus::Exited)),
            "exiting validator should finalize to Exited"
        );
    }
    #[test]
    fn stake_snapshot_ignores_disabled_peer() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::SINGLE;
        let (validator, _, _escrow, _asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        complete_staking_committee(&mut stx, lane_id);
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        {
            let view = state.view();
            let roster = view
                .epoch_validator_peer_ids_for_testing(0)
                .expect("active validator should appear before key disable");
            assert!(
                roster.contains(&validator_peer),
                "active validator should be present before disable"
            );
        }
        let block = new_block_with_height(2);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        seed_validator_consensus_key(&mut stx, &validator_peer, ConsensusKeyStatus::Disabled);
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let roster = view
            .epoch_validator_peer_ids_for_testing(0)
            .unwrap_or_default();
        assert!(
            !roster.contains(&validator_peer),
            "disabled consensus key should remove validator from snapshot"
        );
    }
    #[test]
    fn stake_snapshot_widens_missing_validator_from_topology() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::SINGLE;
        let (validator, _, _, _asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        complete_staking_committee(&mut stx, lane_id);
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        {
            let view = state.view();
            let roster = view
                .epoch_validator_peer_ids_for_testing(0)
                .expect("validator should appear before topology change");
            assert!(
                roster.contains(&validator_peer),
                "validator should be present before topology change"
            );
        }
        let block = new_block_with_height(2);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let foreign_peer = checked_peer_id();
        let _ = stx.world.peers.push(foreign_peer.clone());
        stx.commit_topology.get_mut().clear();
        stx.commit_topology.get_mut().push(foreign_peer);
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let roster = view
            .epoch_validator_peer_ids_for_testing(0)
            .unwrap_or_default();
        assert!(
            roster.contains(&validator_peer),
            "active validator should remain in the snapshot even if commit topology omits it"
        );
    }
    #[test]
    fn stake_snapshot_drops_validator_when_peer_removed() {
        let state = setup_state();
        let block = new_block_with_height(1);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::SINGLE;
        let (validator, _, _, _asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        complete_staking_committee(&mut stx, lane_id);
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let validator_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator is single-signatory")
                .clone(),
        );
        {
            let view = state.view();
            let roster = view
                .epoch_validator_peer_ids_for_testing(0)
                .expect("validator should appear before peer removal");
            assert!(
                roster.contains(&validator_peer),
                "validator should be present before peer removal"
            );
        }
        let block = new_block_with_height(2);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        if let Some(pos) = stx
            .world
            .peers
            .iter()
            .position(|peer| peer == &validator_peer)
        {
            stx.world.peers.remove(pos);
        }
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        let view = state.view();
        let roster = view
            .epoch_validator_peer_ids_for_testing(0)
            .unwrap_or_default();
        assert!(
            !roster.contains(&validator_peer),
            "validator should be dropped when its peer is removed from WSV"
        );
        let record = view
            .world
            .public_lane_validators()
            .get(&(lane_id, validator.clone()))
            .expect("validator record persists");
        assert!(
            matches!(
                record.status,
                PublicLaneValidatorStatus::Active | PublicLaneValidatorStatus::PendingActivation(_)
            ),
            "peer removal gating should not mutate validator status"
        );
    }
    #[test]
    fn bond_and_unbond_updates_totals() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(7),
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id: LaneId::new(7),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                LaneId::new(7),
                &validator,
                &delegator,
                Quantity::from(250_u64),
            ),
            lane_id: LaneId::new(7),
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .unwrap();
        let release_at_ms = stx.block_unix_timestamp_ms();
        SchedulePublicLaneUnbond {
            lane_id: LaneId::new(7),
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("req"),
            amount: Quantity::from(100_u64),
            release_at_ms,
        }
        .execute(&delegator, &mut stx)
        .unwrap();
        let pending = &stx
            .world
            .public_lane_stake_shares
            .get(&(LaneId::new(7), validator.clone(), delegator.clone()))
            .expect("scheduled delegator unbond")
            .pending_unbonds[&Hash::new("req")];
        assert_eq!(pending.slashable_through_height, 6);
        assert_eq!(pending.liability_release_height, 8);
        assert!(
            stx.world
                .public_lane_validators
                .get(&(LaneId::new(7), validator.clone()))
                .is_some(),
            "validator not stored before apply"
        );
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let early_block = new_block_with_height_and_time(2, release_at_ms);
        let mut early_state_block = state.block(early_block.as_ref().header());
        let mut early_tx = early_state_block.transaction_for_callback_testing();
        early_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut early_tx, &asset_def_id);
        early_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        early_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        let error = FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(
                &early_tx,
                LaneId::new(7),
                &validator,
                &delegator,
                Hash::new("req"),
            ),
            lane_id: LaneId::new(7),
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("req"),
        }
        .execute(&delegator, &mut early_tx)
        .expect_err("stake must remain in custody throughout the evidence liability window");
        assert!(
            matches!(&error, Error::InvariantViolation(message) if message.contains("remains slashable")),
            "unexpected early-finalization error: {error:?}"
        );
        drop(early_tx);
        drop(early_state_block);
        let finalize_block = new_block_with_height_and_time(8, release_at_ms);
        let mut finalize_state_block = state.block(finalize_block.as_ref().header());
        let mut finalize_tx = finalize_state_block.transaction_for_callback_testing();
        finalize_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut finalize_tx, &asset_def_id);
        finalize_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        finalize_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        // Native lane obligations retain the same escrow after this unbond's global
        // tenure window has ended. Refusal must preserve the exact financial position.
        {
            use iroha_data_model::sumeragi_lanes::{
                SumeragiLaneCustody, SumeragiLaneSignerCustody, SumeragiLaneStakeBinding,
            };
            let validator_key = (LaneId::new(7), validator.clone());
            let share_key = (LaneId::new(7), validator.clone(), delegator.clone());
            let before_share = finalize_tx
                .world
                .public_lane_stake_shares
                .get(&share_key)
                .unwrap()
                .clone();
            let before_custody = finalize_tx
                .world
                .public_lane_stake_custody
                .get(&validator_key)
                .unwrap()
                .clone();
            let original = finalize_tx
                .world
                .public_lane_validators
                .get(&validator_key)
                .unwrap();
            let binding =
                SumeragiLaneStakeBinding::from_record(original, &before_custody.0).unwrap();
            let creation = original.activation_height.max(1);
            for retired_at in [None, Some(7)] {
                finalize_tx.world.sumeragi_lanes.get_mut().custody = vec![SumeragiLaneCustody {
                    lane: LaneId::new(17),
                    incarnation: [17; 32],
                    instance: [18; 32],
                    created_at: creation,
                    merged: iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier::default(),
                    signer_count: 1,
                    signers: vec![SumeragiLaneSignerCustody { signer: 0, binding }]
                        .try_into()
                        .unwrap(),
                    evidence_horizon: 1,
                    slashing_delay: 1,
                    retired_at,
                }];
                let error = FinalizePublicLaneUnbond {
                    monetary_plan: fixture_unbond_plan(
                        &finalize_tx,
                        LaneId::new(7),
                        &validator,
                        &delegator,
                        Hash::new("req"),
                    ),
                    lane_id: LaneId::new(7),
                    validator: validator.clone(),
                    staker: delegator.clone(),
                    request_id: Hash::new("req"),
                }
                .execute(&delegator, &mut finalize_tx)
                .expect_err("original lane liability must retain custody");
                assert!(
                    matches!(error, Error::InvariantViolation(ref message) if message.contains("committee obligations"))
                );
                assert_eq!(
                    finalize_tx.world.public_lane_stake_shares.get(&share_key),
                    Some(&before_share)
                );
                assert_eq!(
                    finalize_tx
                        .world
                        .public_lane_stake_custody
                        .get(&validator_key),
                    Some(&before_custody)
                );
            }
            // Restore the original global-only fixture and retain its exact height-eight
            // withdrawal boundary and all balance assertions below.
            finalize_tx.world.sumeragi_lanes.get_mut().custody.clear();
        }
        FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(
                &finalize_tx,
                LaneId::new(7),
                &validator,
                &delegator,
                Hash::new("req"),
            ),
            lane_id: LaneId::new(7),
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("req"),
        }
        .execute(&delegator, &mut finalize_tx)
        .expect("unbond becomes releasable after its complete evidence liability window");
        finalize_tx.apply();
        finalize_state_block
            .commit_world_overlay_for_testing()
            .unwrap();
        let view = state.view();
        let record = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(7), validator.clone()))
            .unwrap();
        assert_eq!(record.total_stake, Quantity::from(650_u64));
        let share = view
            .world
            .public_lane_stake_shares()
            .get(&(LaneId::new(7), validator.clone(), delegator.clone()))
            .unwrap();
        assert_eq!(share.bonded, Quantity::from(150_u64));
        assert!(share.pending_unbonds.is_empty());
        let escrow_asset = AssetId::new(asset_def_id.clone(), escrow.clone());
        let validator_stake = AssetId::new(asset_def_id.clone(), validator.clone());
        let delegator_stake = AssetId::new(asset_def_id, delegator.clone());
        let escrow_balance = view
            .world
            .assets()
            .get(&escrow_asset)
            .expect("escrow balance after unbond");
        assert_eq!(escrow_balance.as_ref(), &Quantity::from(650_u64));
        let validator_balance = view
            .world
            .assets()
            .get(&validator_stake)
            .expect("validator free stake");
        let delegator_balance = view
            .world
            .assets()
            .get(&delegator_stake)
            .expect("delegator free stake");
        assert_eq!(validator_balance.as_ref(), &Quantity::from(9_500_u64));
        assert_eq!(delegator_balance.as_ref(), &Quantity::from(9_850_u64));
    }
    #[test]
    fn boundary_block_unbond_covers_the_successor_frozen_epoch() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(3, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        let lane_id = LaneId::new(174);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register boundary-block validator");
        let request_id = Hash::new("boundary-frozen-epoch-unbond");
        SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: Quantity::from(100_u64),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("schedule boundary-block unbond");

        let pending = &stx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane_id, &validator, &validator))
            .expect("boundary-block stake share")
            .pending_unbonds[&request_id];
        assert_eq!(pending.slashable_through_height, 9);
        assert_eq!(pending.liability_release_height, 11);
        assert!(pending_unbond_is_slashable_at(pending, Some(9)));
        assert!(!pending_unbond_is_slashable_at(pending, Some(10)));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bond_schedule_and_finalize_require_staker_authority() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        let lane_id = LaneId::new(83);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let err = BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(250_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-staker authority must not bond delegator funds");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("bond_public_lane_stake rejected: authority must match staker account")
        ));
        assert!(
            stx.world
                .public_lane_stake_shares
                .get(&(lane_id, validator.clone(), delegator.clone()))
                .is_none(),
            "rejected bond must not create delegator stake"
        );
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(250_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect("delegator can bond own funds");
        let release_at_ms = stx.block_unix_timestamp_ms();
        let err = SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("authority-unbond"),
            amount: Quantity::from(100_u64),
            release_at_ms,
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-staker authority must not schedule delegator unbond");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("schedule_public_lane_unbond rejected: authority must match staker account")
        ));
        let share = stx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator.clone(), delegator.clone()))
            .expect("delegator share remains present");
        assert_eq!(share.bonded, Quantity::from(250_u64));
        assert!(share.pending_unbonds.is_empty());
        SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("authority-unbond"),
            amount: Quantity::from(100_u64),
            release_at_ms,
        }
        .execute(&delegator, &mut stx)
        .expect("delegator can schedule own unbond");
        let err = FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Hash::new("authority-unbond"),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("authority-unbond"),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-staker authority must not finalize delegator unbond");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("finalize_public_lane_unbond rejected: authority must match staker account")
        ));
        let share = stx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator.clone(), delegator.clone()))
            .expect("delegator share remains present after rejected finalize");
        assert!(
            share
                .pending_unbonds
                .contains_key(&Hash::new("authority-unbond")),
            "rejected finalize must leave pending unbond intact"
        );
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let finalize_block = new_block_with_height_and_time(8, release_at_ms);
        let mut finalize_state_block = state.block(finalize_block.as_ref().header());
        let mut finalize_tx = finalize_state_block.transaction_for_callback_testing();
        finalize_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut finalize_tx, &asset_def_id);
        finalize_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        finalize_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        FinalizePublicLaneUnbond {
            monetary_plan: fixture_unbond_plan(
                &finalize_tx,
                lane_id,
                &validator,
                &delegator,
                Hash::new("authority-unbond"),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("authority-unbond"),
        }
        .execute(&delegator, &mut finalize_tx)
        .expect("delegator can finalize own unbond after the liability window");
        let share = finalize_tx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator.clone(), delegator.clone()))
            .expect("delegator share remains after finalize");
        assert_eq!(share.bonded, Quantity::from(150_u64));
        assert!(share.pending_unbonds.is_empty());
        let escrow_balance = finalize_tx
            .world
            .assets
            .get(&AssetId::new(asset_def_id.clone(), escrow))
            .expect("escrow balance after authorized finalize");
        assert_eq!(escrow_balance.as_ref(), &Quantity::from(650_u64));
        let delegator_balance = finalize_tx
            .world
            .assets
            .get(&AssetId::new(asset_def_id, delegator))
            .expect("delegator balance after authorized finalize");
        assert_eq!(delegator_balance.as_ref(), &Quantity::from(9_850_u64));
        finalize_tx.apply();
        finalize_state_block
            .commit_world_overlay_for_testing()
            .unwrap();
    }
    #[test]
    fn register_requires_peer() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        stx.world.peers.clear();
        let res = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(42),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(42),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(res.is_err(), "expected register to fail when peer missing");
    }
    #[test]
    fn register_rejects_non_owner_same_dataspace_lane_before_stake_moves() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();

        let (validator, _, escrow, asset_definition) = prepare_accounts(&mut stx);
        let owner_lane = LaneId::SINGLE;
        let sibling_lane = LaneId::new(1);
        set_transaction_lane_catalog(
            &mut stx,
            LaneCatalog::new(
                nonzero!(2_u32),
                vec![
                    LaneConfig::default(),
                    LaneConfig {
                        id: sibling_lane,
                        alias: "shared-staking-sibling".to_owned(),
                        dataspace_id: DataSpaceId::UNIVERSAL,
                        visibility: LaneVisibility::Public,
                        ..LaneConfig::default()
                    },
                ],
            )
            .expect("two public lanes may share the universal dataspace"),
        );
        assert_eq!(stx.staking_authority_lane(sibling_lane), Some(owner_lane));

        let validator_asset = AssetId::new(asset_definition.clone(), validator.clone());
        let escrow_asset = AssetId::new(asset_definition, escrow);
        let validator_balance_before = stx
            .world
            .assets
            .get(&validator_asset)
            .expect("validator stake balance")
            .as_ref()
            .clone();
        let escrow_balance_before = stx
            .world
            .assets
            .get(&escrow_asset)
            .map(|asset| asset.as_ref().clone());

        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                sibling_lane,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: sibling_lane,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("a non-owner sibling must not create a second stake projection");

        assert!(matches!(
            err,
            Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                if message.contains("staking owner is lane")
        ));
        assert_eq!(
            stx.world
                .assets
                .get(&validator_asset)
                .expect("validator stake balance after rejection")
                .as_ref(),
            &validator_balance_before
        );
        assert_eq!(
            stx.world
                .assets
                .get(&escrow_asset)
                .map(|asset| asset.as_ref().clone()),
            escrow_balance_before
        );
        assert!(
            stx.world
                .public_lane_validators
                .get(&(sibling_lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .public_lane_stake_shares
                .get(&(sibling_lane, validator.clone(), validator))
                .is_none()
        );
    }

    #[test]
    fn activate_transitions_pending_to_active() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        // Register matching peer so validator admission passes.
        let peer_id =
            iroha_model_base::peer::PeerId::from(validator.expect_single_signatory().clone());
        let _ = stx.world.peers.push(peer_id);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(2),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(2),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id: LaneId::new(2),
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let record = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(2), validator.clone()))
            .unwrap();
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
    }
    #[test]
    fn exit_preserves_custody_and_blocks_reregister() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let peer_id =
            iroha_model_base::peer::PeerId::from(validator.expect_single_signatory().clone());
        let _ = stx.world.peers.push(peer_id);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(3),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(3),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let now_ms = stx.block_unix_timestamp_ms();
        ExitPublicLaneValidator {
            lane_id: LaneId::new(3),
            validator: validator.clone(),
            release_at_ms: now_ms,
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(3),
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id: LaneId::new(3),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("exit alone must not discard slashable custody");
        assert!(
            matches!(&err, Error::InvariantViolation(message) if message.contains("already registered")),
            "re-registration before the retained election boundary must reject: {err:?}"
        );
        let record = stx
            .world
            .public_lane_validators
            .get(&(LaneId::new(3), validator.clone()))
            .expect("exited validator record remains");
        assert!(matches!(
            record.status,
            PublicLaneValidatorStatus::Exiting(_)
        ));
        let share = stx
            .world
            .public_lane_stake_shares
            .get(&(LaneId::new(3), validator.clone(), validator))
            .expect("bonded custody remains");
        assert_eq!(share.bonded, Quantity::from(1_000_u64));
    }
    #[test]
    fn exit_rejects_non_validator_authority() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(84);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let err = ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("non-validator authority must not exit another validator");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg)
                if msg.contains("exit_public_lane_validator rejected: authority must match validator account")
        ));
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("validator record remains present");
        assert!(
            matches!(
                record.status,
                PublicLaneValidatorStatus::PendingActivation(_)
            ),
            "rejected exit must not mutate validator lifecycle state"
        );
    }
    #[test]
    fn exit_public_lane_validator_rejects_mismatched_public_lane_validator_row() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(163);
        insert_validator_record_for_key(
            &mut stx,
            lane_id,
            LaneId::new(164),
            &validator,
            PublicLaneValidatorStatus::Active,
            Quantity::from(1_000_u64),
        );
        let err = ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect_err("mismatched validator row must reject exit");
        assert!(
            matches!(err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key"))
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
    }
    #[test]
    fn slashed_validator_exit_does_not_bypass_retained_custody() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::new(34);
        let (validator, _, _, _asset_def_id) = prepare_accounts(&mut stx);
        let peer_id =
            iroha_model_base::peer::PeerId::from(validator.expect_single_signatory().clone());
        let _ = stx.world.peers.push(peer_id);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &stx,
                lane_id,
                &validator,
                stx.block_height(),
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash-reason"),
            amount: Quantity::from(100_u64),
            reason_code: "evidence".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("slash succeeds");
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(250_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("slashed validator should remain registered until exited");
        assert!(matches!(
            err,
            Error::InvariantViolation(msg) if msg.contains("already registered")
        ));
        let now_ms = stx.block_unix_timestamp_ms();
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms: now_ms,
        }
        .execute(&validator, &mut stx)
        .expect("exit slashed validator");
        let err = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(250_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect_err("exit must not erase retained slashable custody");
        assert!(
            matches!(&err, Error::InvariantViolation(message) if message.contains("already registered")),
            "re-registration before the retained election boundary must reject: {err:?}"
        );
        let record = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("validator record");
        assert!(
            matches!(record.status, PublicLaneValidatorStatus::Exiting(_)),
            "rejected re-registration must preserve the exited record"
        );
        let share = stx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator.clone(), validator))
            .expect("slashed bonded custody remains");
        assert_eq!(share.bonded, Quantity::from(900_u64));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn slashed_exit_with_release_timer_retains_capacity_while_custody_exists() {
        let state = setup_state();
        let block = new_block_with_height_and_time(1, 1_000);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_validators = nonzero!(1u32);
        let lane_id = LaneId::new(35);
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &stx,
                lane_id,
                &validator,
                stx.block_height(),
                Quantity::from(200_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash-release-gate"),
            amount: Quantity::from(200_u64),
            reason_code: "evidence".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        let release_at_ms = stx.block_unix_timestamp_ms().saturating_add(5_000);
        ExitPublicLaneValidator {
            lane_id,
            validator: validator.clone(),
            release_at_ms,
        }
        .execute(&validator, &mut stx)
        .unwrap();
        stx.apply();
        state_block.commit_empty_block_for_testing().unwrap();
        // Prepare replacement validator in a dedicated setup block.
        let setup_block = new_block_with_height_and_time(2, release_at_ms.saturating_sub(2_000));
        let mut setup_state_block = state.block(setup_block.as_ref().header());
        let mut setup_tx = setup_state_block.transaction_for_callback_testing();
        setup_tx.nexus.staking.max_validators = nonzero!(1u32);
        setup_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut setup_tx, &asset_def_id);
        setup_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        setup_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        let (replacement, _replacement_kp) = gen_account_in("nexus");
        Register::account(Account::new(replacement.clone()))
            .execute(&ALICE_ID, &mut setup_tx)
            .unwrap();
        let replacement_peer = register_peer_for_account(&mut setup_tx, &replacement);
        setup_tx
            .commit_topology
            .get_mut()
            .push(replacement_peer.clone());
        Mint::asset_quantity(
            10_000u32,
            AssetId::new(asset_def_id.clone(), replacement.clone()),
        )
        .execute(&ALICE_ID, &mut setup_tx)
        .unwrap();
        setup_tx.apply();
        setup_state_block.commit_empty_block_for_testing().unwrap();
        let prerelease_block = new_block_with_height_and_time(3, release_at_ms.saturating_sub(1));
        let mut prerelease_state_block = state.block(prerelease_block.as_ref().header());
        {
            let mut prerelease_tx = prerelease_state_block.transaction_for_callback_testing();
            prerelease_tx.nexus.staking.max_validators = nonzero!(1u32);
            prerelease_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
            set_fixture_xor_identity(&mut prerelease_tx, &asset_def_id);
            prerelease_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
            prerelease_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
            let err = RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &prerelease_tx,
                    lane_id,
                    &replacement,
                    Quantity::from(1_000_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&replacement),
                validator: replacement.clone(),
                stake_account: replacement.clone(),
                initial_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
            }
            .execute(&replacement, &mut prerelease_tx)
            .expect_err("capacity should remain full until release time");
            assert!(
                matches!(
                    err,
                    Error::InvariantViolation(ref msg) if msg.contains("maximum validator capacity")
                ),
                "unexpected prerelease error: {err:?}"
            );
            prerelease_tx.apply();
        }
        prerelease_state_block
            .commit_empty_block_for_testing()
            .unwrap();
        let post_block = new_block_with_height_and_time(4, release_at_ms.saturating_add(1));
        let mut post_state_block = state.block(post_block.as_ref().header());
        let mut post_tx = post_state_block.transaction_for_callback_testing();
        post_tx.nexus.staking.max_validators = nonzero!(1u32);
        post_tx.nexus.staking.stake_asset_id = asset_def_id.to_string();
        set_fixture_xor_identity(&mut post_tx, &asset_def_id);
        post_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        post_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        if !post_tx.commit_topology.get().contains(&replacement_peer) {
            post_tx
                .commit_topology
                .get_mut()
                .push(replacement_peer.clone());
        }
        let error = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &post_tx,
                lane_id,
                &replacement,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&replacement),
            validator: replacement.clone(),
            stake_account: replacement.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&replacement, &mut post_tx)
        .expect_err("release time must not free capacity while slashable custody remains");
        assert!(matches!(
            error,
            Error::InvariantViolation(message)
                if message.contains("maximum validator capacity")
        ));
        let previous = post_tx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("slashed validator record still present");
        assert!(
            matches!(previous.status, PublicLaneValidatorStatus::Exiting(_)),
            "the release timer alone must not end the validator's E+2 tenure"
        );
        assert!(
            post_tx.world.public_lane_stake_shares.iter().any(
                |((lane, retained_validator, _), _)| {
                    *lane == lane_id && retained_validator == &validator
                }
            ),
            "slashed exit must retain custody until its stake is explicitly unbonded"
        );
    }
    #[test]
    fn unregister_peer_rejects_active_validator_tenure() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let peer_id =
            iroha_model_base::peer::PeerId::from(validator.expect_single_signatory().clone());
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(31),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(31),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id: LaneId::new(31),
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        stx.commit_topology
            .get_mut()
            .retain(|peer| peer != &peer_id);
        use iroha_data_model::isi::register::Unregister;
        let error = Unregister::<Peer>::peer(peer_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("active validator tenure must reject peer unregistration");
        assert!(
            matches!(&error, Error::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("wait for its deactivation height")),
            "unexpected unregistration rejection: {error}"
        );
        assert!(stx.world.peers().iter().any(|peer| peer == &peer_id));
        let record = stx
            .world
            .public_lane_validators()
            .get(&(LaneId::new(31), validator.clone()))
            .expect("validator record after rejected peer removal");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
    }
    #[test]
    fn unregister_peer_preserves_stake_shares() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let lane_id = LaneId::new(32);
        let (validator, delegator, _, _) = prepare_accounts(&mut stx);
        let peer_id =
            iroha_model_base::peer::PeerId::from(validator.expect_single_signatory().clone());
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        ActivatePublicLaneValidator {
            lane_id,
            validator: validator.clone(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(250_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(250_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .unwrap();
        // Ensure stake shares exist before unregistration.
        let pre_exit_shares = stx
            .world
            .public_lane_stake_shares
            .iter()
            .filter(|((lane, val, _), _)| *lane == lane_id && val == &validator)
            .count();
        assert!(
            pre_exit_shares > 0,
            "expected bonded stake shares prior to unregister"
        );
        stx.commit_topology
            .get_mut()
            .retain(|peer| peer != &peer_id);
        use iroha_data_model::isi::register::Unregister;
        let error = Unregister::<Peer>::peer(peer_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("retained validator tenure must reject peer unregistration");
        assert!(
            matches!(&error, Error::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("wait for its deactivation height")),
            "unexpected unregistration rejection: {error}"
        );
        assert!(stx.world.peers().iter().any(|peer| peer == &peer_id));
        let remaining_shares = stx
            .world
            .public_lane_stake_shares()
            .iter()
            .filter(|((lane, val, _), _)| *lane == lane_id && val == &validator)
            .count();
        assert_eq!(
            remaining_shares, pre_exit_shares,
            "rejected peer removal must preserve every bonded stake share"
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator.clone()))
            .expect("validator record after rejected removal");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
    }
    #[test]
    fn bond_rejects_without_funds() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, _, asset_def_id) = prepare_accounts(&mut stx);
        let delegator_asset = AssetId::new(asset_def_id.clone(), delegator.clone());
        let delegator_balance = Quantity::from(10_000_u64);
        crate::smartcontracts::isi::asset::isi::debit_numeric_asset_balance_for_test(
            &mut stx.world,
            &stx.network_id,
            &delegator_asset,
            &delegator_balance,
        )
        .expect("drain delegator funds");
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(12),
                &validator,
                Quantity::from(500_u64),
            ),
            lane_id: LaneId::new(12),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let res = BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                LaneId::new(12),
                &validator,
                &delegator,
                Quantity::from(500_u64),
            ),
            lane_id: LaneId::new(12),
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx);
        assert!(
            matches!(res, Err(Error::Math(MathError::NotEnoughQuantity))),
            "expected bond to fail when staker lacks funds"
        );
    }
    #[test]
    fn bond_rejects_terminal_validator_statuses_without_moving_funds() {
        let statuses = [
            PublicLaneValidatorStatus::Exiting(0),
            PublicLaneValidatorStatus::Exited,
            PublicLaneValidatorStatus::Slashed(Hash::new("terminal-bond")),
        ];
        for (index, status) in statuses.into_iter().enumerate() {
            let state = setup_state();
            let block = new_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction_for_callback_testing();
            let (validator, delegator, escrow, asset_definition) = prepare_accounts(&mut stx);
            let lane_id = LaneId::new(210 + u32::try_from(index).expect("small status index"));
            RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &stx,
                    lane_id,
                    &validator,
                    Quantity::from(500_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&validator),
                validator: validator.clone(),
                stake_account: validator.clone(),
                initial_stake: Quantity::from(500_u64),
                metadata: Metadata::default(),
            }
            .execute(&validator, &mut stx)
            .expect("register terminal-status fixture");
            stx.world
                .public_lane_validators
                .get_mut(&(lane_id, validator.clone()))
                .expect("validator fixture")
                .status = status;
            let delegator_asset = AssetId::new(asset_definition.clone(), delegator.clone());
            let escrow_asset = AssetId::new(asset_definition, escrow);
            let delegator_before = stx
                .world
                .assets
                .get(&delegator_asset)
                .expect("delegator balance")
                .as_ref()
                .clone();
            let escrow_before = stx
                .world
                .assets
                .get(&escrow_asset)
                .expect("escrow balance")
                .as_ref()
                .clone();

            let error = BondPublicLaneStake {
                monetary_plan: fixture_bond_plan(
                    &stx,
                    lane_id,
                    &validator,
                    &delegator,
                    Quantity::from(100_u64),
                ),
                lane_id,
                validator: validator.clone(),
                staker: delegator.clone(),
                amount: Quantity::from(100_u64),
                metadata: Metadata::default(),
            }
            .execute(&delegator, &mut stx)
            .expect_err("terminal validator status must reject new stake");

            assert!(matches!(
                error,
                Error::InvariantViolation(message)
                    if message.contains("does not accept new stake")
            ));
            assert_eq!(
                stx.world
                    .public_lane_validators
                    .get(&(lane_id, validator.clone()))
                    .expect("validator remains present")
                    .total_stake,
                Quantity::from(500_u64)
            );
            assert!(
                stx.world
                    .public_lane_stake_shares
                    .get(&(lane_id, validator, delegator))
                    .is_none(),
                "rejected bond must not create a delegator share"
            );
            assert_eq!(
                stx.world
                    .assets
                    .get(&delegator_asset)
                    .expect("delegator balance remains")
                    .as_ref(),
                &delegator_before
            );
            assert_eq!(
                stx.world
                    .assets
                    .get(&escrow_asset)
                    .expect("escrow balance remains")
                    .as_ref(),
                &escrow_before
            );
        }
    }
    #[test]
    fn bond_public_lane_stake_rejects_mismatched_public_lane_validator_row() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(165);
        let delegator_asset = AssetId::new(asset_def_id.clone(), delegator.clone());
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        let delegator_before = stx
            .world
            .assets
            .get(&delegator_asset)
            .expect("delegator stake asset")
            .as_ref()
            .clone();
        let escrow_before = stx
            .world
            .assets
            .get(&escrow_asset)
            .map_or_else(Quantity::zero, |asset| asset.as_ref().clone());
        insert_validator_record_for_key(
            &mut stx,
            lane_id,
            LaneId::new(166),
            &validator,
            PublicLaneValidatorStatus::Active,
            Quantity::from(1_000_u64),
        );
        let err = BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(100_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect_err("mismatched validator row must reject bonding");
        assert!(
            matches!(err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key"))
        );
        assert_eq!(
            stx.world
                .assets
                .get(&delegator_asset)
                .expect("delegator stake asset after rejection")
                .as_ref(),
            &delegator_before
        );
        assert_eq!(
            stx.world
                .assets
                .get(&escrow_asset)
                .map_or_else(Quantity::zero, |asset| asset.as_ref().clone()),
            escrow_before
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert_eq!(record.total_stake, Quantity::from(1_000_u64));
    }
    #[test]
    fn register_rejects_below_min_stake() {
        let mut state = setup_state();
        state.nexus.get_mut().staking.min_validator_stake = 2_000_u64.into();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let res = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(3),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(3),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(res.is_err(), "expected min stake rejection");
    }
    #[test]
    fn register_rejects_when_peer_missing() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        let missing_peer = iroha_model_base::peer::PeerId::from(
            validator
                .try_signatory()
                .expect("validator has signatory")
                .clone(),
        );
        if let Some(index) = stx
            .world
            .peers
            .iter()
            .position(|peer| peer == &missing_peer)
        {
            stx.world.peers.remove(index);
        }
        let res = RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(42),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(42),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx);
        assert!(
            matches!(res, Err(Error::InvariantViolation(ref msg)) if msg.contains("peer")),
            "expected missing peer rejection, got {res:?}"
        );
    }
    #[test]
    fn unbond_respects_delay() {
        let mut state = setup_state();
        state.nexus.get_mut().staking.unbonding_delay = Duration::from_secs(10);
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, _, _) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(4),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(4),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let release_at_ms = stx.block_unix_timestamp_ms();
        let res = SchedulePublicLaneUnbond {
            lane_id: LaneId::new(4),
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("req-delay"),
            amount: Quantity::from(100_u64),
            release_at_ms,
        }
        .execute(&delegator, &mut stx);
        assert!(res.is_err(), "expected unbond delay enforcement");
    }
    #[test]
    fn bond_rejects_new_share_at_validator_cap_without_moving_funds() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_stake_shares_per_validator = nonzero!(1_u32);
        let (validator, delegator, _escrow, asset_definition) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(171);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("validator self share occupies the configured capacity");
        finalize_validator_lifecycle(&mut stx)
            .expect("settle due lifecycle before admission snapshot");
        let validator_before = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("validator record")
            .clone();
        let delegator_asset = AssetId::new(asset_definition, delegator.clone());
        let balance_before = stx
            .world
            .assets
            .get(&delegator_asset)
            .expect("delegator stake balance")
            .as_ref()
            .clone();

        let err = BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(100_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect_err("a second share must exceed the configured cap");
        assert!(matches!(
            err,
            Error::InvariantViolation(message)
                if message.contains("maximum stake-share capacity")
        ));
        assert_eq!(
            stx.world
                .public_lane_validators
                .get(&(lane_id, validator.clone())),
            Some(&validator_before),
            "rejected admission must not mutate validator aggregates"
        );
        assert_eq!(
            stx.world
                .assets
                .get(&delegator_asset)
                .expect("delegator stake balance")
                .as_ref(),
            &balance_before,
            "rejected admission must not move stake into escrow"
        );
        assert!(
            stx.world
                .public_lane_stake_shares
                .get(&(lane_id, validator, delegator))
                .is_none(),
            "rejected admission must not create a share"
        );
    }
    #[test]
    fn schedule_unbond_rejects_request_at_share_cap_atomically() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        stx.nexus.staking.max_pending_unbonds_per_share = nonzero!(2_u32);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        let (validator, _delegator, _escrow, _asset_definition) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(172);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        let release_at_ms = stx.block_unix_timestamp_ms();
        for request in [Hash::new("bounded-unbond-1"), Hash::new("bounded-unbond-2")] {
            SchedulePublicLaneUnbond {
                lane_id,
                validator: validator.clone(),
                staker: validator.clone(),
                request_id: request,
                amount: Quantity::from(100_u64),
                release_at_ms,
            }
            .execute(&validator, &mut stx)
            .expect("request up to the configured cap must succeed");
        }
        let validator_before = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("validator record")
            .clone();
        let share_key = (lane_id, validator.clone(), validator.clone());
        let share_before = stx
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .expect("validator self share")
            .clone();

        let err = SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id: Hash::new("bounded-unbond-3"),
            amount: Quantity::from(100_u64),
            release_at_ms,
        }
        .execute(&validator, &mut stx)
        .expect_err("request beyond the configured cap must fail");
        assert!(matches!(
            err,
            Error::InvariantViolation(message)
                if message.contains("maximum pending-unbond capacity")
        ));
        assert_eq!(
            stx.world
                .public_lane_validators
                .get(&(lane_id, validator.clone())),
            Some(&validator_before),
            "rejected request must not mutate validator aggregates"
        );
        assert_eq!(
            stx.world.public_lane_stake_shares.get(&share_key),
            Some(&share_before),
            "rejected request must not mutate the share or pending queue"
        );
    }
    #[test]
    fn schedule_public_lane_unbond_rejects_mismatched_public_lane_validator_row() {
        let mut state = setup_state();
        state.nexus.get_mut().staking.unbonding_delay = Duration::from_millis(0);
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_definition) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(167);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("seed canonical stake custody before corrupting the validator row");
        let validator_key = (lane_id, validator.clone());
        stx.world
            .public_lane_validators
            .get_mut(&validator_key)
            .expect("registered validator")
            .lane_id = LaneId::new(168);
        let custody_before = stx
            .world
            .public_lane_stake_custody
            .get(&validator_key)
            .cloned();
        let escrow_asset = AssetId::new(asset_definition, escrow);
        let balance_before = stx.world.assets.get(&escrow_asset).cloned();
        let err = SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            request_id: Hash::new("req-mismatched"),
            amount: Quantity::from(100_u64),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&delegator, &mut stx)
        .expect_err("mismatched validator row must reject unbond scheduling");
        assert!(
            matches!(&err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key")),
            "unexpected unbond rejection: {err}"
        );
        assert_eq!(
            stx.world.public_lane_stake_custody.get(&validator_key),
            custody_before.as_ref(),
            "corrupt validator rows must not release retained custody"
        );
        assert_eq!(stx.world.assets.get(&escrow_asset), balance_before.as_ref());
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert_eq!(record.total_stake, Quantity::from(1_000_u64));
    }
    #[test]
    fn slash_transfers_funds_to_sink() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, escrow, asset_def_id) = prepare_accounts(&mut stx);
        // Route slashes to the delegator account to ensure the transfer is observable.
        stx.nexus.staking.slash_sink_account_id = delegator.to_string();
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(13),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(13),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                LaneId::new(13),
                &validator,
                &delegator,
                Quantity::from(500_u64),
            ),
            lane_id: LaneId::new(13),
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .unwrap();
        SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &stx,
                LaneId::new(13),
                &validator,
                stx.block_height(),
                Quantity::from(400_u64),
            ),
            lane_id: LaneId::new(13),
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash-escrow"),
            amount: Quantity::from(400_u64),
            reason_code: "evidence".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let escrow_asset = AssetId::new(asset_def_id.clone(), escrow.clone());
        let sink_asset = AssetId::new(asset_def_id.clone(), delegator.clone());
        let escrow_balance = view
            .world
            .assets()
            .get(&escrow_asset)
            .expect("escrow asset after slash");
        let sink_balance = view
            .world
            .assets()
            .get(&sink_asset)
            .expect("slash sink asset");
        assert_eq!(escrow_balance.as_ref(), &Quantity::from(1_100_u64));
        assert_eq!(sink_balance.as_ref(), &Quantity::from(9_900_u64));
        let validator_record = view
            .world
            .public_lane_validators()
            .get(&(LaneId::new(13), validator.clone()))
            .expect("validator after slash");
        assert_eq!(validator_record.total_stake, Quantity::from(1_100_u64));
        assert_eq!(validator_record.self_stake, Quantity::from(600_u64));
        let self_share = view
            .world
            .public_lane_stake_shares()
            .get(&(LaneId::new(13), validator.clone(), validator.clone()))
            .expect("self stake share after slash");
        assert_eq!(self_share.bonded, Quantity::from(600_u64));
        let delegator_share = view
            .world
            .public_lane_stake_shares()
            .get(&(LaneId::new(13), validator, delegator))
            .expect("delegator stake share after slash");
        assert_eq!(delegator_share.bonded, Quantity::from(500_u64));
    }
    #[test]
    fn consensus_slash_after_unbond_schedule_consumes_offender_pending_custody() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, _escrow, _asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(173);
        stx.nexus.staking.slash_sink_account_id = delegator.to_string();
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register slash-order fixture validator");
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(500_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(500_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect("bond nominator stake");
        let request_id = Hash::new("self-pending-before-slash");
        SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: Quantity::from(900_u64),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("move offender self stake into slashable pending custody");

        let mut share_keys = vec![
            stake_key(lane_id, &validator, &validator),
            stake_key(lane_id, &validator, &delegator),
        ];
        share_keys.sort();
        apply_indexed_consensus_slash_to_validator(
            &mut stx,
            lane_id,
            &validator,
            Hash::new("self-pending-priority"),
            &Quantity::from(400_u64),
            0,
            ConsensusSlashLiability::Root(2),
            &share_keys,
        )
        .expect("an H+1 offence remains slashable from frozen pending custody");

        let record = stx
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .expect("slashed validator record");
        assert_eq!(record.total_stake, Quantity::from(500_u64));
        assert_eq!(record.self_stake, Quantity::zero());
        let self_share = stx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator.clone(), validator.clone()))
            .expect("offender pending share remains");
        assert_eq!(self_share.bonded, Quantity::zero());
        assert_eq!(
            self_share.pending_unbonds[&request_id].amount,
            Quantity::from(600_u64)
        );
        let nominator_share = stx
            .world
            .public_lane_stake_shares
            .get(&(lane_id, validator, delegator))
            .expect("nominator share remains");
        assert_eq!(nominator_share.bonded, Quantity::from(500_u64));
        assert!(nominator_share.pending_unbonds.is_empty());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn manual_slash_enforces_offence_tenure_and_pending_custody_cutoff() {
        let mut state = setup_state();
        set_epoch_length(&mut state, 3);
        let block = new_block_with_height_and_time(1, 0);
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _delegator, escrow, asset_definition) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(175);
        set_test_npos_penalty_windows(&mut stx, 1, 1);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register manual-slash fixture validator");
        let request_id = Hash::new("manual-slash-pending-cutoff");
        SchedulePublicLaneUnbond {
            lane_id,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: Quantity::from(900_u64),
            release_at_ms: stx.block_unix_timestamp_ms(),
        }
        .execute(&validator, &mut stx)
        .expect("schedule pending custody before the manual slash");
        let pending = &stx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane_id, &validator, &validator))
            .expect("manual-slash fixture share")
            .pending_unbonds[&request_id];
        assert_eq!(pending.slashable_through_height, 6);
        stx.apply();
        state_block.commit_world_overlay_for_testing().unwrap();

        let slash_block = new_block_with_height_and_time(7, 1);
        let mut slash_state_block = state.block(slash_block.as_ref().header());
        let mut slash_tx = slash_state_block.transaction_for_callback_testing();
        slash_tx.nexus.staking.stake_asset_id = asset_definition.to_string();
        set_fixture_xor_identity(&mut slash_tx, &asset_definition);
        slash_tx.nexus.staking.stake_escrow_account_id = escrow.to_string();
        slash_tx.nexus.staking.slash_sink_account_id = escrow.to_string();
        slash_tx.nexus.staking.max_slash_bps = 10_000;
        finalize_validator_lifecycle(&mut slash_tx).expect("activate fixture validator");

        for (offence_height, expected_message) in [
            (
                0,
                "slash offence height must identify a non-zero height no later than the current block",
            ),
            (
                8,
                "slash offence height must identify a non-zero height no later than the current block",
            ),
        ] {
            let error = SlashPublicLaneValidator {
                monetary_plan: fixture_slash_plan(
                    &slash_tx,
                    lane_id,
                    &validator,
                    offence_height,
                    Quantity::from(1_u64),
                ),
                lane_id,
                validator: validator.clone(),
                offence_height,
                slash_id: Hash::new(offence_height.to_be_bytes()),
                amount: Quantity::from(1_u64),
                reason_code: "invalid offence height".to_owned(),
                metadata: Metadata::default(),
            }
            .execute(&ALICE_ID, &mut slash_tx)
            .expect_err("zero and future offence heights must fail closed");
            assert!(
                matches!(error, Error::InvariantViolation(message) if message.contains(expected_message))
            );
        }

        slash_tx
            .world
            .public_lane_validators
            .get_mut(&(lane_id, validator.clone()))
            .expect("manual-slash fixture validator")
            .deactivation_height = Some(7);
        let error = SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &slash_tx,
                lane_id,
                &validator,
                7,
                Quantity::from(1_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: 7,
            slash_id: Hash::new("manual-slash-outside-tenure"),
            amount: Quantity::from(1_u64),
            reason_code: "outside retained tenure".to_owned(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut slash_tx)
        .expect_err("the exclusive deactivation boundary must reject the offence height");
        assert!(
            matches!(error, Error::InvariantViolation(message) if message.contains("outside the validator tenure"))
        );
        slash_tx
            .world
            .public_lane_validators
            .get_mut(&(lane_id, validator.clone()))
            .expect("manual-slash fixture validator")
            .deactivation_height = None;

        let error = SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &slash_tx,
                lane_id,
                &validator,
                7,
                Quantity::from(101_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: 7,
            slash_id: Hash::new("manual-slash-after-pending-cutoff"),
            amount: Quantity::from(101_u64),
            reason_code: "after pending custody cutoff".to_owned(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut slash_tx)
        .expect_err("post-cutoff pending custody must not expand slashable exposure");
        assert!(
            matches!(error, Error::InvariantViolation(message) if message.contains("exceeds configured maximum ratio"))
        );
        let share = slash_tx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane_id, &validator, &validator))
            .expect("rejected slash preserves the fixture share");
        assert_eq!(share.bonded, Quantity::from(100_u64));
        assert_eq!(
            share.pending_unbonds[&request_id].amount,
            Quantity::from(900_u64)
        );

        SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &slash_tx,
                lane_id,
                &validator,
                7,
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            offence_height: 7,
            slash_id: Hash::new("manual-slash-bonded-only"),
            amount: Quantity::from(100_u64),
            reason_code: "bonded custody only".to_owned(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut slash_tx)
        .expect("the bonded portion remains slashable for an in-tenure offence");
        let share = slash_tx
            .world
            .public_lane_stake_shares
            .get(&stake_key(lane_id, &validator, &validator))
            .expect("pending custody remains after the bonded slash");
        assert_eq!(share.bonded, Quantity::zero());
        assert_eq!(
            share.pending_unbonds[&request_id].amount,
            Quantity::from(900_u64)
        );
    }
    #[test]
    fn validation_only_consensus_slash_rolls_back_every_world_write() {
        let _status_guard = crate::status::operator_status_test_guard();
        crate::status::reset_nexus_economics_for_tests();
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let lane_id = LaneId::new(13);
        let (validator, escrow_asset, sink_asset, staking_config) = {
            let mut transaction = state_block.transaction_for_callback_testing();
            let (validator, delegator, escrow, asset_definition_id) =
                prepare_accounts(&mut transaction);
            transaction.nexus.staking.slash_sink_account_id = delegator.to_string();
            RegisterPublicLaneValidator {
                monetary_plan: fixture_registration_plan(
                    &transaction,
                    lane_id,
                    &validator,
                    Quantity::from(1_000_u64),
                ),
                lane_id,
                peer_id: validator_peer_id(&validator),
                validator: validator.clone(),
                stake_account: validator.clone(),
                initial_stake: Quantity::from(1_000_u64),
                metadata: Metadata::default(),
            }
            .execute(&validator, &mut transaction)
            .expect("register validation-only slash target");
            let escrow_asset = AssetId::new(asset_definition_id.clone(), escrow.clone());
            let sink_asset = AssetId::new(asset_definition_id, delegator);
            let staking_config = transaction.nexus.staking.clone();
            transaction.apply();
            (validator, escrow_asset, sink_asset, staking_config)
        };
        // `prepare_accounts` configures the transaction snapshot. Preserve that
        // exact custody policy for the independent consensus-validation scope.
        state_block.nexus.staking = staking_config;
        state_block.world.take_external_events();
        let status_before = crate::status::lane_scoped_status_fingerprint_for_tests();
        let record_before = state_block
            .world
            .public_lane_validators
            .get(&(lane_id, validator.clone()))
            .cloned()
            .expect("registered validator remains in the block overlay");
        let escrow_before = state_block
            .world
            .assets
            .get(&escrow_asset)
            .map_or_else(Quantity::zero, |asset| asset.as_ref().clone());
        let sink_before = state_block
            .world
            .assets
            .get(&sink_asset)
            .map_or_else(Quantity::zero, |asset| asset.as_ref().clone());
        let share_key = (lane_id, validator.clone(), validator.clone());
        let share_before = state_block
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .cloned()
            .expect("registered validator retains a self-stake share");

        {
            let mut validation = state_block
                .consensus_effects_transaction()
                .expect("funded consensus-effects validation overlay");
            let now_ms = validation.block_unix_timestamp_ms();
            apply_slash_to_validator_without_observability(
                &mut validation,
                lane_id,
                &validator,
                Hash::new("validation-only-consensus-slash"),
                &Quantity::from(100_u64),
                now_ms,
            )
            .expect("a valid slash must be applicable in the disposable overlay");
            let validation_record = validation
                .world
                .public_lane_validators
                .get(&(lane_id, validator.clone()))
                .expect("validation overlay retains the slashed validator");
            assert_eq!(validation_record.total_stake, Quantity::from(900_u64));
            assert_eq!(
                validation
                    .world
                    .public_lane_stake_shares
                    .get(&share_key)
                    .expect("validation overlay retains the reduced self-stake share")
                    .bonded,
                Quantity::from(900_u64)
            );
            assert_eq!(
                validation
                    .world
                    .assets
                    .get(&escrow_asset)
                    .expect("validation overlay retains escrow")
                    .as_ref(),
                &Quantity::from(900_u64)
            );
            assert_eq!(
                validation
                    .world
                    .assets
                    .get(&sink_asset)
                    .expect("validation overlay credits the slash sink")
                    .as_ref(),
                &Quantity::from(10_100_u64)
            );
        }

        assert_eq!(
            state_block
                .world
                .public_lane_validators
                .get(&(lane_id, validator))
                .expect("discarded validation leaves the validator intact"),
            &record_before
        );
        assert_eq!(
            state_block
                .world
                .assets
                .get(&escrow_asset)
                .map_or_else(Quantity::zero, |asset| asset.as_ref().clone()),
            escrow_before
        );
        assert_eq!(
            state_block
                .world
                .assets
                .get(&sink_asset)
                .map_or_else(Quantity::zero, |asset| asset.as_ref().clone()),
            sink_before
        );
        assert_eq!(
            state_block
                .world
                .public_lane_stake_shares
                .get(&share_key)
                .expect("discarded validation leaves the self-stake share intact"),
            &share_before
        );
        assert!(
            state_block.world.take_external_events().is_empty(),
            "discarded consensus validation must not publish world events"
        );
        assert_eq!(
            crate::status::lane_scoped_status_fingerprint_for_tests(),
            status_before,
            "discarded consensus validation must not publish process-global status"
        );
        crate::status::reset_nexus_economics_for_tests();
    }
    #[test]
    fn slash_public_lane_validator_rejects_mismatched_public_lane_validator_row() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, escrow, asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(169);
        let escrow_asset = AssetId::new(asset_def_id, escrow);
        RegisterPublicLaneValidator::new(
            lane_id,
            validator.clone(),
            validator_peer_id(&validator),
            validator.clone(),
            1_000_u64.into(),
            Metadata::default(),
            fixture_registration_plan(&stx, lane_id, &validator, &1_000_u64.into()),
        )
        .execute(&validator, &mut stx)
        .unwrap();
        let monetary_plan = fixture_slash_plan(
            &stx,
            lane_id,
            &validator,
            stx.block_height(),
            &100_u64.into(),
        );
        let escrow_before = stx
            .world
            .assets
            .get(&escrow_asset)
            .unwrap()
            .as_ref()
            .clone();
        let record = stx
            .world
            .public_lane_validators
            .get_mut(&(lane_id, validator.clone()))
            .unwrap();
        record.status = PublicLaneValidatorStatus::Active;
        record.lane_id = LaneId::new(170);
        let err = SlashPublicLaneValidator {
            // The exact plan captured before corruption must not bypass
            // storage-key validation of this deliberately malformed record.
            monetary_plan,
            lane_id,
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash-mismatched-row"),
            amount: Quantity::from(100_u64),
            reason_code: "evidence".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("mismatched validator row must reject slashing");
        assert!(
            matches!(err, Error::InvariantViolation(msg) if msg.contains("does not match its storage key"))
        );
        assert_eq!(
            stx.world
                .assets
                .get(&escrow_asset)
                .map_or_else(Quantity::zero, |asset| asset.as_ref().clone()),
            escrow_before
        );
        let record = stx
            .world
            .public_lane_validators()
            .get(&(lane_id, validator))
            .expect("mismatched record remains present");
        assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
        assert_eq!(record.total_stake, Quantity::from(1_000_u64));
    }
    #[test]
    fn slash_ignores_mismatched_public_lane_stake_share_rows() {
        let state = setup_state();
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, delegator, _escrow, _asset_def_id) = prepare_accounts(&mut stx);
        let lane_id = LaneId::new(171);
        stx.nexus.staking.max_slash_bps = 10_000;
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .expect("register validator");
        BondPublicLaneStake {
            monetary_plan: fixture_bond_plan(
                &stx,
                lane_id,
                &validator,
                &delegator,
                Quantity::from(100_u64),
            ),
            lane_id,
            validator: validator.clone(),
            staker: delegator.clone(),
            amount: Quantity::from(100_u64),
            metadata: Metadata::default(),
        }
        .execute(&delegator, &mut stx)
        .expect("bond delegator stake");
        let validator_key = (lane_id, validator.clone());
        let share_key = (lane_id, validator.clone(), delegator.clone());
        let validator_before = stx
            .world
            .public_lane_validators
            .get(&validator_key)
            .expect("validator before slash")
            .clone();
        assert_eq!(validator_before.total_stake, Quantity::from(1_100_u64));
        let mut malformed_share = stx
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .expect("delegator share before corruption")
            .clone();
        let monetary_plan = fixture_slash_plan(
            &stx,
            lane_id,
            &validator,
            stx.block_height(),
            &Quantity::from(1_100_u64),
        );
        malformed_share.lane_id = LaneId::new(172);
        stx.world
            .public_lane_stake_shares
            .insert(share_key.clone(), malformed_share);
        let err = SlashPublicLaneValidator {
            monetary_plan,
            lane_id,
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash-mismatched-share-row"),
            amount: Quantity::from(1_100_u64),
            reason_code: "evidence".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("mismatched stake-share row must not satisfy slash");
        assert!(
            matches!(&err, Error::InvariantViolation(msg) if msg.contains("public-lane stake share does not match its storage key")),
            "malformed share must reject before slash mutation: {err:?}"
        );
        let validator_after = stx
            .world
            .public_lane_validators
            .get(&validator_key)
            .expect("validator after rejected slash");
        assert_eq!(
            validator_after.total_stake, validator_before.total_stake,
            "rejected slash must not reduce validator total stake"
        );
        assert_eq!(
            validator_after.self_stake, validator_before.self_stake,
            "rejected slash must not reduce validator self stake"
        );
        assert!(
            !matches!(
                validator_after.status,
                PublicLaneValidatorStatus::Slashed(_)
            ),
            "rejected slash must not mark validator as slashed"
        );
        let share_after = stx
            .world
            .public_lane_stake_shares
            .get(&share_key)
            .expect("malformed share remains as stored");
        assert_eq!(share_after.lane_id, LaneId::new(172));
        assert_eq!(share_after.bonded, Quantity::from(100_u64));
    }

    #[test]
    fn slash_rejects_above_max_ratio() {
        let mut state = setup_state();
        state.nexus.get_mut().staking.max_slash_bps = 1_000; // 10%
        let block = new_block();
        let mut state_block = state.block(block.as_ref().header());
        let mut stx = state_block.transaction_for_callback_testing();
        let (validator, _, _, _) = prepare_accounts(&mut stx);
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                LaneId::new(5),
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id: LaneId::new(5),
            peer_id: validator_peer_id(&validator),
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, &mut stx)
        .unwrap();
        let res = SlashPublicLaneValidator {
            monetary_plan: fixture_slash_plan(
                &stx,
                LaneId::new(5),
                &validator,
                stx.block_height(),
                Quantity::from(200_u64),
            ),
            lane_id: LaneId::new(5),
            validator: validator.clone(),
            offence_height: stx.block_height(),
            slash_id: Hash::new("slash"),
            amount: Quantity::from(200_u64),
            reason_code: "double_sign".to_string(),
            metadata: Metadata::default(),
        }
        .execute(&ALICE_ID, &mut stx);
        assert!(res.is_err(), "expected slash ratio guard to reject");
    }
    #[test]
    fn slash_ratio_arithmetic_accepts_representable_results_at_512_bit_boundary() {
        let maximum: Quantity = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047"
            .parse()
            .expect("signed maximum quantity");
        assert!(slash_within_limit(&maximum, &maximum, 10_000).expect("exact comparison"));
        assert!(!slash_within_limit(&maximum, &maximum, 9_999).expect("exact comparison"));
        let capped = max_slash_amount(&maximum, 9_999)
            .expect("wide product is divided before the final domain check");
        assert!(capped < maximum);
        assert!(slash_within_limit(&capped, &maximum, 9_999).expect("capped amount is legal"));
    }
}
