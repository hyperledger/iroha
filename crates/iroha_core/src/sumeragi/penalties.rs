//! Deterministic `NPoS` consensus-evidence slashing.
//!
//! Parent validator locators retain exact original-pool backing and nested key custody.
//! TODO(S8): evidence/history graphs, penalty-action arithmetic
//! still need complete original-pool owners; this locator owner does not fund those graphs.
#[cfg(test)]
use crate::state::StateBlock;
#[cfg(feature = "telemetry")]
use crate::telemetry::StateTelemetry;
use crate::{
    smartcontracts::isi::staking::{
        ConsensusSlashLiability, PublicLaneStakeIndex, apply_indexed_consensus_slash_to_validator,
        apply_indexed_slash_to_validator_without_observability,
        indexed_slashable_validator_exposure, max_slash_amount, validator_tenure_contains_height,
    },
    state::{
        EvidencePreparationError, State, StateTransaction, StateView, WorldReadOnly,
        public_lane_validator_record_matches_key,
    },
};
use eyre::{Result, WrapErr, eyre};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedBuffer,
    ChargedBufferFromChargeError, PrepaidBufferError,
};
use iroha_crypto::{ChargedPublicKey, Hash, PublicKey, PublicKeyAllocationError};
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{Evidence, EvidencePenaltyStatus, EvidenceScope},
    },
    consensus::{
        NposConsensusEffects, NposConsensusSlashAction, NposMarkConsensusEvidenceAppliedAction,
        NposPenaltyAction,
    },
    prelude::AccountId,
};
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use std::alloc::Layout;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Default)]
/// Result of applying one exact finalized penalty bundle.
pub struct PenaltyOutcome {
    /// Number of evidence records terminalized.
    pub applied: u64,
    /// Number of actual custody slashes applied.
    pub slashed: u64,
}
#[derive(Clone, Copy)]
enum EffectsApplicationMode {
    Commit,
    #[cfg(test)]
    ValidateOnly,
}
struct ValidatorLocator {
    peer_key: ChargedPublicKey,
    lane_id: LaneId,
    validator: AccountId,
    activation_height: u64,
    deactivation_height: Option<u64>,
    root_authority: bool,
}
/// Immutable flat lookup. Concrete keys/accounts cannot unwind during destruction;
/// row destruction releases every account before the final nested-charge ledger.
struct ValidatorMap {
    rows: ChargedBuffer<ValidatorLocator>,
    _account_charges: ChargedBuffer<AllocationCharge>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ValidatorMapDemand {
    rows: usize,
    account_charges: usize,
    nested_bytes: usize,
}

fn locator_is_needed(
    view: &StateView<'_>,
    record: &iroha_data_model::nexus::PublicLaneValidatorRecord,
) -> bool {
    (view.is_lane_active_for_authority(record.lane_id)
        && view.staking_authority_lane(record.lane_id) == Some(record.lane_id))
        || view.world().sumeragi_lanes().custody.iter().any(|row| {
            row.signers.as_slice().iter().any(|entry| {
                entry.binding.activation_height == record.activation_height
                    && entry
                        .binding
                        .names_account(record.lane_id, &record.validator)
                        .unwrap_or(true)
            })
        })
}

impl ValidatorMapDemand {
    fn from_world(view: &StateView<'_>) -> Result<Self> {
        let mut demand = Self::default();
        let mut current_lane = None;
        let mut lane_count = 0_u32;
        // The World cursor is ordered by (lane, account); no per-lane map is needed.
        for (key, record) in view.world().public_lane_validators().iter() {
            if !public_lane_validator_record_matches_key(key, record) {
                continue;
            }
            if current_lane != Some(key.0) {
                current_lane = Some(key.0);
                lane_count = 0;
            }
            lane_count = lane_count
                .checked_add(1)
                .ok_or_else(|| eyre!("public-lane validator count overflows u32"))?;
            if lane_count > view.nexus.staking.max_validators.get() {
                return Err(eyre!(
                    "public lane {} exceeds retained validator capacity",
                    key.0
                ));
            }
            if !locator_is_needed(view, record) {
                continue;
            }
            validator_tenure_contains_height(record, record.activation_height)
                .wrap_err("retained public-lane validator tenure is non-canonical")?;
            demand.add(record.peer_id.public_key(), &key.1)?;
        }
        Ok(demand)
    }

    fn add(
        &mut self,
        peer: &PublicKey,
        account: &AccountId,
    ) -> Result<(), EvidencePreparationError> {
        let overflow = || EvidencePreparationError::Admission(AllocationRefusal::DemandOverflow);
        self.rows = self.rows.checked_add(1).ok_or(overflow())?;
        self.nested_bytes = self
            .nested_bytes
            .checked_add(peer.retained_allocation_layout().size())
            .ok_or(overflow())?;
        let mut failed = false;
        account
            .for_each_admission_clone_layout(|layout| {
                if let (Some(bytes), Some(charges)) = (
                    self.nested_bytes.checked_add(layout.size()),
                    self.account_charges.checked_add(1),
                ) {
                    self.nested_bytes = bytes;
                    self.account_charges = charges;
                } else {
                    failed = true;
                }
            })
            .map_err(|_| EvidencePreparationError::Invariant)?;
        if failed {
            return Err(overflow());
        }
        Ok(())
    }

    fn retained_bytes(self) -> Result<usize, EvidencePreparationError> {
        let overflow = || EvidencePreparationError::Admission(AllocationRefusal::DemandOverflow);
        let rows = Layout::array::<ValidatorLocator>(self.rows).map_err(|_| overflow())?;
        let ledger =
            Layout::array::<AllocationCharge>(self.account_charges).map_err(|_| overflow())?;
        rows.size()
            .checked_add(ledger.size())
            .and_then(|bytes| bytes.checked_add(self.nested_bytes))
            .ok_or(overflow())
    }
}

impl ValidatorMap {
    fn from_world(
        view: &StateView<'_>,
        index: &PublicLaneStakeIndex,
        budget: &AllocationBudget,
    ) -> Result<Self> {
        let demand = ValidatorMapDemand::from_world(view)?;
        let reservation = budget
            .try_reserve_bytes(demand.retained_bytes()?)
            .map_err(EvidencePreparationError::Admission)?;
        Self::from_reservation(view, index, demand, budget, reservation)
    }

    fn from_reservation(
        view: &StateView<'_>,
        index: &PublicLaneStakeIndex,
        demand: ValidatorMapDemand,
        budget: &AllocationBudget,
        mut reservation: AllocationReservation,
    ) -> Result<Self> {
        if !reservation.belongs_to(budget)
            || reservation.remaining_bytes() != demand.retained_bytes()?
        {
            return Err(EvidencePreparationError::Invariant.into());
        }
        // Declare the ledger first: every partial row/account is destroyed before its
        // charges on refusal or unwind. A completed map preserves that field order.
        let mut account_charges =
            ChargedBuffer::from_reservation(demand.account_charges, &mut reservation)
                .map_err(validator_map_buffer_error)?;
        let mut rows = ChargedBuffer::from_reservation(demand.rows, &mut reservation)
            .map_err(validator_map_buffer_error)?;
        for (key, record) in view.world().public_lane_validators().iter() {
            if !public_lane_validator_record_matches_key(key, record)
                || !locator_is_needed(view, record)
            {
                continue;
            }
            // Preserve validation even when no pending proof will use this locator.
            // The exposure is already materialized under original stake-index custody.
            original_slashable_exposure(index, key.0, &key.1)?;
            let peer = record.peer_id.public_key();
            let charge = reservation
                .try_split(peer.retained_allocation_layout())
                .map_err(|_| EvidencePreparationError::Invariant)?;
            let peer_key = peer
                .try_clone_from_charge(budget, charge)
                .map_err(|(_, error)| match error {
                    PublicKeyAllocationError::Allocation(
                        ChargedBufferFromChargeError::Allocator { layout },
                    ) => EvidencePreparationError::Allocator {
                        requested_bytes: layout.size(),
                    },
                    _ => EvidencePreparationError::Invariant,
                })?;
            let validator = clone_locator_account(&key.1, &mut reservation, &mut account_charges)?;
            rows.try_push(ValidatorLocator {
                peer_key,
                lane_id: key.0,
                validator,
                activation_height: record.activation_height,
                deactivation_height: record.deactivation_height,
                root_authority: view.is_lane_active_for_authority(key.0)
                    && view.staking_authority_lane(key.0) == Some(key.0),
            })
            .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        if rows.as_slice().len() != demand.rows
            || account_charges.as_slice().len() != demand.account_charges
            || reservation.remaining_bytes() != 0
        {
            return Err(EvidencePreparationError::Invariant.into());
        }
        rows.as_mut_slice().sort_unstable_by(|left, right| {
            left.peer_key
                .get()
                .cmp(right.peer_key.get())
                .then_with(|| left.lane_id.cmp(&right.lane_id))
                .then_with(|| left.validator.cmp(&right.validator))
        });
        Ok(Self {
            rows,
            _account_charges: account_charges,
        })
    }

    fn get(&self, peer: &PublicKey) -> Option<&[ValidatorLocator]> {
        let rows = self.rows.as_slice();
        let first = rows.partition_point(|row| row.peer_key.get() < peer);
        let count = rows[first..].partition_point(|row| row.peer_key.get() == peer);
        (count != 0).then_some(&rows[first..first + count])
    }
}

fn validator_map_buffer_error(error: PrepaidBufferError) -> EvidencePreparationError {
    match error {
        PrepaidBufferError::Allocation(error) => error.into(),
        PrepaidBufferError::Reservation(_) => EvidencePreparationError::Invariant,
    }
}

fn clone_locator_account(
    account: &AccountId,
    reservation: &mut AllocationReservation,
    charges: &mut ChargedBuffer<AllocationCharge>,
) -> Result<AccountId, EvidencePreparationError> {
    let mut failed = false;
    account
        .for_each_admission_clone_layout(|layout| {
            if failed {
                return;
            }
            match reservation.try_split(layout) {
                Ok(charge) => failed = charges.try_push(charge).is_err(),
                Err(_) => failed = true,
            }
        })
        .map_err(|_| EvidencePreparationError::Invariant)?;
    if failed {
        return Err(EvidencePreparationError::Invariant);
    }
    account
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

fn original_slashable_exposure<'a>(
    index: &'a PublicLaneStakeIndex,
    lane: LaneId,
    validator: &AccountId,
) -> Result<&'a Quantity> {
    index
        .total_exposure(lane, validator)
        .map_err(|error| eyre!("invalid slashable stake exposure for {validator}: {error}"))
}

struct ParentPenaltySnapshot {
    pending: ChargedBuffer<PendingPenaltyEvidence>,
    max_slash_bps: u16,
    validator_map: ValidatorMap,
    stake_index: PublicLaneStakeIndex,
    #[cfg(test)]
    stake_share_row_visits: usize,
}
type PendingPenaltyEntry =
    iroha_config::parameters::defaults::nexus::storage::ConsensusPenaltyPendingEntry;
#[repr(transparent)]
struct PendingPenaltyEvidence(PendingPenaltyEntry);
fn consensus_penalty_is_due(
    recorded_at_height: u64,
    slashing_delay: u64,
    current_height: u64,
) -> bool {
    recorded_at_height
        .checked_add(slashing_delay)
        .is_some_and(|eligible_height| eligible_height <= current_height)
}
/// Exact allocation made when a compact public key is cloned into pending
/// penalty metadata. `PublicKeyCompact` stores one algorithm tag and the
/// borrowed payload in a `ConstVec<u8>` backed by `Box<[u8]>`.
fn pending_peer_key_layout(peer: &PeerId) -> Result<Layout, EvidencePreparationError> {
    let (algorithm, payload) = peer
        .public_key()
        .try_to_bytes()
        .map_err(|_| EvidencePreparationError::Invariant)?;
    let bytes = payload
        .len()
        .checked_add(1)
        .ok_or(EvidencePreparationError::Admission(
            AllocationRefusal::DemandOverflow,
        ))?;
    if algorithm != iroha_crypto::Algorithm::BlsNormal
        || bytes != iroha_config::parameters::defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PEER_KEY_BYTES
    {
        return Err(EvidencePreparationError::Invariant);
    }
    Layout::array::<u8>(bytes)
        .map_err(|_| EvidencePreparationError::Admission(AllocationRefusal::DemandOverflow))
}

/// Parent-state derivation of native evidence penalties and exact custody effects.
pub struct PenaltyApplier<'a> {
    state: &'a State,
}
impl<'a> PenaltyApplier<'a> {
    pub(crate) fn new(
        state: &'a State,
        #[cfg(feature = "telemetry")] _telemetry: Option<&'a StateTelemetry>,
        #[cfg(not(feature = "telemetry"))] _telemetry: Option<()>,
    ) -> Self {
        Self { state }
    }
    fn parent_snapshot(
        view: &StateView<'_>,
        current_height: u64,
        budget: &AllocationBudget,
        stake_budget: &AllocationBudget,
    ) -> Result<ParentPenaltySnapshot> {
        let evidence_capacity = super::evidence::committed_evidence_capacity(view.world());
        if evidence_capacity.record_capacity_exceeded {
            return Err(eyre!(
                "committed native Sumeragi evidence exceeds the record capacity"
            ));
        }
        if evidence_capacity.byte_capacity_exceeded {
            return Err(eyre!(
                "committed native Sumeragi evidence exceeds the proof-byte capacity"
            ));
        }
        let world = view.world();
        let slashing_delay =
            crate::sumeragi::epoch::parameters::resolve_npos_slashing_delay_blocks_from_world(
                world,
            )?
            .ok_or_else(|| eyre!("NPoS penalty derivation requires signed NPoS parameters"))?;
        let due = |record: &crate::state::RetainedEvidenceRecord| {
            let admitted_at = if cfg!(all(test, sumeragi_core_mutation = "HC3"))
                && matches!(record.attribution.scope, EvidenceScope::Lane(_))
            {
                record.attribution.height
            } else {
                record.recorded_at_height
            };
            !record.penalty_status.is_terminal()
                && record.recorded_at_height < current_height
                && consensus_penalty_is_due(admitted_at, slashing_delay, current_height)
        };
        // This borrowed count and the fill below read the same StateView.
        // Fund the exact original backing before constructing the stake index.
        let mut due_count = 0_usize;
        let mut peer_key_bytes = 0_usize;
        for (_, record) in world.consensus_evidence().iter() {
            if !due(record) {
                continue;
            }
            due_count = due_count
                .checked_add(record.attribution.offenders.len().max(1))
                .ok_or(EvidencePreparationError::Admission(
                    AllocationRefusal::DemandOverflow,
                ))?;
            for offender in &record.attribution.offenders {
                let peer = &offender.peer_id;
                peer_key_bytes = peer_key_bytes
                    .checked_add(pending_peer_key_layout(peer)?.size())
                    .ok_or(EvidencePreparationError::Admission(
                        AllocationRefusal::DemandOverflow,
                    ))?;
            }
        }
        let mut pending =
            ChargedBuffer::new(due_count, budget).map_err(EvidencePreparationError::from)?;
        // Prepay every nested compact key before stake-index construction or
        // any clone. Each split charge stays in the same pending entry as its
        // key and refunds only after that entry's PeerId has been dropped.
        let mut peer_key_reservation = budget
            .try_reserve_bytes(peer_key_bytes)
            .map_err(EvidencePreparationError::Admission)?;
        let exposure_index = PublicLaneStakeIndex::from_world(
            world,
            view.nexus.staking.max_stake_shares_per_validator.get(),
            view.nexus.staking.max_pending_unbonds_per_share.get(),
            stake_budget,
        )
        .wrap_err("failed to index slashable public-lane stake exposure")?;
        let candidates_map = ValidatorMap::from_world(view, &exposure_index, budget)?;
        for (key, record) in world.consensus_evidence().iter() {
            if !due(record) {
                continue;
            }
            if record.attribution.offenders.is_empty() {
                pending
                    .try_push(PendingPenaltyEvidence((
                        *key,
                        record.attribution.scope,
                        record.attribution.height,
                        record.recorded_at_height,
                        record.attribution.instance,
                        None,
                    )))
                    .map_err(|_| EvidencePreparationError::Invariant)?;
            }
            for offender in &record.attribution.offenders {
                let layout = pending_peer_key_layout(&offender.peer_id)?;
                let charge = peer_key_reservation
                    .try_split(layout)
                    .map_err(|_| EvidencePreparationError::Invariant)?;
                let owned = offender
                    .peer_id
                    .public_key()
                    .try_clone_from_charge(budget, charge)
                    .map_err(|(_charge, error)| match error {
                        PublicKeyAllocationError::Allocation(
                            ChargedBufferFromChargeError::Allocator { layout },
                        ) => {
                            if cfg!(all(test, sumeragi_core_mutation = "HC160")) {
                                EvidencePreparationError::Invariant
                            } else {
                                EvidencePreparationError::Allocator {
                                    requested_bytes: layout.size(),
                                }
                            }
                        }
                        _ => EvidencePreparationError::Invariant,
                    })?;
                // SAFETY: the immutable compact key moves immediately into the
                // existing move-only pending tuple with its exact original charge.
                // PeerId precedes the charge, so refusal, unwind and final drop
                // destroy the actual compact Box before refunding its credit.
                #[allow(unsafe_code)]
                let (peer_key, charge) = unsafe { owned.into_allocation_parts() };
                pending
                    .try_push(PendingPenaltyEvidence((
                        *key,
                        record.attribution.scope,
                        record.attribution.height,
                        record.recorded_at_height,
                        record.attribution.instance,
                        Some((
                            offender.signer,
                            PeerId::new(peer_key),
                            offender.lane_stake,
                            charge,
                        )),
                    )))
                    .map_err(|_| EvidencePreparationError::Invariant)?;
            }
        }
        if peer_key_reservation.remaining_bytes() != 0 {
            return Err(EvidencePreparationError::Invariant.into());
        }
        #[cfg(test)]
        let stake_share_row_visits = exposure_index.row_visits();
        Ok(ParentPenaltySnapshot {
            pending,
            max_slash_bps: view.nexus.staking.max_slash_bps,
            validator_map: candidates_map,
            stake_index: exposure_index,
            #[cfg(test)]
            stake_share_row_visits,
        })
    }
    pub(crate) fn derive_npos_consensus_effects(
        &self,
        block_header: &BlockHeader,
    ) -> Result<NposConsensusEffects> {
        let (evidence_admissions, penalty_actions, _index) =
            self.derive_from_stable_parent(block_header, true)?;
        Ok(NposConsensusEffects {
            parent_service_commit_qc: None,
            evidence_admissions,
            penalty_actions,
        })
    }
    /// Derive deterministic parent-state actions and retain their original funded
    /// stake index for pristine application. Dropping either rejects this attempt.
    pub(crate) fn derive_npos_penalty_actions(
        &self,
        block_header: &BlockHeader,
    ) -> Result<(Vec<NposPenaltyAction>, PublicLaneStakeIndex)> {
        self.derive_from_stable_parent(block_header, false)
            .map(|(_, actions, index)| (actions, index))
    }
    fn derive_from_stable_parent(
        &self,
        block_header: &BlockHeader,
        include_admissions: bool,
    ) -> Result<(Vec<Evidence>, Vec<NposPenaltyAction>, PublicLaneStakeIndex)> {
        loop {
            let generation_before = self.state.state_view_generation();
            if generation_before % 2 != 0 {
                std::thread::yield_now();
                continue;
            }
            let view = self.state.view();
            let result = Self::parent_snapshot(
                &view,
                block_header.height().get(),
                self.state.evidence_preparation_budget(),
                self.state.stake_index_budget(),
            )
            .and_then(|snapshot| {
                drop(view);
                let admissions = if include_admissions {
                    super::evidence::pending_evidence_admissions(
                        self.state,
                        block_header.height().get(),
                        generation_before,
                    )
                } else {
                    Vec::new()
                };
                self.derive_consensus_penalty_actions(block_header, snapshot)
                    .map(|(actions, index)| (admissions, actions, index))
            });
            let generation_after = self.state.state_view_generation();
            if generation_before == generation_after && generation_after % 2 == 0 {
                return result;
            }
            std::thread::yield_now();
        }
    }
    #[allow(clippy::too_many_lines)]
    fn derive_consensus_penalty_actions(
        &self,
        block_header: &BlockHeader,
        snapshot: ParentPenaltySnapshot,
    ) -> Result<(Vec<NposPenaltyAction>, PublicLaneStakeIndex)> {
        let current_height = block_header.height().get();
        let mut pending = snapshot.pending;
        if pending.as_slice().is_empty() {
            return Ok((Vec::new(), snapshot.stake_index));
        }
        pending
            .as_mut_slice()
            .sort_unstable_by(|left, right| left.0.0.cmp(&right.0.0));
        let _witness_suppression = crate::exec_witness::suppress_recording_for_current_thread();
        let mut scratch = self
            .state
            .consensus_effects_probe_block(block_header.clone())?;
        let mut actions = Vec::new();
        for record in pending.as_slice() {
            let (key, scope, offence_height, recorded_at, instance, signer) = &record.0;
            let key = *key;
            // Admission already validated and anchored this immutable context.
            // Re-reading mutable local Kura files here would make block
            // construction depend on node-local I/O after consensus admission.
            let slash_id = key;
            if let Some((signer, peer_id, binding, _peer_key_charge)) = signer.as_ref() {
                let liability = match (scope, binding) {
                    (EvidenceScope::Root, None) => {
                        Some(ConsensusSlashLiability::Root(*offence_height))
                    }
                    (EvidenceScope::Root, Some(_)) => {
                        return Err(eyre!("root evidence has lane custody"));
                    }
                    (EvidenceScope::Lane(scope), Some(binding)) => {
                        Some(ConsensusSlashLiability::Lane {
                            scope: *scope,
                            instance: *instance,
                            recorded_at: *recorded_at,
                            signer: *signer,
                            binding: *binding,
                        })
                    }
                    (EvidenceScope::Lane(_), None) => None,
                };
                if let Some(liability) = liability
                    && let Some(locators) = snapshot.validator_map.get(peer_id.public_key())
                {
                    for locator in locators {
                        if matches!(liability, ConsensusSlashLiability::Root(_))
                            && (!locator.root_authority
                                || *offence_height < locator.activation_height
                                || locator
                                    .deactivation_height
                                    .is_some_and(|height| *offence_height >= height))
                        {
                            continue;
                        }
                        let validator_key = (locator.lane_id, locator.validator.clone());
                        let current_record = scratch
                            .world
                            .public_lane_validators
                            .get(&validator_key)
                            .ok_or_else(|| {
                                eyre!(
                                    "penalty planning lost retained validator {} on lane {}",
                                    locator.validator,
                                    locator.lane_id
                                )
                            })?;
                        if !liability.names_registration(&scratch.world, current_record)? {
                            continue;
                        }
                        let share_keys = snapshot
                            .stake_index
                            .share_keys(locator.lane_id, &locator.validator);
                        let current_exposure = indexed_slashable_validator_exposure(
                            &scratch.world,
                            locator.lane_id,
                            &locator.validator,
                            current_record,
                            liability,
                            share_keys,
                        )
                        .wrap_err_with(|| {
                            format!(
                                "failed to recompute slashable exposure for {} on lane {}",
                                locator.validator, locator.lane_id
                            )
                        })?;
                        let original_exposure = original_slashable_exposure(
                            &snapshot.stake_index,
                            locator.lane_id,
                            &locator.validator,
                        )?;
                        if &current_exposure > original_exposure {
                            return Err(eyre!(
                                "slashable exposure increased while planning one penalty bundle"
                            ));
                        }
                        let amount = max_slash_amount(&current_exposure, snapshot.max_slash_bps)?;
                        if amount.is_zero() {
                            continue;
                        }
                        let slash = NposConsensusSlashAction {
                            evidence_key: key,
                            signer: *signer,
                            peer_id: peer_id.clone(),
                            lane_id: locator.lane_id,
                            validator: locator.validator.clone(),
                            slash_id,
                            amount,
                        };
                        let mut transaction = scratch.consensus_effects_transaction()?;
                        apply_indexed_slash_to_validator_without_observability(
                            &mut transaction,
                            slash.lane_id,
                            &slash.validator,
                            slash.slash_id,
                            &slash.amount,
                            block_header.creation_time_ms,
                            liability,
                            share_keys,
                        )
                        .wrap_err_with(|| {
                            format!(
                                "failed to plan consensus slash for {} on lane {}",
                                slash.validator, slash.lane_id
                            )
                        })?;
                        transaction.apply_consensus_effects();
                        actions.push(NposPenaltyAction::ConsensusSlash(slash));
                    }
                }
            }
            // A removed, inactive, or zero-stake offender is still terminal:
            // retaining an unslashable record forever would exhaust the
            // bounded committed evidence table and suppress future proofs.
            actions.push(NposPenaltyAction::MarkConsensusEvidenceApplied(
                NposMarkConsensusEvidenceAppliedAction {
                    evidence_key: key,
                    height: current_height,
                },
            ));
        }
        actions.sort();
        actions.dedup();
        Ok((actions, snapshot.stake_index))
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_npos_consensus_effects_to_transaction(
    tx: &mut StateTransaction<'_, '_>,
    effects: &NposConsensusEffects,
    stake_index: Option<&PublicLaneStakeIndex>,
    evidence_prune_keys: &[Hash],
    admitted: &[super::evidence::AdmittedEvidence],
    current_height: u64,
    current_view: u64,
    now_ms: u64,
) -> Result<PenaltyOutcome> {
    apply_npos_consensus_effects_to_transaction_inner(
        tx,
        effects,
        stake_index,
        evidence_prune_keys,
        admitted,
        current_height,
        current_view,
        now_ms,
        EffectsApplicationMode::Commit,
    )
}
/// Validate post-execution consensus effects in a rollback-only transaction.
///
/// The caller must pass the exact prune plan derived from immutable parent
/// state. Operational slash counters and telemetry are suppressed because the
/// transaction is deliberately discarded. Consensus effects never contribute
/// to the transaction execution witness in either application mode.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_npos_consensus_effects_after_execution(
    state_block: &mut StateBlock<'_>,
    effects: &NposConsensusEffects,
    evidence_prune_keys: &[Hash],
    admitted: &[super::evidence::AdmittedEvidence],
    current_height: u64,
    current_view: u64,
    now_ms: u64,
) -> Result<()> {
    let mut tx = state_block.consensus_effects_transaction()?;
    // This test-only post-execution diagnostic has a different source overlay.
    // Production consumes the original pre-State index through the same kernel.
    let stake_index = effects
        .penalty_actions
        .iter()
        .any(|action| matches!(action, NposPenaltyAction::ConsensusSlash(_)))
        .then(|| {
            PublicLaneStakeIndex::from_world(
                &tx.world,
                tx.nexus.staking.max_stake_shares_per_validator.get(),
                tx.nexus.staking.max_pending_unbonds_per_share.get(),
                tx.stake_index_budget,
            )
        })
        .transpose()?;
    apply_npos_consensus_effects_to_transaction_inner(
        &mut tx,
        effects,
        stake_index.as_ref(),
        evidence_prune_keys,
        admitted,
        current_height,
        current_view,
        now_ms,
        EffectsApplicationMode::ValidateOnly,
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn apply_npos_consensus_effects_to_transaction_inner(
    tx: &mut StateTransaction<'_, '_>,
    effects: &NposConsensusEffects,
    stake_index: Option<&PublicLaneStakeIndex>,
    evidence_prune_keys: &[Hash],
    admitted: &[super::evidence::AdmittedEvidence],
    current_height: u64,
    current_view: u64,
    now_ms: u64,
    mode: EffectsApplicationMode,
) -> Result<PenaltyOutcome> {
    if admitted.len() != effects.evidence_admissions.len()
        || admitted
            .iter()
            .zip(&effects.evidence_admissions)
            .any(|(original, evidence)| original.key() != super::evidence::evidence_key(evidence))
    {
        return Err(eyre!(
            "native evidence lost its independently verified pristine attribution"
        ));
    }
    let requires_index = effects
        .penalty_actions
        .iter()
        .any(|action| matches!(action, NposPenaltyAction::ConsensusSlash(_)));
    if requires_index != stake_index.is_some() {
        return Err(eyre!(
            "consensus effects differ from their prepared stake-index owner"
        ));
    }
    // These are finality effects, not transaction execution. Suppress the
    // process-global recorder in both commit and rollback-only validation so
    // concurrent in-process State instances cannot contaminate one another.
    let _witness_suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let mut outcome = PenaltyOutcome::default();
    if !evidence_prune_keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(eyre!(
            "native Sumeragi parent evidence prune plan is not canonical"
        ));
    }
    for key in evidence_prune_keys {
        let record = tx
            .world
            .consensus_evidence
            .get(key)
            .ok_or_else(|| eyre!("native Sumeragi parent evidence prune target is absent"))?;
        if !record.penalty_status.is_terminal() {
            return Err(eyre!(
                "native Sumeragi parent evidence prune target is not terminal"
            ));
        }
        if !super::evidence::committed_evidence_record_is_prunable(
            &tx.world,
            record,
            current_height,
        )? {
            return Err(eyre!(
                "native Sumeragi parent evidence prune target is not stale under the post-execution evidence horizon"
            ));
        }
    }
    for key in evidence_prune_keys {
        tx.world.consensus_evidence.remove(*key);
    }
    if tx
        .world
        .consensus_evidence
        .iter()
        .count()
        .saturating_add(effects.evidence_admissions.len())
        > super::evidence::MAX_COMMITTED_EVIDENCE_RECORDS
    {
        return Err(eyre!(
            "bounded native Sumeragi evidence table has no reclaimable capacity"
        ));
    }
    let mut retained_evidence_bytes = 0_usize;
    for (_, record) in tx.world.consensus_evidence.iter() {
        let encoded_len = super::evidence::evidence_encoded_len(&record.evidence);
        if encoded_len > super::evidence::MAX_EVIDENCE_ADMISSION_BYTES {
            return Err(eyre!(
                "committed native Sumeragi evidence contains an oversized individual proof"
            ));
        }
        retained_evidence_bytes = super::evidence::checked_evidence_byte_sum(
            retained_evidence_bytes,
            [encoded_len],
            super::evidence::MAX_COMMITTED_EVIDENCE_BYTES,
        )
        .ok_or_else(|| {
            eyre!("bounded native Sumeragi evidence table exceeds its proof-byte capacity")
        })?;
    }
    let incoming_evidence_bytes = super::evidence::checked_evidence_byte_sum(
        0,
        effects
            .evidence_admissions
            .iter()
            .map(super::evidence::evidence_encoded_len),
        super::evidence::MAX_EVIDENCE_ADMISSION_BYTES,
    )
    .ok_or_else(|| eyre!("native Sumeragi evidence admission batch exceeds its byte capacity"))?;
    if super::evidence::checked_evidence_byte_sum(
        retained_evidence_bytes,
        [incoming_evidence_bytes],
        super::evidence::MAX_COMMITTED_EVIDENCE_BYTES,
    )
    .is_none()
    {
        return Err(eyre!(
            "bounded native Sumeragi evidence table has no reclaimable proof-byte capacity"
        ));
    }
    for (evidence, admitted) in effects.evidence_admissions.iter().zip(admitted) {
        let key = admitted.key();
        if tx.world.consensus_evidence.get(&key).is_some() {
            return Err(eyre::eyre!(
                "native Sumeragi evidence was already admitted by a committed block"
            ));
        }
        tx.world.consensus_evidence.insert(
            key,
            admitted.record(evidence, current_height, current_view, now_ms)?,
        );
    }
    for action in &effects.penalty_actions {
        match action {
            NposPenaltyAction::ConsensusSlash(action) => {
                ensure_evidence_penalty_is_unresolved(tx, &action.evidence_key)?;
                let record = tx
                    .world
                    .consensus_evidence
                    .get(&action.evidence_key)
                    .expect("validated unresolved evidence exists");
                if !record.attribution.offenders.iter().any(|offender| {
                    offender.signer == action.signer && offender.peer_id == action.peer_id
                }) {
                    return Err(eyre!(
                        "mandatory slash does not name an original proven signer"
                    ));
                }
                let liability = ConsensusSlashLiability::from_attribution(
                    &record.attribution,
                    record.recorded_at_height,
                    action.signer,
                )
                .ok_or_else(|| eyre!("mandatory slash has no original monetary custody"))?;
                if matches!(liability, ConsensusSlashLiability::Root(_))
                    && !tx.is_lane_active_for_authority(action.lane_id)
                {
                    return Err(eyre!(
                        "consensus slash targets a lane made inactive by block execution"
                    ));
                }
                let share_keys = stake_index
                    .expect("validated slash controls carry their original stake index")
                    .share_keys(action.lane_id, &action.validator);
                match mode {
                    EffectsApplicationMode::Commit => apply_indexed_consensus_slash_to_validator(
                        tx,
                        action.lane_id,
                        &action.validator,
                        action.slash_id,
                        &action.amount,
                        now_ms,
                        liability,
                        share_keys,
                    )?,
                    #[cfg(test)]
                    EffectsApplicationMode::ValidateOnly => {
                        apply_indexed_slash_to_validator_without_observability(
                            tx,
                            action.lane_id,
                            &action.validator,
                            action.slash_id,
                            &action.amount,
                            now_ms,
                            liability,
                            share_keys,
                        )?;
                    }
                }
                outcome.slashed = outcome.slashed.saturating_add(1);
            }
            NposPenaltyAction::MarkConsensusEvidenceApplied(action) => {
                if action.height != current_height {
                    return Err(eyre!(
                        "consensus evidence-applied marker has the wrong block height"
                    ));
                }
                ensure_evidence_penalty_is_unresolved(tx, &action.evidence_key)?;
                let mut record = tx
                    .world
                    .consensus_evidence
                    .get(&action.evidence_key)
                    .cloned()
                    .expect("validated unresolved evidence exists");
                record.penalty_status = EvidencePenaltyStatus::Applied {
                    height: action.height,
                };
                tx.world
                    .consensus_evidence
                    .insert(action.evidence_key, record);
                outcome.applied = outcome.applied.saturating_add(1);
            }
        }
    }
    Ok(outcome)
}
fn ensure_evidence_penalty_is_unresolved(
    tx: &StateTransaction<'_, '_>,
    evidence_key: &Hash,
) -> Result<()> {
    let record = tx
        .world
        .consensus_evidence
        .get(evidence_key)
        .ok_or_else(|| eyre!("consensus penalty action references missing evidence"))?;
    match record.penalty_status {
        EvidencePenaltyStatus::Pending => {}
        EvidencePenaltyStatus::Applied { .. } => {
            return Err(eyre!(
                "consensus penalty action references already applied evidence"
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
fn penalty_staking_fixture_ids() -> (
    iroha_data_model::asset::AssetDefinitionId,
    AccountId,
    AccountId,
) {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::parameter::system::SumeragiNposParameters;

    let account = |seed: u8| {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic penalty-custody key");
        AccountId::new(key.public_key().clone())
    };
    let asset_definition = SumeragiNposParameters::default().xor_asset_definition_id;
    (asset_definition, account(0xE1), account(0xE2))
}

#[cfg(test)]
fn penalty_staking_fixture_header() -> BlockHeader {
    BlockHeader::new(
        core::num::NonZeroU64::new(1).expect("non-zero penalty fixture height"),
        None,
        None,
        1,
        0,
    )
}

/// Install the governed stake asset and distinct escrow/slash-sink accounts used by
/// Sumeragi penalty tests.
///
/// The setup is committed through a real world overlay so asset indexes and the
/// definition incarnation stay consistent with production instruction execution.
#[cfg(test)]
pub(crate) fn configure_penalty_staking_state_for_tests(state: &mut State) {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::{
        account::Account,
        asset::{AssetBalancePolicy, AssetDefinition},
        isi::Register,
    };

    let (asset_definition, escrow, slash_sink) = penalty_staking_fixture_ids();
    assert_ne!(
        escrow, slash_sink,
        "penalty fixture must exercise an actual escrow-to-sink movement"
    );
    let mut nexus = state.nexus_snapshot();
    nexus.staking.stake_asset_id = asset_definition.to_string();
    nexus.staking.stake_escrow_account_id = escrow.to_string();
    nexus.staking.slash_sink_account_id = slash_sink.to_string();
    state
        .set_nexus(nexus)
        .expect("install penalty staking custody configuration");

    let mut state_block = state.block(penalty_staking_fixture_header());
    let mut transaction = state_block.transaction();
    Register::account(Account::new(escrow.clone()))
        .execute(&escrow, &mut transaction)
        .expect("register penalty stake escrow account");
    Register::account(Account::new(slash_sink))
        .execute(&escrow, &mut transaction)
        .expect("register penalty slash sink account");
    Register::asset_definition(AssetDefinition::new(
        asset_definition,
        "XOR",
        iroha_primitives::numeric::NumericSpec::fractional(9),
        AssetBalancePolicy::Global,
        None,
    ))
    .execute(&escrow, &mut transaction)
    .expect("register penalty stake asset definition");
    transaction.apply();
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit penalty staking custody fixture");
}

/// Seed one validator with an account, an exactly backed escrow balance, and
/// the matching retained validator/share and exact custody rows needed by the slash executor.
#[cfg(test)]
pub(crate) fn seed_penalty_validator_for_tests(
    state: &State,
    lane_id: LaneId,
    peer: &PeerId,
    stake: Quantity,
) -> AccountId {
    use crate::smartcontracts::{Execute as _, isi::staking::prepare_stake_custody_credit};
    use iroha_data_model::{
        account::Account,
        asset::AssetId,
        isi::{Mint, Register},
        nexus::{PublicLaneStakeShare, PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    };
    use iroha_model_base::metadata::Metadata;

    assert!(!stake.is_zero(), "penalty validator stake must be non-zero");
    let (asset_definition, escrow, _slash_sink) = penalty_staking_fixture_ids();
    let validator = AccountId::new(peer.public_key().clone());
    let mut state_block = state.block(penalty_staking_fixture_header());
    let mut transaction = state_block.transaction();
    if transaction.world.accounts.get(&validator).is_none() {
        Register::account(Account::new(validator.clone()))
            .execute(&validator, &mut transaction)
            .expect("register penalty validator account");
    }
    let escrow_asset = AssetId::new(asset_definition, escrow.clone());
    Mint::asset_quantity(stake.clone(), escrow_asset.clone())
        .execute(&escrow, &mut transaction)
        .expect("mint exact penalty stake into escrow");
    let balance = transaction
        .world
        .assets
        .get(&escrow_asset)
        .expect("minted penalty escrow exists")
        .as_ref()
        .clone();
    assert!(
        transaction
            .world
            .public_lane_stake_custody
            .get(&(lane_id, validator.clone()))
            .is_none(),
        "penalty validator fixture must not replace existing custody"
    );
    prepare_stake_custody_credit(
        &transaction.world,
        lane_id,
        &validator,
        &escrow_asset,
        &stake,
        &balance,
    )
    .expect("reserve the exact minted validator stake")
    .apply(&mut transaction.world);
    assert!(
        transaction
            .world
            .public_lane_validators
            .insert(
                (lane_id, validator.clone()),
                PublicLaneValidatorRecord {
                    lane_id,
                    validator: validator.clone(),
                    peer_id: peer.clone(),
                    stake_account: validator.clone(),
                    total_stake: stake.clone(),
                    self_stake: stake.clone(),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            )
            .is_none(),
        "penalty validator fixture must not replace an existing row"
    );
    assert!(
        transaction
            .world
            .public_lane_stake_shares
            .insert(
                (lane_id, validator.clone(), validator.clone()),
                PublicLaneStakeShare {
                    lane_id,
                    validator: validator.clone(),
                    staker: validator.clone(),
                    bonded: stake,
                    pending_unbonds: BTreeMap::new(),
                    metadata: Metadata::default(),
                },
            )
            .is_none(),
        "penalty validator fixture must not replace an existing stake share"
    );
    transaction.apply();
    state_block
        .commit_world_overlay_for_testing()
        .expect("commit exactly backed penalty validator fixture");
    validator
}

/// Install explicit accepted penalty-kernel prestate for an original payload pool test.
/// Native evidence admission and offence authentication have separate real-history controls.
#[cfg(test)]
pub(crate) fn pending_payload_penalty_fixture(state: &State) -> (Hash, usize) {
    let key = tests::insert_evidence(state, tests::fixture_vote_evidence(1, 0), 1);
    (key, std::mem::size_of::<PendingPenaltyEvidence>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::staking::apply_slash_to_validator_without_observability,
        state::{State, StateBlock, World},
        sumeragi::evidence::evidence_key,
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
    use iroha_data_model::{
        NetworkId,
        asset::{AssetDefinitionId, AssetId},
        block::{
            BlockHeader,
            consensus::{Evidence, EvidenceRecord, ValidatorIndex},
        },
        nexus::{
            LaneCatalog, LaneConfig, LaneVisibility, PublicLaneStakeShare, PublicLaneUnbonding,
        },
        parameter::{Parameter, system::SumeragiNposParameters},
        prelude::AccountId,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::topology::LaneId;
    use iroha_primitives::numeric::Quantity;
    use std::num::{NonZeroU32, NonZeroU64};
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("penalty fixture key generation should succeed")
    }
    fn penalty_staking_ids() -> (AssetDefinitionId, AccountId, AccountId) {
        penalty_staking_fixture_ids()
    }
    fn fresh_state() -> State {
        let mut state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        configure_penalty_staking_state_for_tests(&mut state);
        state
    }

    /// Execute real signed NPoS genesis before testing a finalized slash operation.
    /// Component evidence below remains explicit fixture prestate; no retired sidecar
    /// substitutes for the native committed authority required by monetary execution.
    fn native_penalty_state() -> State {
        use crate::sumeragi::{startup, test_chain::signed_genesis_fixture_for_state};
        use iroha_data_model::{
            IntoKeyValue as _, Registrable as _, account::Account, domain::Domain,
            parameter::system::ConsensusMode,
        };
        use iroha_model_base::chain::ChainId;

        let key = KeyPair::try_from_seed(vec![0xEF; 32], Algorithm::Ed25519).unwrap();
        let authority = AccountId::new(key.public_key().clone());
        let chain_id = ChainId::from("native-penalty-custody-fixture");
        let validators = roster_keys()
            .iter()
            .map(|key| {
                (
                    PeerId::new(key.public_key().clone()),
                    iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let (genesis, state) = signed_genesis_fixture_for_state(
            &chain_id,
            &key,
            &validators,
            Vec::new(),
            1,
            Some(SumeragiNposParameters {
                slashing_delay_blocks: 1,
                ..SumeragiNposParameters::default()
            }),
            |network| {
                let seed = fresh_state();
                let nexus = seed.nexus_snapshot();
                let mut world = seed.world;
                let domain = iroha_genesis::GENESIS_DOMAIN_ID.clone();
                world.insert_domain_for_testing(
                    domain.clone(),
                    Domain::new(domain).build(&authority),
                );
                let (id, account) = Account::new(authority.clone())
                    .build(&authority)
                    .into_key_value();
                world.accounts.insert(id, account);
                let mut state = State::new_with_chain_and_network_id_for_testing(
                    world,
                    Kura::blank_kura_for_testing(),
                    LiveQueryStore::start_test(),
                    chain_id.clone(),
                    network,
                );
                state
                    .set_nexus(nexus)
                    .expect("exact network XOR custody configuration");
                state
            },
        )
        .expect("signed native NPoS genesis binds its original staking custody policies");
        assert_eq!(
            state.view().height(),
            0,
            "policy derivation must not publish"
        );
        assert_eq!(
            state.network_id_ref(),
            &NetworkId::from_genesis_hash(genesis.hash()),
            "the final State belongs to the policy-bound original signed genesis"
        );
        startup::apply_genesis(&state, genesis, &authority, ConsensusMode::Npos, None)
            .expect("original executed native genesis and authority");
        assert_eq!(state.view().height(), 1);
        state
    }

    fn fresh_state_with_shared_public_staking_lanes() -> State {
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("non-zero lane count"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "penalty-sibling".to_owned(),
                    visibility: LaneVisibility::Public,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("shared public penalty lane catalog");
        let mut state = State::new_with_nexus_for_testing(
            World::default(),
            nexus,
            LiveQueryStore::start_test(),
        );
        configure_penalty_staking_state_for_tests(&mut state);
        state
    }

    fn roster_keys() -> Vec<KeyPair> {
        let mut keys = (0_u8..4)
            .map(|index| {
                KeyPair::try_from_seed(vec![0xD0 + index; 32], Algorithm::BlsNormal)
                    .expect("deterministic penalty-roster BLS key")
            })
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        keys
    }
    fn roster() -> Vec<PeerId> {
        roster_keys()
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect()
    }
    /// Signed native proof used only as explicit prestate for the penalty kernel.
    /// Native admission and restored attribution are tested against actual history separately.
    pub(super) fn fixture_vote_evidence(signer: ValidatorIndex, view: u64) -> Evidence {
        use iroha_sumeragi::{
            message::{Evidence as NativeEvidence, Vote, VoteKind},
            types::{EpochId, Hash32, Signature as NativeSignature},
        };
        let keys = roster_keys();
        let vote = |seed: u8| {
            let mut vote = Vote {
                kind: VoteKind::Prepare,
                instance: Hash32([0x41; 32]),
                epoch: EpochId {
                    epoch: 0,
                    context: Hash32([0x42; 32]),
                },
                height: 1,
                view,
                block_hash: Hash32([seed; 32]),
                result: Hash32([0x43; 32]),
                signer,
                sig: NativeSignature([0; iroha_sumeragi::types::SIGNATURE_LEN]),
            };
            vote.sig = NativeSignature(
                Signature::new(keys[signer as usize].private_key(), &vote.preimage())
                    .payload()
                    .try_into()
                    .unwrap(),
            );
            vote
        };
        Evidence::from_native(&NativeEvidence::VoteEquivocation(vote(0x31), vote(0x32))).unwrap()
    }

    fn set_commit_topology(state: &State, peers: Vec<PeerId>) {
        let mut topology = state.commit_topology.block();
        topology.clear();
        topology.extend(peers);
        topology.commit();
    }
    pub(super) fn insert_evidence(
        state: &State,
        evidence: Evidence,
        recorded_at_height: u64,
    ) -> Hash {
        let key = evidence_key(&evidence);
        let iroha_sumeragi::message::Evidence::VoteEquivocation(first, _) =
            evidence.decode_native().unwrap()
        else {
            panic!("component vote proof");
        };
        let attribution = iroha_data_model::block::consensus::EvidenceAttribution {
            scope: iroha_data_model::block::consensus::EvidenceScope::Root,
            instance: first.instance.0,
            height: first.height,
            epoch: first.epoch.epoch,
            context_id: first.epoch.context.0,
            authority_generation: [0x44; 32],
            offenders: vec![iroha_data_model::block::consensus::EvidenceOffender {
                lane_stake: None,
                signer: first.signer,
                peer_id: roster()[first.signer as usize].clone(),
            }],
            safety_violation: false,
        };
        let record = EvidenceRecord {
            evidence,
            attribution,
            recorded_at_height,
            recorded_at_view: 0,
            recorded_at_ms: recorded_at_height.saturating_mul(1_000),
            penalty_status: EvidencePenaltyStatus::Pending,
        };
        let mut block = state.world.consensus_evidence.block();
        let record = crate::state::RetainedEvidenceRecord::from_fixture(
            record,
            &state.ivm_execution_budget(),
        )
        .unwrap();
        block.insert(key, record);
        block.commit();
        key
    }

    fn fund_penalty_escrow(
        state: &State,
        lane_id: LaneId,
        validator: &AccountId,
        amount: &Quantity,
    ) {
        use crate::smartcontracts::{Execute as _, isi::staking::prepare_stake_custody_credit};
        use iroha_data_model::isi::Mint;

        let (asset_definition, escrow, _) = penalty_staking_ids();
        let escrow_asset = AssetId::new(asset_definition, escrow.clone());
        let mut state_block = state.block(penalty_staking_fixture_header());
        let mut transaction = state_block.transaction();
        Mint::asset_quantity(amount.clone(), escrow_asset.clone())
            .execute(&escrow, &mut transaction)
            .expect("mint extra delegated penalty stake into escrow");
        let balance = transaction
            .world
            .assets
            .get(&escrow_asset)
            .expect("minted penalty escrow exists")
            .as_ref()
            .clone();
        prepare_stake_custody_credit(
            &transaction.world,
            lane_id,
            validator,
            &escrow_asset,
            amount,
            &balance,
        )
        .expect("reserve the exact additional delegated stake")
        .apply(&mut transaction.world);
        transaction.apply();
        state_block
            .commit_world_overlay_for_testing()
            .expect("commit delegated stake custody fixture");
    }

    fn add_validator_record_on_lane(state: &State, lane_id: LaneId, peer: &PeerId) -> AccountId {
        seed_penalty_validator_for_tests(state, lane_id, peer, Quantity::from(10_000_u64))
    }

    fn add_validator_record(state: &State, peer: &PeerId) -> AccountId {
        add_validator_record_on_lane(state, LaneId::SINGLE, peer)
    }

    fn install_one_block_delay_npos(state: &State) {
        let mut parameters = state.world.parameters.block();
        let npos = SumeragiNposParameters {
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        };
        parameters.set_parameter(Parameter::Custom(npos.into_custom_parameter()));
        parameters.commit();
    }
    fn penalty_header(height: u64) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(height).expect("non-zero penalty test height"),
            None,
            None,
            height.saturating_mul(1_000),
            0,
        )
    }
    fn height_two_state_block(state: &State) -> StateBlock<'_> {
        state.block(penalty_header(2))
    }
    fn retire_primary_lane_in_candidate(state_block: &mut StateBlock<'_>) {
        let catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("non-zero lane count"),
            vec![LaneConfig {
                id: LaneId::new(1),
                alias: "post-execution-lane".to_owned(),
                ..LaneConfig::default()
            }],
        )
        .expect("sparse post-execution lane catalog");
        state_block.nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog);
        state_block.nexus.lane_catalog = catalog;
    }
    #[test]
    fn consensus_penalty_delay_does_not_saturate_into_early_eligibility() {
        assert!(consensus_penalty_is_due(u64::MAX, 0, u64::MAX));
        assert!(consensus_penalty_is_due(u64::MAX - 1, 1, u64::MAX));
        assert!(!consensus_penalty_is_due(u64::MAX, 1, u64::MAX));
        assert!(!consensus_penalty_is_due(u64::MAX - 1, 2, u64::MAX));
    }
    #[test]
    fn parent_snapshot_two_pass_stake_index_retains_exact_exposure() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peers = roster();
        let first = add_validator_record(&state, &peers[0]);
        let second = add_validator_record(&state, &peers[1]);
        let delegator = AccountId::new(
            KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
                .expect("deterministic penalty delegator")
                .public_key()
                .clone(),
        );
        let nested_key_bytes = |account: &AccountId| {
            let mut bytes = 0_usize;
            account
                .for_each_admission_clone_layout(|layout| bytes += layout.size())
                .expect("fixture account has canonical key material");
            bytes
        };
        let expected_nested_key_bytes = 4 * nested_key_bytes(&first)
            + 3 * nested_key_bytes(&second)
            + nested_key_bytes(&delegator);
        let pending_id = Hash::new(b"indexed pending unbond");
        {
            let key = (LaneId::SINGLE, first.clone(), first.clone());
            let mut block = state.world.public_lane_stake_shares.block();
            let mut share = block.get(&key).cloned().expect("first self-share exists");
            share.bonded = Quantity::from(9_000_u64);
            share.pending_unbonds.insert(
                pending_id,
                PublicLaneUnbonding {
                    request_id: pending_id,
                    amount: Quantity::from(1_000_u64),
                    release_at_ms: 10_000,
                    slashable_through_height: 1,
                    liability_release_height: 3,
                },
            );
            block.insert(key, share);
            block.insert(
                (LaneId::SINGLE, first.clone(), delegator.clone()),
                PublicLaneStakeShare {
                    lane_id: LaneId::SINGLE,
                    validator: first.clone(),
                    staker: delegator,
                    bonded: Quantity::from(3_000_u64),
                    pending_unbonds: BTreeMap::new(),
                    metadata: Metadata::default(),
                },
            );
            block.commit();
        }
        fund_penalty_escrow(&state, LaneId::SINGLE, &first, &Quantity::from(3_000_u64));
        {
            let key = (LaneId::SINGLE, first.clone());
            let mut block = state.world.public_lane_validators.block();
            let mut record = block.get(&key).cloned().expect("first validator exists");
            record.total_stake = Quantity::from(12_000_u64);
            record.self_stake = Quantity::from(9_000_u64);
            block.insert(key, record);
            block.commit();
        }

        let view = state.view();
        let snapshot = PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        )
        .expect("canonical multi-validator stake snapshot");

        assert_eq!(snapshot.stake_share_row_visits, 6);
        let (asset_definition, escrow, _) = penalty_staking_ids();
        let escrow_asset = AssetId::new(asset_definition, escrow);
        assert_eq!(
            view.world
                .public_lane_stake_custody()
                .get(&(LaneId::SINGLE, first.clone())),
            Some(&(escrow_asset.clone(), Quantity::from(13_000_u64))),
            "both bonded and pending delegated liabilities retain exact custody"
        );
        assert_eq!(
            view.world
                .public_lane_stake_custody()
                .get(&(LaneId::SINGLE, second.clone())),
            Some(&(escrow_asset.clone(), Quantity::from(10_000_u64)))
        );
        assert_eq!(
            view.world.public_lane_stake_reserves().get(&escrow_asset),
            Some(&Quantity::from(23_000_u64)),
            "shared escrow reserves sum every validator's liability exactly once"
        );
        assert_eq!(
            view.world
                .assets()
                .get(&escrow_asset)
                .map(|balance| balance.as_ref().clone()),
            Some(Quantity::from(23_000_u64))
        );
        let first_locator = snapshot
            .validator_map
            .get(peers[0].public_key())
            .and_then(|locators| locators.first())
            .expect("first validator indexed");
        assert_eq!(first_locator.validator, first);
        assert_eq!(
            original_slashable_exposure(
                &snapshot.stake_index,
                first_locator.lane_id,
                &first_locator.validator
            )
            .unwrap(),
            &Quantity::from(13_000_u64)
        );
        let second_locator = snapshot
            .validator_map
            .get(peers[1].public_key())
            .and_then(|locators| locators.first())
            .expect("second validator indexed");
        assert_eq!(second_locator.validator, second);
        assert_eq!(
            original_slashable_exposure(
                &snapshot.stake_index,
                second_locator.lane_id,
                &second_locator.validator
            )
            .unwrap(),
            &Quantity::from(10_000_u64)
        );
        assert_eq!(
            state.stake_index_budget().reserved_bytes(),
            3 * std::mem::size_of::<crate::smartcontracts::isi::staking::PublicLaneStakeShareKey>()
                + 2 * std::mem::size_of::<(
                    LaneId,
                    AccountId,
                    std::ops::Range<usize>,
                    Quantity,
                    Quantity,
                    Quantity,
                    Option<Quantity>,
                )>()
                + expected_nested_key_bytes
                // Eight account-key charges and four aggregate charges per group.
                + 16 * std::mem::size_of::<iroha_allocation::AllocationCharge>()
                // Both groups retain their bonded, self and exposure limbs;
                // only the first group has a nonzero pending magnitude.
                + 7 * std::mem::size_of::<usize>()
        );
        drop(snapshot);
        assert_eq!(state.stake_index_budget().reserved_bytes(), 0);
    }
    #[test]
    fn parent_stake_index_backing_refusal_preserves_source_and_retries_after_release() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peers = roster();
        let validator = add_validator_record(&state, &peers[0]);
        let share_key = (LaneId::SINGLE, validator.clone(), validator.clone());
        let original = state
            .world
            .public_lane_stake_shares
            .view()
            .get(&share_key)
            .cloned()
            .expect("accepted source share");
        let budget = state.stake_index_budget();
        let mut validator_key_bytes = 0_usize;
        validator
            .for_each_admission_clone_layout(|layout| validator_key_bytes += layout.size())
            .expect("fixture validator has canonical key material");
        let backing = std::mem::size_of::<
            crate::smartcontracts::isi::staking::PublicLaneStakeShareKey,
        >() + std::mem::size_of::<(
            LaneId,
            AccountId,
            std::ops::Range<usize>,
            Quantity,
            Quantity,
            Quantity,
            Option<Quantity>,
        )>() + 3
            * (validator_key_bytes + std::mem::size_of::<iroha_allocation::AllocationCharge>())
            + 4 * std::mem::size_of::<iroha_allocation::AllocationCharge>()
            + 3 * std::mem::size_of::<usize>();
        let exact_held = budget
            .try_reserve_bytes(budget.limit_bytes() - backing)
            .expect("leave exact combined backing in original pool");
        let view = state.view();
        let exact =
            PenaltyApplier::parent_snapshot(&view, 2, state.evidence_preparation_budget(), budget)
                .expect("exact remaining combined backing admits one validator");
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(exact);
        drop(exact_held);
        assert_eq!(budget.reserved_bytes(), 0);
        let held_bytes = budget.limit_bytes() - backing + 1;
        let held = budget
            .try_reserve_bytes(held_bytes)
            .expect("hold original index pool capacity");
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            budget,
        ) {
            Ok(_) => panic!("one byte below the combined backings must refuse locally"),
            Err(error) => error,
        };
        let local = error
            .downcast_ref::<EvidencePreparationError>()
            .expect("typed local stake-index capacity refusal");
        assert!(matches!(
            local,
            EvidencePreparationError::Admission(AllocationRefusal::Capacity {
                requested_bytes,
                ..
            }) if *requested_bytes == backing
        ));
        assert!(local.release_wait().is_some());
        assert_eq!(budget.reserved_bytes(), held_bytes);
        assert_eq!(
            view.world.public_lane_stake_shares().get(&share_key),
            Some(&original)
        );
        drop(held);
        let snapshot =
            PenaltyApplier::parent_snapshot(&view, 2, state.evidence_preparation_budget(), budget)
                .expect("same-State retry after original owner releases capacity");
        assert_eq!(budget.reserved_bytes(), backing);
        assert_eq!(
            snapshot.stake_index.share_keys(LaneId::SINGLE, &validator),
            &[share_key]
        );
        drop(snapshot);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn parent_snapshot_rejects_corrupt_stake_share_outside_candidate_set() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let validator = AccountId::new(
            KeyPair::try_from_seed(vec![0xA6; 32], Algorithm::Ed25519)
                .expect("deterministic corrupt-share validator")
                .public_key()
                .clone(),
        );
        let staker = AccountId::new(
            KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::Ed25519)
                .expect("deterministic corrupt-share staker")
                .public_key()
                .clone(),
        );
        let share = PublicLaneStakeShare {
            lane_id: LaneId::new(1),
            validator: validator.clone(),
            staker: staker.clone(),
            bonded: Quantity::from(1_u64),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        };
        let mut block = state.world.public_lane_stake_shares.block();
        block.insert((LaneId::SINGLE, validator, staker), share);
        block.commit();

        let view = state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("a corrupt share row must fail the complete parent snapshot"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("failed to index slashable public-lane stake exposure"),
            "unexpected rejection: {error}"
        );
        assert!(
            format!("{error:#}").contains("stake share does not match its storage key"),
            "unexpected rejection chain: {error:#}"
        );
    }
    #[test]
    fn parent_snapshot_rejects_orphan_stake_share_aggregate() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let validator = AccountId::new(
            KeyPair::try_from_seed(vec![0xA8; 32], Algorithm::Ed25519)
                .expect("deterministic orphan-share validator")
                .public_key()
                .clone(),
        );
        let share = PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            bonded: Quantity::from(1_u64),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        };
        let key = (LaneId::SINGLE, validator.clone(), validator);
        let mut block = state.world.public_lane_stake_shares.block();
        block.insert(key.clone(), share.clone());
        block.commit();

        let view = state.view();
        let empty_budget = AllocationBudget::new(0);
        let preflight_error = match PublicLaneStakeIndex::from_world(
            view.world(),
            view.nexus.staking.max_stake_shares_per_validator.get(),
            view.nexus.staking.max_pending_unbonds_per_share.get(),
            &empty_budget,
        ) {
            Ok(_) => panic!("an orphan stake-share group must fail before allocation"),
            Err(error) => error,
        };
        assert!(
            format!("{preflight_error:#}").contains("has no validator record"),
            "unexpected pre-allocation rejection: {preflight_error:#}"
        );
        assert_eq!(empty_budget.reserved_bytes(), 0);
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("an orphan stake-share aggregate must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("has no validator record"),
            "unexpected rejection: {error:#}"
        );
        assert_eq!(state.stake_index_budget().reserved_bytes(), 0);
        assert_eq!(
            view.world.public_lane_stake_shares().get(&key),
            Some(&share)
        );
    }
    #[test]
    fn parent_snapshot_enforces_stake_share_and_pending_unbond_caps() {
        let mut share_capped_state = fresh_state();
        share_capped_state
            .nexus
            .get_mut()
            .staking
            .max_stake_shares_per_validator = NonZeroU32::new(1).expect("non-zero stake-share cap");
        install_one_block_delay_npos(&share_capped_state);
        let peers = roster();
        let validator = add_validator_record(&share_capped_state, &peers[0]);
        let delegator = AccountId::new(
            KeyPair::try_from_seed(vec![0xA9; 32], Algorithm::Ed25519)
                .expect("deterministic capped-share delegator")
                .public_key()
                .clone(),
        );
        let share = PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: delegator.clone(),
            bonded: Quantity::from(1_u64),
            pending_unbonds: BTreeMap::new(),
            metadata: Metadata::default(),
        };
        let mut block = share_capped_state.world.public_lane_stake_shares.block();
        block.insert((LaneId::SINGLE, validator, delegator), share);
        block.commit();
        let view = share_capped_state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            share_capped_state.evidence_preparation_budget(),
            share_capped_state.stake_index_budget(),
        ) {
            Ok(_) => panic!("stake-share cap overflow must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("exceeds stake-share capacity"),
            "unexpected rejection: {error:#}"
        );

        let mut pending_capped_state = fresh_state();
        pending_capped_state
            .nexus
            .get_mut()
            .staking
            .max_pending_unbonds_per_share =
            NonZeroU32::new(1).expect("non-zero pending-unbond cap");
        install_one_block_delay_npos(&pending_capped_state);
        let validator = add_validator_record(&pending_capped_state, &peers[0]);
        let key = (LaneId::SINGLE, validator.clone(), validator);
        let mut block = pending_capped_state.world.public_lane_stake_shares.block();
        let mut share = block.get(&key).cloned().expect("capped self-share exists");
        for marker in [0xB0_u8, 0xB1_u8] {
            let request_id = Hash::new([marker]);
            share.pending_unbonds.insert(
                request_id,
                PublicLaneUnbonding {
                    request_id,
                    amount: Quantity::from(1_u64),
                    release_at_ms: 10_000,
                    slashable_through_height: 1,
                    liability_release_height: 3,
                },
            );
        }
        block.insert(key, share);
        block.commit();
        let view = pending_capped_state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            pending_capped_state.evidence_preparation_budget(),
            pending_capped_state.stake_index_budget(),
        ) {
            Ok(_) => panic!("pending-unbond cap overflow must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("exceeds pending-unbond capacity"),
            "unexpected rejection: {error:#}"
        );
    }
    #[test]
    fn parent_snapshot_enforces_retained_validator_capacity() {
        let state = native_penalty_state();
        // This negative fixture exceeds the retained, consensus-visible owner
        // capacity. Changing the local Nexus cache cannot change that policy.
        let mut runtime = state.canonical_runtime.block();
        runtime.get_mut().owner_policy.max_validators = 1;
        runtime.commit();
        assert_eq!(state.nexus_snapshot().staking.max_validators.get(), 1);
        install_one_block_delay_npos(&state);
        let peers = roster();
        add_validator_record(&state, &peers[0]);
        add_validator_record(&state, &peers[1]);

        let view = state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("validator-cap overflow must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("exceeds retained validator capacity"),
            "unexpected rejection: {error:#}"
        );
    }
    #[test]
    fn parent_snapshot_rejects_non_canonical_pending_unbond() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peers = roster();
        let validator = add_validator_record(&state, &peers[0]);
        let key = (LaneId::SINGLE, validator.clone(), validator);
        let map_key = Hash::new(b"pending map key");
        let payload_id = Hash::new(b"different pending payload id");
        let mut block = state.world.public_lane_stake_shares.block();
        let mut share = block.get(&key).cloned().expect("self-share exists");
        share.pending_unbonds.insert(
            map_key,
            PublicLaneUnbonding {
                request_id: payload_id,
                amount: Quantity::from(1_u64),
                release_at_ms: 10_000,
                slashable_through_height: 1,
                liability_release_height: 3,
            },
        );
        block.insert(key, share);
        block.commit();

        let view = state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("a non-canonical pending unbond must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("pending unbond is non-canonical"),
            "unexpected rejection: {error:#}"
        );
    }
    #[test]
    fn parent_snapshot_rejects_non_validator_self_stake_account() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peers = roster();
        let validator = add_validator_record(&state, &peers[0]);
        let foreign_stake_account = AccountId::new(
            KeyPair::try_from_seed(vec![0xB2; 32], Algorithm::Ed25519)
                .expect("deterministic foreign stake account")
                .public_key()
                .clone(),
        );
        let key = (LaneId::SINGLE, validator);
        let mut block = state.world.public_lane_validators.block();
        let mut record = block.get(&key).cloned().expect("validator record exists");
        record.stake_account = foreign_stake_account;
        block.insert(key, record);
        block.commit();

        let view = state.view();
        let empty_budget = AllocationBudget::new(0);
        let preflight_error = match PublicLaneStakeIndex::from_world(
            view.world(),
            view.nexus.staking.max_stake_shares_per_validator.get(),
            view.nexus.staking.max_pending_unbonds_per_share.get(),
            &empty_budget,
        ) {
            Ok(_) => panic!("a foreign stake account must fail before allocation"),
            Err(error) => error,
        };
        assert!(
            format!("{preflight_error:#}")
                .contains("stake account must match the validator account"),
            "unexpected pre-allocation rejection: {preflight_error:#}"
        );
        assert_eq!(empty_budget.reserved_bytes(), 0);
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("a foreign self-stake account must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("stake account must match the validator account"),
            "unexpected rejection: {error:#}"
        );
    }
    #[test]
    fn parent_snapshot_rejects_validator_totals_that_disagree_with_index() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peers = roster();
        let validator = add_validator_record(&state, &peers[0]);
        let key = (LaneId::SINGLE, validator);
        let mut block = state.world.public_lane_validators.block();
        let mut record = block.get(&key).cloned().expect("validator record exists");
        record.total_stake = Quantity::from(9_999_u64);
        block.insert(key, record);
        block.commit();

        let view = state.view();
        let error = match PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        ) {
            Ok(_) => panic!("mismatched validator totals must fail the parent snapshot"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}")
                .contains("public-lane validator totals do not match canonical stake shares"),
            "unexpected rejection: {error:#}"
        );
    }
    #[test]
    fn admitted_native_attribution_does_not_require_a_kura_reread() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let evidence = fixture_vote_evidence(1, 0);
        let key = insert_evidence(&state, evidence, 1);
        let applier = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        );
        let actions = applier
            .derive_npos_consensus_effects(&penalty_header(2))
            .expect("admitted native attribution is retained")
            .penalty_actions;
        assert!(actions.iter().any(|action| matches!(
            action,
            NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                if mark.evidence_key == key && mark.height == 2
        )));
    }
    #[test]
    fn parent_penalty_plan_retains_only_due_evidence_metadata() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let terminal = insert_evidence(&state, fixture_vote_evidence(2, 1), 1);
        let future = insert_evidence(&state, fixture_vote_evidence(0, 2), 2);
        let mut rows = state.world.consensus_evidence.block();
        let mut terminal_record = rows.get(&terminal).cloned().expect("terminal row exists");
        terminal_record.penalty_status = EvidencePenaltyStatus::Applied { height: 1 };
        rows.insert(terminal, terminal_record);
        rows.commit();

        let view = state.view();
        let snapshot = PenaltyApplier::parent_snapshot(
            &view,
            2,
            state.evidence_preparation_budget(),
            state.stake_index_budget(),
        )
        .expect("bounded parent penalty metadata is valid");
        assert_eq!(snapshot.pending.as_slice().len(), 1);
        assert_eq!(snapshot.pending.as_slice()[0].0.0, due);
        assert_eq!(snapshot.pending.as_slice()[0].0.1, EvidenceScope::Root);
        assert_eq!(snapshot.pending.as_slice()[0].0.2, 1);
        assert_eq!(
            snapshot.pending.as_slice()[0]
                .0
                .5
                .as_ref()
                .map(|(index, _, _, _)| *index),
            Some(1)
        );
        let signer_key_layout =
            pending_peer_key_layout(&frozen_roster[1]).expect("canonical retained peer key layout");
        assert_eq!(signer_key_layout.align(), 1);
        assert_eq!(
            signer_key_layout.size(),
            frozen_roster[1].public_key().to_bytes().1.len() + 1
        );
        assert_eq!(
            state.evidence_preparation_budget().reserved_bytes(),
            std::mem::size_of::<PendingPenaltyEvidence>() + signer_key_layout.size(),
            "the exact due backing and nested peer key retain original charges"
        );
        drop(view);
        drop(snapshot);
        assert_eq!(state.evidence_preparation_budget().reserved_bytes(), 0);

        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_penalty_actions(&penalty_header(2))
        .map(|(actions, _index)| actions)
        .expect("only due parent evidence receives a penalty marker");
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                if mark.evidence_key == due && mark.height == 2
        ));
        assert!(!actions.iter().any(|action| match action {
            NposPenaltyAction::ConsensusSlash(slash) =>
                slash.evidence_key == terminal || slash.evidence_key == future,
            NposPenaltyAction::MarkConsensusEvidenceApplied(mark) =>
                mark.evidence_key == terminal || mark.evidence_key == future,
        }));
    }
    #[test]
    fn validator_map_exact_pool_refusal_retry_move_drop_and_unwind_preserve_source() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let state = fresh_state();
        let peers = roster();
        let validator = add_validator_record(&state, &peers[0]);
        let view = state.view();
        let key = (LaneId::SINGLE, validator.clone());
        let original = view.world.public_lane_validators().get(&key).unwrap();
        let original_peer = original
            .peer_id
            .public_key()
            .try_to_bytes()
            .unwrap()
            .1
            .as_ptr();
        let original_account = validator
            .expect_single_signatory()
            .try_to_bytes()
            .unwrap()
            .1
            .as_ptr();
        let index =
            PublicLaneStakeIndex::from_world(view.world(), 16, 16, state.stake_index_budget())
                .unwrap();
        let demand = ValidatorMapDemand::from_world(&view).unwrap();
        assert_eq!(demand.rows, 1);
        assert_eq!(demand.account_charges, 1);
        let required = demand.retained_bytes().unwrap();
        assert_eq!(
            required,
            std::mem::size_of::<ValidatorLocator>()
                + std::mem::size_of::<AllocationCharge>()
                + original
                    .peer_id
                    .public_key()
                    .retained_allocation_layout()
                    .size()
                + validator
                    .expect_single_signatory()
                    .retained_allocation_layout()
                    .size()
        );
        let budget = AllocationBudget::new(required);
        let held = budget.try_reserve_bytes(1).unwrap();
        let error = ValidatorMap::from_world(&view, &index, &budget)
            .err()
            .unwrap();
        assert!(matches!(error.downcast_ref::<EvidencePreparationError>(),
            Some(EvidencePreparationError::Admission(AllocationRefusal::Capacity { requested_bytes, .. }))
                if *requested_bytes == required));
        assert!(
            error
                .downcast_ref::<EvidencePreparationError>()
                .unwrap()
                .release_wait()
                .is_some()
        );
        assert_eq!(budget.reserved_bytes(), 1);
        assert_eq!(
            view.world.public_lane_validators().get(&key),
            Some(original)
        );
        assert_eq!(
            original
                .peer_id
                .public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .as_ptr(),
            original_peer
        );
        assert_eq!(
            validator
                .expect_single_signatory()
                .try_to_bytes()
                .unwrap()
                .1
                .as_ptr(),
            original_account
        );
        drop(held);
        let map = ValidatorMap::from_world(&view, &index, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), required);
        let rows = map.rows.as_slice().as_ptr();
        let peer = map.get(peers[0].public_key()).unwrap()[0]
            .peer_key
            .get()
            .try_to_bytes()
            .unwrap()
            .1
            .as_ptr();
        assert_ne!(peer, original_peer);
        let moved = std::hint::black_box(map);
        assert_eq!(moved.rows.as_slice().as_ptr(), rows);
        assert_eq!(
            moved.get(peers[0].public_key()).unwrap()[0]
                .peer_key
                .get()
                .try_to_bytes()
                .unwrap()
                .1
                .as_ptr(),
            peer
        );
        assert_eq!(
            moved.get(peers[0].public_key()).unwrap()[0].validator,
            validator
        );
        assert!(moved.get(peers[1].public_key()).is_none());
        assert_eq!(budget.reserved_bytes(), required);
        drop(moved);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _map = ValidatorMap::from_world(&view, &index, &budget).unwrap();
                assert_eq!(budget.reserved_bytes(), required);
                panic!("abandon the original locator plan");
            }))
            .is_err()
        );
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            view.world.public_lane_validators().get(&key),
            Some(original)
        );
    }

    #[test]
    fn validator_map_refusal_preserves_due_evidence_and_committed_escrow_until_retry() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let peer = roster().remove(1);
        let validator = add_validator_record(&state, &peer);
        let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let original = state
            .world
            .consensus_evidence
            .view()
            .get(&due)
            .unwrap()
            .clone();
        let (definition, escrow, _) = penalty_staking_ids();
        let asset = AssetId::new(definition, escrow);
        let before = state
            .world
            .assets
            .view()
            .get(&asset)
            .unwrap()
            .as_ref()
            .clone();
        let map_bytes = ValidatorMapDemand::from_world(&state.view())
            .unwrap()
            .retained_bytes()
            .unwrap();
        let pending_bytes = std::mem::size_of::<PendingPenaltyEvidence>()
            + pending_peer_key_layout(&peer).unwrap().size();
        let budget = state.evidence_preparation_budget();
        let held_bytes = budget.limit_bytes() - pending_bytes - map_bytes + 1;
        let held = budget.try_reserve_bytes(held_bytes).unwrap();
        let applier = PenaltyApplier::new(&state, None);
        let error = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .err()
            .unwrap();
        assert!(matches!(error.downcast_ref::<EvidencePreparationError>(),
            Some(EvidencePreparationError::Admission(AllocationRefusal::Capacity { requested_bytes, .. }))
                if *requested_bytes == map_bytes));
        assert!(
            error
                .downcast_ref::<EvidencePreparationError>()
                .unwrap()
                .release_wait()
                .is_some()
        );
        assert_eq!(budget.reserved_bytes(), held_bytes);
        assert_eq!(state.stake_index_budget().reserved_bytes(), 0);
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original)
        );
        assert_eq!(
            state.world.assets.view().get(&asset).unwrap().as_ref(),
            &before
        );
        drop(held);
        let (actions, index) = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .unwrap();
        assert!(actions.iter().any(|action| matches!(action, NposPenaltyAction::ConsensusSlash(slash)
            if slash.evidence_key == due && slash.validator == validator && slash.amount == Quantity::from(10_000_u64))));
        assert!(actions.iter().any(
            |action| matches!(action, NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
            if mark.evidence_key == due && mark.height == 2)
        ));
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original)
        );
        assert_eq!(
            state.world.assets.view().get(&asset).unwrap().as_ref(),
            &before
        );
        assert_eq!(budget.reserved_bytes(), 0);
        drop(index);
        assert_eq!(state.stake_index_budget().reserved_bytes(), 0);
    }

    #[test]
    fn validator_map_rejects_foreign_or_incomplete_prepaid_backing() {
        let state = fresh_state();
        let peers = roster();
        add_validator_record(&state, &peers[0]);
        let view = state.view();
        let index =
            PublicLaneStakeIndex::from_world(view.world(), 16, 16, state.stake_index_budget())
                .unwrap();
        let demand = ValidatorMapDemand::from_world(&view).unwrap();
        let required = demand.retained_bytes().unwrap();
        let budget = AllocationBudget::new(required);
        let foreign = AllocationBudget::new(required);
        for reservation in [
            foreign.try_reserve_bytes(required).unwrap(),
            budget.try_reserve_bytes(required - 1).unwrap(),
        ] {
            let error = ValidatorMap::from_reservation(&view, &index, demand, &budget, reservation)
                .err()
                .unwrap();
            assert!(matches!(
                error.downcast_ref::<EvidencePreparationError>(),
                Some(EvidencePreparationError::Invariant)
            ));
        }
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
        let map = ValidatorMap::from_world(&view, &index, &budget).unwrap();
        assert_eq!(map.get(peers[0].public_key()).unwrap().len(), 1);
        drop(map);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn validator_map_multisig_partial_clone_refusal_preserves_exact_nested_custody() {
        use iroha_data_model::account::{MultisigMember, MultisigPolicy};

        let first = KeyPair::try_from_seed(vec![0x91; 32], Algorithm::Ed25519).unwrap();
        let second = KeyPair::try_from_seed(vec![0x92; 32], Algorithm::Ed25519).unwrap();
        let account = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                    MultisigMember::new(second.public_key().clone(), 1).unwrap(),
                ],
            )
            .unwrap(),
        );
        let source_members = account.multisig_policy().unwrap().members().as_ptr();
        let mut demand = ValidatorMapDemand::default();
        demand.add(first.public_key(), &account).unwrap();
        assert_eq!(demand.account_charges, 3);
        let account_bytes =
            demand.nested_bytes - first.public_key().retained_allocation_layout().size();
        let ledger_bytes = Layout::array::<AllocationCharge>(demand.account_charges)
            .unwrap()
            .size();
        let budget = AllocationBudget::new(account_bytes + ledger_bytes);
        let mut reservation = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let mut charges =
            ChargedBuffer::from_reservation(demand.account_charges, &mut reservation).unwrap();
        // The members backing and first key exist before the second key's active
        // decoder scope refuses. All matching original credit remains in the ledger.
        let limits =
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 33, usize::MAX);
        let error = norito::core::with_decode_limits_scope(limits, || {
            clone_locator_account(&account, &mut reservation, &mut charges)
        })
        .err()
        .unwrap();
        assert!(matches!(
            error,
            EvidencePreparationError::DecodeScope {
                attempted_bytes: 66,
                limit_bytes: 33
            }
        ));
        assert_eq!(
            account.multisig_policy().unwrap().members().as_ptr(),
            source_members
        );
        assert_eq!(charges.as_slice().len(), demand.account_charges);
        assert_eq!(reservation.remaining_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(charges);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut reservation = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let mut charges =
            ChargedBuffer::from_reservation(demand.account_charges, &mut reservation).unwrap();
        let cloned = clone_locator_account(&account, &mut reservation, &mut charges).unwrap();
        assert_eq!(cloned, account);
        assert_ne!(
            cloned.multisig_policy().unwrap().members().as_ptr(),
            source_members
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(cloned);
        drop(charges);
        drop(reservation);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn validator_map_flat_lookup_matches_peer_lane_account_order_and_per_lane_caps() {
        use iroha_data_model::nexus::{DataSpaceCatalog, DataSpaceMetadata};
        use iroha_model_base::topology::DataSpaceId;

        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).unwrap(),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "second-owner".into(),
                    dataspace_id: DataSpaceId::new(1),
                    visibility: LaneVisibility::Public,
                    ..LaneConfig::default()
                },
            ],
        )
        .unwrap();
        nexus.dataspace_catalog = DataSpaceCatalog::new(
            nexus
                .lane_catalog
                .lanes()
                .iter()
                .map(|lane| DataSpaceMetadata {
                    id: lane.dataspace_id,
                    alias: format!("owner-{}", lane.id.as_u32()),
                    description: None,
                    fault_tolerance: 1,
                })
                .collect(),
        )
        .unwrap();
        let mut state = State::new_with_nexus_for_testing(
            World::default(),
            nexus,
            LiveQueryStore::start_test(),
        );
        configure_penalty_staking_state_for_tests(&mut state);
        state.nexus.get_mut().staking.max_validators = NonZeroU32::new(2).unwrap();
        let peers = roster();
        let first = add_validator_record_on_lane(&state, LaneId::SINGLE, &peers[1]);
        let second = add_validator_record_on_lane(&state, LaneId::SINGLE, &peers[0]);
        add_validator_record_on_lane(&state, LaneId::new(1), &peers[0]);
        {
            let key = (LaneId::SINGLE, first.clone());
            let mut records = state.world.public_lane_validators.block();
            let mut row = records.get(&key).unwrap().clone();
            row.peer_id = peers[0].clone();
            records.insert(key, row);
            records.commit();
        }
        let view = state.view();
        let index =
            PublicLaneStakeIndex::from_world(view.world(), 16, 16, state.stake_index_budget())
                .unwrap();
        let map =
            ValidatorMap::from_world(&view, &index, state.evidence_preparation_budget()).unwrap();
        let mut reference = BTreeMap::<PublicKey, Vec<(LaneId, AccountId)>>::new();
        for ((lane, account), row) in view.world.public_lane_validators().iter() {
            reference
                .entry(row.peer_id.public_key().clone())
                .or_default()
                .push((*lane, account.clone()));
        }
        for (peer, expected) in &mut reference {
            expected.sort();
            let actual = map
                .get(peer)
                .unwrap()
                .iter()
                .map(|row| (row.lane_id, row.validator.clone()))
                .collect::<Vec<_>>();
            assert_eq!(actual.as_slice(), expected.as_slice());
        }
        let locators = map.get(peers[0].public_key()).unwrap();
        assert_eq!(
            locators.len(),
            3,
            "the lane count resets at the next authoritative lane"
        );
        assert_eq!(locators[2].lane_id, LaneId::new(1));
        assert_eq!(locators[2].validator, second);
        assert!(locators[..2].iter().any(|row| row.validator == first));
        for row in locators {
            assert_eq!(
                original_slashable_exposure(&index, row.lane_id, &row.validator).unwrap(),
                &Quantity::from(10_000_u64)
            );
        }
        assert!(map.get(peers[1].public_key()).is_none());
        drop(map);
        assert_eq!(state.evidence_preparation_budget().reserved_bytes(), 0);
    }

    #[test]
    fn validator_map_demand_detects_row_ledger_and_nested_overflow() {
        let peer = roster().remove(0);
        let account = AccountId::new(peer.public_key().clone());
        for mut demand in [
            ValidatorMapDemand {
                rows: usize::MAX,
                ..ValidatorMapDemand::default()
            },
            ValidatorMapDemand {
                account_charges: usize::MAX,
                ..ValidatorMapDemand::default()
            },
            ValidatorMapDemand {
                nested_bytes: usize::MAX,
                ..ValidatorMapDemand::default()
            },
        ] {
            assert!(matches!(
                demand.add(peer.public_key(), &account),
                Err(EvidencePreparationError::Admission(
                    AllocationRefusal::DemandOverflow
                ))
            ));
        }
        assert!(matches!(
            ValidatorMapDemand {
                rows: usize::MAX,
                ..ValidatorMapDemand::default()
            }
            .retained_bytes(),
            Err(EvidencePreparationError::Admission(
                AllocationRefusal::DemandOverflow
            ))
        ));
    }

    #[test]
    fn pending_penalty_backing_refusal_preserves_source_and_retries_after_original_release() {
        use iroha_allocation::AllocationRefusal;

        let max_rows = super::super::evidence::MAX_COMMITTED_EVIDENCE_RECORDS
            * iroha_sumeragi::types::MAX_COMMITTEE_SIZE;
        let max_layout = std::alloc::Layout::array::<PendingPenaltyEvidence>(max_rows)
            .expect("bounded penalty metadata layout");
        assert_eq!(
            max_layout.size(),
            iroha_config::parameters::defaults::nexus::storage::CONSENSUS_EVIDENCE_PENDING_PLAN_BYTES
        );
        assert_eq!(
            max_layout.align(),
            std::mem::align_of::<PendingPenaltyEntry>()
        );

        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let original = state
            .world
            .consensus_evidence
            .view()
            .get(&due)
            .cloned()
            .expect("original evidence row");
        let budget = state.evidence_preparation_budget();
        let one_due_layout =
            std::alloc::Layout::array::<PendingPenaltyEvidence>(1).expect("one due entry layout");
        let occupied_bytes = budget.limit_bytes() - one_due_layout.size() + 1;
        let original_owner = budget
            .try_reserve_bytes(occupied_bytes)
            .expect("retain the original pool before penalty derivation");
        let applier = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        );
        let error = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .map(|(actions, _index)| actions)
            .expect_err("one byte below the exact due backing must refuse locally");
        let refusal = error
            .downcast_ref::<EvidencePreparationError>()
            .expect("typed local preparation refusal");
        assert!(matches!(
            refusal,
            EvidencePreparationError::Admission(AllocationRefusal::Capacity {
                requested_bytes,
                ..
            }) if *requested_bytes == one_due_layout.size()
        ));
        assert!(refusal.release_wait().is_some());
        assert_eq!(budget.reserved_bytes(), occupied_bytes);
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original),
            "a local refusal cannot consume or terminalize accepted evidence"
        );
        drop(original_owner);
        let actions = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .map(|(actions, _index)| actions)
            .expect("the same State retries after the original owner releases capacity");
        assert!(matches!(
            actions.as_slice(),
            [NposPenaltyAction::MarkConsensusEvidenceApplied(mark)]
                if mark.evidence_key == due && mark.height == 2
        ));
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original)
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn original_staking_payload_refusal_retains_evidence_pool_and_exact_assembly_retry() {
        use crate::{state::StateReadOnly, sumeragi::payload, tx::AcceptedTransaction};
        use iroha_data_model::{
            isi::Log,
            level::Level,
            transaction::{FeePaymentIntent, TransactionBuilder},
        };
        use iroha_primitives::time::TimeSource;
        use std::{task::Context, time::Duration};

        for state_admission in [false, true] {
            let state = native_penalty_state();
            install_one_block_delay_npos(&state);
            let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
            let original = state
                .world
                .consensus_evidence
                .view()
                .get(&due)
                .cloned()
                .unwrap();
            let view = state.view();
            let parent = view
                .latest_block()
                .expect("completed original State read")
                .unwrap();
            let key = KeyPair::try_from_seed(vec![0xEF; 32], Algorithm::Ed25519).unwrap();
            let mut builder = TransactionBuilder::new(
                *state.network_id_ref(),
                AccountId::new(key.public_key().clone()),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Log::new(
                Level::INFO,
                "original staking payload retry".to_owned(),
            )]);
            builder.set_creation_time(parent.header().creation_time() + Duration::from_millis(1));
            let (_, clock) =
                TimeSource::new_mock(parent.header().creation_time() + Duration::from_millis(2));
            let accepted = AcceptedTransaction::accept_with_time_source(
                builder.sign(key.private_key()),
                state.network_id_ref(),
                Duration::from_secs(1),
                view.world().parameters().transaction(),
                &iroha_config::parameters::actual::Crypto::default(),
                &clock,
            )
            .unwrap();
            drop(view);
            let assembly = payload::Assembly {
                parent: &parent,
                view: 0,
                cadence: Duration::from_millis(1),
            };
            let transactions = [accepted];
            let original_transaction = transactions[0].hash();
            let original_parent = parent.hash();
            let budget = if state_admission {
                state.kura().block_hash_history_budget()
            } else {
                state.evidence_preparation_budget().clone()
            };
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let observer_bytes = budget.reserved_bytes();
            let requested_bytes = std::mem::size_of::<PendingPenaltyEvidence>();
            let occupied_bytes = if state_admission {
                budget.limit_bytes() - budget.reserved_bytes()
            } else {
                budget.limit_bytes() - observer_bytes - requested_bytes + 1
            };
            let blocking_owner = budget.try_reserve_bytes(occupied_bytes).unwrap();
            let original_error = PenaltyApplier::new(&state, None)
                .derive_npos_consensus_effects(&penalty_header(2))
                .expect_err("the actual original producer must refuse this same evidence backing");
            let error = payload::assemble(&state, assembly, &transactions)
                .expect_err("the actual original pool cannot fund this staking preparation");
            let release = if state_admission {
                let original_error = original_error
                    .downcast_ref::<crate::state::MergeLedgerCommitError>()
                    .expect("actual scratch State acquisition preserves its history owner");
                let crate::state::MergeLedgerCommitError::BlockHashAdmission(original_refusal) =
                    original_error
                else {
                    panic!("scratch State lost its original history refusal: {original_error:?}");
                };
                let refusal = std::error::Error::source(&error)
                    .and_then(|source| source.downcast_ref::<crate::state::StateAdmissionError>())
                    .unwrap_or_else(|| panic!("payload loses original State admission: {error:?}"));
                assert_eq!(
                    refusal,
                    &crate::state::StateAdmissionError::History(original_refusal.clone())
                );
                assert!(matches!(
                    refusal,
                    crate::state::StateAdmissionError::History(
                        crate::state::BlockHashAdmissionError::Capacity(
                            AllocationRefusal::Capacity { .. }
                        )
                    )
                ));
                refusal.release_wait().unwrap().clone()
            } else {
                let original_refusal = original_error
                    .downcast_ref::<EvidencePreparationError>()
                    .expect("the original producer retains its typed evidence pool refusal");
                let refusal = std::error::Error::source(&error)
                    .and_then(|source| source.downcast_ref::<EvidencePreparationError>())
                    .unwrap_or_else(|| {
                        panic!("payload loses original evidence preparation: {error:?}")
                    });
                assert_eq!(refusal, original_refusal);
                assert!(
                    matches!(refusal, EvidencePreparationError::Admission(AllocationRefusal::Capacity {
                requested_bytes: actual, reserved_bytes, limit_bytes, ..
            }) if *actual == requested_bytes && *reserved_bytes == occupied_bytes + observer_bytes && *limit_bytes == budget.limit_bytes())
                );
                refusal.release_wait().unwrap().clone()
            };

            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(registration.poll_wait(&release, &mut context).is_pending());
            assert!(budget.reserved_bytes() >= occupied_bytes);
            assert_eq!(
                state.world.consensus_evidence.view().get(&due),
                Some(&original)
            );
            assert_eq!(state.view().height(), 1);
            assert_eq!(transactions[0].hash(), original_transaction);
            assert_eq!(parent.hash(), original_parent);
            drop(blocking_owner);
            assert!(registration.poll_wait(&release, &mut context).is_ready());
            let proposal = payload::assemble(&state, assembly, &transactions)
                .expect("the exact parent, transactions and evidence retry after original release");
            assert!(
                matches!(proposal.npos_consensus_effects().unwrap().penalty_actions.as_slice(),
            [NposPenaltyAction::MarkConsensusEvidenceApplied(mark)] if mark.evidence_key == due && mark.height == 2)
            );
            assert_eq!(
                state.world.consensus_evidence.view().get(&due),
                Some(&original)
            );
            assert_eq!(state.view().height(), 1);
            assert_eq!(transactions[0].hash(), original_transaction);
            assert_eq!(parent.hash(), original_parent);
            drop(registration);
            if !state_admission {
                assert_eq!(budget.reserved_bytes(), 0);
            }
            assert_eq!(
                payload::encode(&proposal).unwrap(),
                payload::encode(&payload::assemble(&state, assembly, &transactions).unwrap())
                    .unwrap()
            );
        }
    }

    #[test]
    fn pending_penalty_peer_key_allocator_refusal_preserves_original_source_and_retries() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let view = state.view();
        let original = view
            .world()
            .consensus_evidence()
            .get(&due)
            .expect("original accepted evidence row");
        assert_eq!(original.attribution.offenders.len(), 1);
        let offender = &original.attribution.offenders[0];
        let original_peer = &offender.peer_id;
        let original_pointer = original_peer
            .public_key()
            .borrowed_parts()
            .expect("original canonical compact key")
            .1
            .as_ptr();
        let layout = pending_peer_key_layout(original_peer).expect("exact original key layout");
        assert_eq!(
            layout,
            original_peer.public_key().retained_allocation_layout()
        );
        let budget = state.evidence_preparation_budget();
        let stake_budget = state.stake_index_budget();
        let baseline = budget.reserved_bytes();
        let stake_baseline = stake_budget.reserved_bytes();

        // Exercise the real allocation after exact original-pool admission. Ordinary
        // PeerId::clone would abort here; a charged fallible copy returns this layout.
        let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
            PenaltyApplier::parent_snapshot(&view, 2, budget, stake_budget)
        });
        assert!(
            refused,
            "the actual compact key allocation must be attempted"
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("physical key refusal must not complete pending penalty metadata"),
        };
        let refusal = error
            .downcast_ref::<EvidencePreparationError>()
            .expect("physical refusal retains its original local preparation cause");
        assert!(matches!(
            refusal,
            EvidencePreparationError::Allocator { requested_bytes }
                if *requested_bytes == layout.size()
        ));
        assert!(
            refusal.release_wait().is_none(),
            "allocator refusal has no invented pool wake"
        );
        drop(error);
        assert_eq!(budget.reserved_bytes(), baseline);
        assert_eq!(stake_budget.reserved_bytes(), stake_baseline);
        assert_eq!(view.height(), 1);
        assert_eq!(original.penalty_status, EvidencePenaltyStatus::Pending);
        assert_eq!(view.world().consensus_evidence().get(&due), Some(original));
        assert_eq!(
            original_peer
                .public_key()
                .borrowed_parts()
                .unwrap()
                .1
                .as_ptr(),
            original_pointer,
            "physical refusal must retain the same original key allocation"
        );

        let snapshot = PenaltyApplier::parent_snapshot(&view, 2, budget, stake_budget)
            .expect("the same original source retries after physical allocation is restored");
        assert!(snapshot.validator_map.rows.as_slice().is_empty());
        assert!(
            snapshot
                .validator_map
                ._account_charges
                .as_slice()
                .is_empty()
        );
        assert_eq!(snapshot.pending.as_slice().len(), 1);
        let retained = &snapshot.pending.as_slice()[0].0;
        assert_eq!(retained.0, due);
        assert_eq!(retained.1, original.attribution.scope);
        assert_eq!(retained.2, original.attribution.height);
        assert_eq!(retained.3, original.recorded_at_height);
        assert_eq!(retained.4, original.attribution.instance);
        let (signer, peer, lane_stake, charge) = retained.5.as_ref().expect("actual retained key");
        assert_eq!(*signer, offender.signer);
        assert_eq!(peer, original_peer);
        assert_eq!(*lane_stake, offender.lane_stake);
        assert!(charge.belongs_to(budget));
        assert_eq!(charge.layout(), layout);
        assert_eq!(peer.public_key().retained_allocation_layout(), layout);
        assert_ne!(
            peer.public_key().borrowed_parts().unwrap().1.as_ptr(),
            original_pointer
        );
        assert_eq!(
            budget.reserved_bytes(),
            baseline + std::mem::size_of::<PendingPenaltyEvidence>() + layout.size(),
            "the actual pending buffer and copied compact key retain exact original charges"
        );
        assert_eq!(stake_budget.reserved_bytes(), stake_baseline);
        drop(snapshot);
        assert_eq!(
            budget.reserved_bytes(),
            baseline,
            "last-owner drop refunds actual pending fields"
        );
        assert_eq!(stake_budget.reserved_bytes(), stake_baseline);
        assert_eq!(view.world().consensus_evidence().get(&due), Some(original));
        assert_eq!(
            original_peer
                .public_key()
                .borrowed_parts()
                .unwrap()
                .1
                .as_ptr(),
            original_pointer
        );
        assert_eq!(view.height(), 1);
    }

    #[test]
    fn pending_penalty_peer_key_refusal_preserves_source_and_retries_after_original_release() {
        use iroha_allocation::AllocationRefusal;

        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let due = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let original = state
            .world
            .consensus_evidence
            .view()
            .get(&due)
            .cloned()
            .expect("original evidence row");
        let budget = state.evidence_preparation_budget();
        let backing = std::mem::size_of::<PendingPenaltyEvidence>();
        let peer_key_bytes = pending_peer_key_layout(&roster()[1])
            .expect("canonical peer key layout")
            .size();
        let occupied_bytes = budget.limit_bytes() - backing - peer_key_bytes + 1;
        let original_owner = budget
            .try_reserve_bytes(occupied_bytes)
            .expect("retain the original pool before penalty derivation");
        let applier = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        );
        let error = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .map(|(actions, _index)| actions)
            .expect_err("one byte below the exact nested key must refuse locally");
        let refusal = error
            .downcast_ref::<EvidencePreparationError>()
            .expect("typed local preparation refusal");
        assert!(matches!(
            refusal,
            EvidencePreparationError::Admission(AllocationRefusal::Capacity {
                requested_bytes,
                ..
            }) if *requested_bytes == peer_key_bytes
        ));
        assert!(refusal.release_wait().is_some());
        assert_eq!(budget.reserved_bytes(), occupied_bytes);
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original),
            "nested-key capacity refusal cannot consume accepted evidence"
        );
        drop(original_owner);
        let actions = applier
            .derive_npos_penalty_actions(&penalty_header(2))
            .map(|(actions, _index)| actions)
            .expect("the same State retries after original pool release");
        assert!(matches!(
            actions.as_slice(),
            [NposPenaltyAction::MarkConsensusEvidenceApplied(mark)]
                if mark.evidence_key == due && mark.height == 2
        ));
        assert_eq!(
            state.world.consensus_evidence.view().get(&due),
            Some(&original)
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn derived_slash_targets_frozen_roster_even_when_live_topology_diverges() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        set_commit_topology(
            &state,
            vec![PeerId::new(checked_keypair().public_key().clone())],
        );
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let evidence = fixture_vote_evidence(1, 37);
        let key = insert_evidence(&state, evidence, 1);
        {
            let view = state.view();
            let snapshot = PenaltyApplier::parent_snapshot(
                &view,
                2,
                state.evidence_preparation_budget(),
                state.stake_index_budget(),
            )
            .expect("canonical penalty parent snapshot");
            let locators = snapshot
                .validator_map
                .get(offender.public_key())
                .expect("active validator tenure is indexed by its frozen-roster key");
            assert_eq!(locators.len(), 1);
            assert_eq!(locators[0].activation_height, 1);
            let exposure = original_slashable_exposure(
                &snapshot.stake_index,
                locators[0].lane_id,
                &locators[0].validator,
            )
            .unwrap();
            assert_eq!(exposure, &Quantity::from(10_000_u64));
            assert_eq!(snapshot.max_slash_bps, 10_000);
            assert_eq!(
                max_slash_amount(exposure, snapshot.max_slash_bps).expect("canonical slash amount"),
                Quantity::from(10_000_u64)
            );
        }
        {
            let mut scratch = state
                .consensus_effects_probe_block(penalty_header(2))
                .unwrap();
            let mut transaction = scratch
                .consensus_effects_transaction()
                .expect("fixture consensus-effects transaction admission");
            apply_slash_to_validator_without_observability(
                &mut transaction,
                LaneId::SINGLE,
                &validator,
                key,
                &Quantity::from(10_000_u64),
                2_000,
            )
            .expect("the canonical penalty fixture must admit its derived slash");
        }
        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("canonical evidence produces deterministic effects")
        .penalty_actions;
        assert!(
            actions.iter().any(|action| matches!(
                action,
                NposPenaltyAction::ConsensusSlash(slash)
                    if slash.evidence_key == key
                        && slash.signer == 1
                        && slash.peer_id == offender
                        && slash.validator == validator
            )),
            "derived actions: {actions:#?}"
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                if mark.evidence_key == key && mark.height == 2
        )));
    }
    #[test]
    fn multiple_due_evidence_records_slash_only_remaining_custody() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let first_key = insert_evidence(&state, fixture_vote_evidence(1, 37), 1);
        let second_key = insert_evidence(&state, fixture_vote_evidence(1, 38), 1);
        assert_ne!(first_key, second_key);

        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("sequential penalties consume only custody that remains")
        .penalty_actions;

        let slashes = actions
            .iter()
            .filter_map(|action| match action {
                NposPenaltyAction::ConsensusSlash(slash) => Some(slash),
                NposPenaltyAction::MarkConsensusEvidenceApplied(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(slashes.len(), 1);
        assert_eq!(slashes[0].validator, validator);
        assert_eq!(slashes[0].amount, Quantity::from(10_000_u64));
        let terminal_keys = actions
            .iter()
            .filter_map(|action| match action {
                NposPenaltyAction::MarkConsensusEvidenceApplied(mark) => Some(mark.evidence_key),
                NposPenaltyAction::ConsensusSlash(_) => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(terminal_keys, BTreeSet::from([first_key, second_key]));
    }
    #[test]
    fn penalty_derivation_fails_closed_on_missing_staking_custody_definition() {
        use iroha_data_model::{isi::error::InstructionExecutionError, query::error::FindError};

        let state = native_penalty_state();
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        add_validator_record(&state, &offender);
        let key = insert_evidence(&state, fixture_vote_evidence(1, 37), 1);
        let (asset_definition, _, _) = penalty_staking_ids();
        let mut definitions = state.world.asset_definitions.block();
        definitions
            .remove(asset_definition.clone())
            .expect("remove fixture staking definition");
        definitions.commit();

        let error = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect_err("invalid custody must abort rather than silently terminalize evidence");
        assert_eq!(
            error.downcast_ref::<InstructionExecutionError>(),
            Some(&InstructionExecutionError::Find(
                FindError::AssetDefinition(asset_definition)
            )),
            "the canonical XOR check must reject the exact missing custody definition: {error:#}"
        );
        assert_eq!(
            state
                .world
                .consensus_evidence
                .view()
                .get(&key)
                .expect("rejected derivation retains its evidence")
                .penalty_status,
            EvidencePenaltyStatus::Pending,
            "failed custody validation cannot terminalize evidence"
        );
    }
    #[test]
    fn evidence_cannot_slash_a_peer_tenure_activated_after_the_offence() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let validator_key = (LaneId::SINGLE, validator.clone());
        let mut records = state.world.public_lane_validators.block();
        let mut record = records
            .get(&validator_key)
            .cloned()
            .expect("validator tenure exists");
        record.activation_height = 2;
        records.insert(validator_key, record);
        records.commit();
        let evidence = fixture_vote_evidence(1, 37);
        let key = insert_evidence(&state, evidence, 1);

        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("pre-tenure evidence remains terminal and deterministic")
        .penalty_actions;

        assert!(
            !actions.iter().any(|action| matches!(
                action,
                NposPenaltyAction::ConsensusSlash(slash)
                    if slash.evidence_key == key || slash.validator == validator
            )),
            "evidence from an earlier peer tenure must not slash newly activated stake"
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                if mark.evidence_key == key && mark.height == 2
        )));
    }
    #[test]
    fn multiple_due_evidence_for_fully_slashed_signer_is_sequential_and_terminal() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let first_key = insert_evidence(&state, fixture_vote_evidence(1, 7), 1);
        let second_key = insert_evidence(&state, fixture_vote_evidence(1, 8), 1);
        assert_ne!(first_key, second_key);

        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("sequential scratch application handles multiple due proofs")
        .penalty_actions;

        let slashes = actions
            .iter()
            .filter_map(|action| match action {
                NposPenaltyAction::ConsensusSlash(slash) => Some(slash),
                NposPenaltyAction::MarkConsensusEvidenceApplied(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            slashes.len(),
            1,
            "the first canonical proof consumes all retained stake, so a second slash cannot be derived"
        );
        assert_eq!(slashes[0].validator, validator);
        assert_eq!(slashes[0].amount, Quantity::from(10_000_u64));
        assert!(slashes[0].evidence_key == first_key || slashes[0].evidence_key == second_key);
        for evidence_key in [&first_key, &second_key] {
            assert!(actions.iter().any(|action| matches!(
                action,
                NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                    if &mark.evidence_key == evidence_key && mark.height == 2
            )));
        }

        let (asset_definition, escrow, slash_sink) = penalty_staking_fixture_ids();
        let escrow_asset = iroha_data_model::asset::AssetId::new(asset_definition, escrow);
        let view = state.view();
        assert_eq!(
            view.world
                .assets()
                .get(&escrow_asset)
                .map(|balance| balance.as_ref().clone()),
            Some(Quantity::from(10_000_u64)),
            "scratch derivation must not debit committed escrow"
        );
        assert!(
            view.world
                .assets()
                .iter()
                .all(|(asset, _)| asset.account() != &slash_sink),
            "scratch derivation must not create a committed slash-sink balance"
        );
    }
    #[test]
    fn consensus_penalty_ignores_singleton_non_owner_shared_dataspace_projection() {
        let state = fresh_state_with_shared_public_staking_lanes();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record_on_lane(&state, LaneId::new(1), &offender);
        let evidence = fixture_vote_evidence(1, 37);
        let key = insert_evidence(&state, evidence, 1);

        let actions = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("canonical evidence remains processable")
        .penalty_actions;

        assert!(
            !actions.iter().any(|action| matches!(
                action,
                NposPenaltyAction::ConsensusSlash(slash)
                    if slash.evidence_key == key
                        || slash.peer_id == offender
                        || slash.validator == validator
            )),
            "a non-owner compatibility projection must not receive a consensus slash action"
        );
        assert!(
            actions.iter().any(|action| matches!(
                action,
                NposPenaltyAction::MarkConsensusEvidenceApplied(mark)
                    if mark.evidence_key == key
            )),
            "an unslashable offence must still reach a terminal state"
        );
    }
    #[test]
    fn post_execution_lane_retirement_rejects_the_entire_consensus_penalty_bundle() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let evidence_key = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let effects = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("due evidence derives a complete penalty bundle");
        assert!(effects.penalty_actions.iter().any(|action| matches!(
            action,
            NposPenaltyAction::ConsensusSlash(slash)
                if slash.evidence_key == evidence_key && slash.validator == validator
        )));

        let evidence_prune_keys =
            crate::sumeragi::evidence::committed_evidence_prune_keys_from_state(&state, 2)
                .expect("fund exact committed-evidence prune keys");
        let mut state_block = height_two_state_block(&state);
        retire_primary_lane_in_candidate(&mut state_block);
        let error = validate_npos_consensus_effects_after_execution(
            &mut state_block,
            &effects,
            evidence_prune_keys.as_slice(),
            &[],
            2,
            0,
            2_000,
        )
        .expect_err("retiring a slash target must reject the candidate block");
        assert!(
            error
                .to_string()
                .contains("lane made inactive by block execution"),
            "unexpected rejection: {error}"
        );
        let record = state_block
            .world
            .consensus_evidence
            .get(&evidence_key)
            .expect("rollback preserves the unresolved evidence");
        assert_eq!(record.penalty_status, EvidencePenaltyStatus::Pending);
    }
    #[test]
    fn post_execution_evidence_terminalization_rejects_slash_and_mark_atomically() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        let validator = add_validator_record(&state, &offender);
        let evidence_key = insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let effects = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("due evidence derives a complete penalty bundle");
        let evidence_prune_keys =
            crate::sumeragi::evidence::committed_evidence_prune_keys_from_state(&state, 2)
                .expect("fund exact committed-evidence prune keys");
        let mut state_block = height_two_state_block(&state);
        {
            let mut transaction = state_block.transaction();
            let mut record = transaction
                .world
                .consensus_evidence
                .get(&evidence_key)
                .cloned()
                .expect("candidate terminalization target exists");
            record.penalty_status = EvidencePenaltyStatus::Applied { height: 2 };
            transaction
                .world
                .consensus_evidence
                .insert(evidence_key, record);
            transaction.apply();
        }

        let error = validate_npos_consensus_effects_after_execution(
            &mut state_block,
            &effects,
            evidence_prune_keys.as_slice(),
            &[],
            2,
            0,
            2_000,
        )
        .expect_err("same-block terminalization must reject the candidate penalty bundle");
        assert!(
            error.to_string().contains("already applied evidence"),
            "unexpected rejection: {error}"
        );
        let evidence = state_block
            .world
            .consensus_evidence
            .get(&evidence_key)
            .expect("candidate terminalization remains staged");
        assert_eq!(
            evidence.penalty_status,
            EvidencePenaltyStatus::Applied { height: 2 }
        );
        let validator_record = state_block
            .world
            .public_lane_validators
            .get(&(LaneId::SINGLE, validator))
            .expect("validator record remains staged");
        assert_eq!(validator_record.total_stake, Quantity::from(10_000_u64));
    }
    #[test]
    fn post_execution_penalty_validation_cannot_write_an_active_global_witness() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        add_validator_record(&state, &offender);
        insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let effects = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_consensus_effects(&penalty_header(2))
        .expect("due evidence derives a complete penalty bundle");
        let evidence_prune_keys =
            crate::sumeragi::evidence::committed_evidence_prune_keys_from_state(&state, 2)
                .expect("fund exact committed-evidence prune keys");
        let mut state_block = height_two_state_block(&state);

        let witness_guard = crate::exec_witness::exec_witness_guard();
        crate::exec_witness::start_block();
        validate_npos_consensus_effects_after_execution(
            &mut state_block,
            &effects,
            evidence_prune_keys.as_slice(),
            &[],
            2,
            0,
            2_000,
        )
        .expect("valid penalty effects remain applicable in the rollback-only overlay");
        let witness = crate::exec_witness::drain_exec_witness();
        drop(witness_guard);

        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
        assert!(witness.fastpq_batches.is_empty());
    }
    #[test]
    fn committed_consensus_penalty_cannot_publish_transaction_execution_evidence() {
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        let frozen_roster = roster();
        let offender = frozen_roster[1].clone();
        add_validator_record(&state, &offender);
        insert_evidence(&state, fixture_vote_evidence(1, 0), 1);
        let (penalty_actions, stake_index) = PenaltyApplier::new(
            &state,
            #[cfg(feature = "telemetry")]
            None,
            #[cfg(not(feature = "telemetry"))]
            None,
        )
        .derive_npos_penalty_actions(&penalty_header(2))
        .expect("due evidence derives a complete penalty bundle");
        let effects = NposConsensusEffects {
            parent_service_commit_qc: None,
            evidence_admissions: Vec::new(),
            penalty_actions,
        };
        let evidence_prune_keys =
            crate::sumeragi::evidence::committed_evidence_prune_keys_from_state(&state, 2)
                .expect("fund exact committed-evidence prune keys");
        let mut state_block = height_two_state_block(&state);

        let witness_guard = crate::exec_witness::exec_witness_guard();
        crate::exec_witness::start_block();
        let mut transaction = state_block
            .consensus_effects_transaction()
            .expect("fixture consensus-effects transaction admission");
        apply_npos_consensus_effects_to_transaction(
            &mut transaction,
            &effects,
            Some(&stake_index),
            evidence_prune_keys.as_slice(),
            &[],
            2,
            0,
            2_000,
        )
        .expect("valid committed penalty effects apply");
        transaction.apply_consensus_effects();
        let witness = crate::exec_witness::drain_exec_witness();
        drop(witness_guard);

        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
        assert!(witness.fastpq_batches.is_empty());
        assert!(state_block.drain_transfer_transcripts().is_empty());
    }

    /// Explicit admitted prestate for the monetary kernel. The separate native reader tests
    /// authenticate branch/custody; this fixture does not pretend its World edits are history.
    fn lane_penalty_fixture(bound: bool) -> (State, Hash, AccountId) {
        use iroha_data_model::{
            block::consensus::LaneEvidenceScope,
            sumeragi_lanes::{
                SumeragiLaneCustody, SumeragiLaneFrontier, SumeragiLaneSignerCustody,
                SumeragiLaneStakeBinding,
            },
        };
        let state = native_penalty_state();
        install_one_block_delay_npos(&state);
        state.nexus.write().staking.max_slash_bps = 1_000;
        let owner = LaneId::new(42);
        let validator = add_validator_record_on_lane(&state, owner, &roster()[1]);
        let view = state.view();
        assert!(!view.is_lane_active_for_authority(owner));
        let key = (owner, validator.clone());
        let record = view.world().public_lane_validators().get(&key).unwrap();
        let escrow = &view
            .world()
            .public_lane_stake_custody()
            .get(&key)
            .unwrap()
            .0;
        let binding = SumeragiLaneStakeBinding::from_record(record, escrow).unwrap();
        let params = view
            .world()
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .unwrap();
        let obligation = SumeragiLaneCustody {
            lane: LaneId::new(7),
            incarnation: [0x71; 32],
            instance: [0x41; 32],
            created_at: 1,
            merged: SumeragiLaneFrontier::default(),
            signer_count: 4,
            signers: if bound {
                vec![SumeragiLaneSignerCustody { signer: 1, binding }]
                    .try_into()
                    .unwrap()
            } else {
                Default::default()
            },
            evidence_horizon: params.evidence_horizon_blocks(),
            slashing_delay: params.slashing_delay_blocks(),
            retired_at: Some(20),
        };
        let scope = LaneEvidenceScope {
            lane: obligation.lane,
            incarnation: obligation.incarnation,
            created_at: 1,
            admission_parent_height: 20,
            admission_parent_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"monetary kernel parent",
            )),
            admission_parent_core_hash: [0x72; 32],
            admission_parent_result: [0x73; 32],
        };
        drop(view);
        let mut lanes = state.world.sumeragi_lanes.block();
        lanes.get_mut().custody.push(obligation);
        lanes.commit();
        let iroha_sumeragi::message::Evidence::VoteEquivocation(mut first, mut second) =
            fixture_vote_evidence(1, 0).decode_native().unwrap()
        else {
            panic!("vote fixture")
        };
        for vote in [&mut first, &mut second] {
            vote.height = 1_000;
            vote.sig = iroha_sumeragi::types::Signature(
                Signature::new(roster_keys()[1].private_key(), &vote.preimage())
                    .payload()
                    .try_into()
                    .unwrap(),
            );
        }
        let proof = Evidence::from_native(&iroha_sumeragi::message::Evidence::VoteEquivocation(
            first, second,
        ))
        .unwrap();
        let key = insert_evidence(&state, proof, 21);
        let mut rows = state.world.consensus_evidence.block();
        let mut row = rows.get(&key).unwrap().canonical_projection();
        row.attribution.scope = EvidenceScope::Lane(scope);
        row.attribution.height = 1_000; // Native lane clock, intentionally above global carrier.
        row.attribution.offenders[0].lane_stake = bound.then_some(binding);
        let row =
            crate::state::RetainedEvidenceRecord::from_fixture(row, &state.ivm_execution_budget())
                .unwrap();
        rows.insert(key, row);
        rows.commit();
        (state, key, validator)
    }

    #[test]
    fn original_lane_liability_checks_exact_registration_before_exposure() {
        let (state, key, validator) = lane_penalty_fixture(true);
        let view = state.view();
        let evidence = view.world().consensus_evidence().get(&key).unwrap();
        let liability = ConsensusSlashLiability::from_attribution(
            &evidence.attribution,
            evidence.recorded_at_height,
            1,
        )
        .unwrap();
        let original = view
            .world()
            .public_lane_validators()
            .get(&(LaneId::new(42), validator))
            .unwrap();
        assert!(
            liability
                .names_registration(view.world(), original)
                .unwrap()
        );
        let mut later = original.clone();
        later.activation_height += 1;
        assert!(
            !liability.names_registration(view.world(), &later).unwrap(),
            "the same account and peer cannot move a lien to a later registration"
        );
        let mut substituted = original.clone();
        substituted.peer_id = roster()[0].clone();
        assert!(
            liability
                .names_registration(view.world(), &substituted)
                .is_err(),
            "the exact retained peer is part of the original escrow binding"
        );
    }

    #[test]
    fn original_lane_liability_slashes_retired_owner_without_using_native_height() {
        let (state, evidence_key, validator) = lane_penalty_fixture(true);
        let applier = PenaltyApplier::new(&state, None);
        let (early, _) = applier
            .derive_npos_penalty_actions(&penalty_header(21))
            .unwrap();
        assert!(
            early.is_empty(),
            "the admission carrier cannot slash its own proof"
        );
        let (actions, index) = applier
            .derive_npos_penalty_actions(&penalty_header(22))
            .unwrap();
        let slash = actions
            .iter()
            .find_map(|action| match action {
                NposPenaltyAction::ConsensusSlash(slash) => Some(slash),
                _ => None,
            })
            .expect("original custody remains liable after routing retirement");
        assert_eq!(slash.evidence_key, evidence_key);
        assert_eq!(slash.lane_id, LaneId::new(42));
        assert_eq!(slash.validator, validator);
        assert_eq!(slash.amount, Quantity::from(1_000_u64));
        let before = state
            .view()
            .world()
            .public_lane_stake_custody()
            .get(&(slash.lane_id, validator.clone()))
            .unwrap()
            .1
            .clone();
        let mut block = state
            .consensus_effects_probe_block(penalty_header(22))
            .unwrap();
        let mut tx = block.consensus_effects_transaction().unwrap();
        let effects = NposConsensusEffects {
            parent_service_commit_qc: None,
            evidence_admissions: Vec::new(),
            penalty_actions: actions,
        };
        apply_npos_consensus_effects_to_transaction(
            &mut tx,
            &effects,
            Some(&index),
            &[],
            &[],
            22,
            0,
            22_000,
        )
        .unwrap();
        let after = &tx
            .world
            .public_lane_stake_custody
            .get(&(LaneId::new(42), validator))
            .unwrap()
            .1;
        assert_eq!(
            before.checked_sub(after).unwrap(),
            Quantity::from(1_000_u64)
        );
        assert!(
            tx.world
                .consensus_evidence
                .get(&evidence_key)
                .unwrap()
                .penalty_status
                .is_terminal()
        );
    }

    #[test]
    fn lane_liability_never_targets_later_registration_or_originally_unbound_member() {
        for bound in [true, false] {
            let (state, evidence_key, validator) = lane_penalty_fixture(bound);
            if bound {
                let mut records = state.world.public_lane_validators.block();
                let key = (LaneId::new(42), validator);
                let mut later = records.get(&key).unwrap().clone();
                later.activation_height += 1;
                records.insert(key, later);
                records.commit();
            }
            let (actions, _) = PenaltyApplier::new(&state, None)
                .derive_npos_penalty_actions(&penalty_header(22))
                .unwrap();
            assert_eq!(
                actions,
                vec![NposPenaltyAction::MarkConsensusEvidenceApplied(
                    NposMarkConsensusEvidenceAppliedAction {
                        evidence_key,
                        height: 22
                    },
                )]
            );
        }
    }

    #[test]
    fn lane_liability_rejects_changed_incarnation_policy_and_same_tenure_escrow() {
        for mutation in 0..3 {
            let (state, _, validator) = lane_penalty_fixture(true);
            match mutation {
                0 | 1 => {
                    let mut rows = state.world.sumeragi_lanes.block();
                    if mutation == 0 {
                        rows.get_mut().custody[0].incarnation = [0x99; 32];
                    } else {
                        rows.get_mut().custody[0].evidence_horizon += 1;
                    }
                    rows.commit();
                }
                _ => {
                    let mut custody = state.world.public_lane_stake_custody.block();
                    let key = (LaneId::new(42), validator);
                    let (asset, amount) = custody.get(&key).unwrap().clone();
                    let (_, _, sink) = penalty_staking_ids();
                    custody.insert(
                        key,
                        (AssetId::new(asset.definition().clone(), sink), amount),
                    );
                    custody.commit();
                }
            }
            assert!(
                PenaltyApplier::new(&state, None)
                    .derive_npos_penalty_actions(&penalty_header(22))
                    .is_err()
            );
        }
    }

    #[test]
    fn terminalized_evidence_count_includes_unslashable_original_lane_record() {
        // This is explicit admitted monetary-kernel prestate, not an assertion that
        // seeded World attribution is certified history. Genesis execution is real.
        let (state, evidence_key, validator) = lane_penalty_fixture(false);
        let lane = LaneId::new(42);
        let validator_key = (lane, validator);
        let (asset_definition, _, _) = penalty_staking_ids();
        let view = state.view();
        let original_record = view
            .world()
            .consensus_evidence()
            .get(&evidence_key)
            .unwrap()
            .clone();
        assert_eq!(
            original_record.penalty_status,
            EvidencePenaltyStatus::Pending
        );
        let original_custody = view
            .world()
            .public_lane_stake_custody()
            .get(&validator_key)
            .unwrap()
            .clone();
        let original_validator = view
            .world()
            .public_lane_validators()
            .get(&validator_key)
            .unwrap()
            .clone();
        let original_balances = view
            .world()
            .assets()
            .iter()
            .map(|(id, amount)| (id.clone(), amount.as_ref().clone()))
            .collect::<Vec<_>>();
        let original_supply = view
            .world()
            .asset_definitions()
            .get(&asset_definition)
            .unwrap()
            .total_quantity()
            .clone();
        drop(view);

        let (actions, _index) = PenaltyApplier::new(&state, None)
            .derive_npos_penalty_actions(&penalty_header(22))
            .unwrap();
        assert_eq!(
            actions,
            vec![NposPenaltyAction::MarkConsensusEvidenceApplied(
                NposMarkConsensusEvidenceAppliedAction {
                    evidence_key,
                    height: 22
                },
            )],
            "an originally unbound signer terminalizes without inventing monetary liability"
        );
        let effects = NposConsensusEffects {
            parent_service_commit_qc: None,
            evidence_admissions: Vec::new(),
            penalty_actions: actions,
        };
        let mut block = state
            .consensus_effects_probe_block(penalty_header(22))
            .unwrap();
        // Separate any inherited fixture events from this exact finality operation.
        let _original_events = block.world.take_external_events();
        let witness_guard = crate::exec_witness::exec_witness_guard();
        crate::exec_witness::start_block();
        let mut transaction = block.consensus_effects_transaction().unwrap();
        let outcome = apply_npos_consensus_effects_to_transaction(
            &mut transaction,
            &effects,
            None,
            &[],
            &[],
            22,
            0,
            22_000,
        )
        .unwrap();
        let mut expected_record = original_record;
        expected_record.penalty_status = EvidencePenaltyStatus::Applied { height: 22 };
        assert_eq!(
            transaction
                .world
                .consensus_evidence
                .get(&evidence_key)
                .unwrap(),
            &expected_record,
            "only the existing original record's terminal status changes"
        );
        assert_eq!(
            transaction
                .world
                .public_lane_stake_custody
                .get(&validator_key),
            Some(&original_custody)
        );
        assert_eq!(
            transaction.world.public_lane_validators.get(&validator_key),
            Some(&original_validator)
        );
        assert_eq!(
            transaction
                .world
                .assets()
                .iter()
                .map(|(id, amount)| (id.clone(), amount.as_ref().clone()))
                .collect::<Vec<_>>(),
            original_balances,
            "all escrow, sink, payer and recipient balances remain exact"
        );
        assert_eq!(
            transaction
                .world
                .asset_definitions()
                .get(&asset_definition)
                .unwrap()
                .total_quantity(),
            &original_supply,
            "terminal markers do not mint, burn or charge fees"
        );
        transaction.apply_consensus_effects();
        assert!(block.world.take_external_events().is_empty());
        let witness = crate::exec_witness::drain_exec_witness();
        drop(witness_guard);
        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
        assert!(witness.fastpq_batches.is_empty());
        assert!(block.drain_transfer_transcripts().is_empty());
        assert_eq!(outcome.slashed, 0, "there is no custody slash");
        // This is the intended causal BEFORE assertion: the original kernel
        // reports zero, after successfully terminalizing the same record above.
        assert_eq!(
            outcome.applied, 1,
            "count terminalized records, not slash actions"
        );
    }
}
