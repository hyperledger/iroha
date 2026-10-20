//! Original-pool custody for the complete immutable penalty action graph.

use super::*;
use iroha_allocation::RetainedPayload;
use iroha_primitives::numeric::{ChargedQuantity, QuantityAccumulator};

/// Move-only action vector and every nested key, account and quantity allocation.
pub(crate) struct FundedPenaltyActions(RetainedPayload<Vec<NposPenaltyAction>>);

impl FundedPenaltyActions {
    /// Admit the empty graph in the same pool as nonempty penalty preparation.
    pub(crate) fn empty(budget: &AllocationBudget) -> Result<Self, EvidencePreparationError> {
        ActionBuilder::new(ActionDemand::default(), budget)?.finish()
    }

    /// Borrow canonical actions without separating them from allocation custody.
    pub(crate) fn as_slice(&self) -> &[NposPenaltyAction] {
        self.0.get()
    }

    #[cfg(test)]
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }

    #[cfg(test)]
    fn allocation_bytes(&self) -> usize {
        self.0.allocation_bytes().expect("checked action layouts")
    }
}

impl std::ops::Deref for FundedPenaltyActions {
    type Target = [NposPenaltyAction];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl std::fmt::Debug for FundedPenaltyActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_slice().fmt(f)
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct ActionDemand {
    actions: usize,
    nested_charges: usize,
}

impl ActionDemand {
    fn marker(&mut self) -> Result<(), EvidencePreparationError> {
        self.actions = self.actions.checked_add(1).ok_or_else(overflow)?;
        Ok(())
    }

    fn slash(&mut self, validator: &AccountId) -> Result<(), EvidencePreparationError> {
        self.marker()?;
        // One peer key and one native quantity backing, including zero-sized digits.
        self.nested_charges = self.nested_charges.checked_add(2).ok_or_else(overflow)?;
        let mut failed = false;
        validator
            .for_each_admission_clone_layout(|_| {
                if let Some(count) = self.nested_charges.checked_add(1) {
                    self.nested_charges = count;
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

    /// Upper bound of one plan's graph. A record's offender rows are contiguous
    /// and the builder keeps one marker per evidence key, so each run of equal keys
    /// reserves one marker slot instead of one per offender row.
    pub(super) fn from_snapshot(snapshot: &ParentPenaltySnapshot) -> Result<Self> {
        let mut demand = Self::default();
        let mut previous = None;
        for pending in snapshot.pending.as_slice() {
            if previous != Some(pending.0.0) {
                demand.marker()?;
                previous = Some(pending.0.0);
            }
            if matches!(pending.0.1, EvidenceScope::SccpGeneration { .. }) {
                // Planning's canonical refusal: sizing must not mask native metadata
                // that claims an SCCP scope without its retained original record.
                let original = snapshot
                    .sccp_pending
                    .as_slice()
                    .iter()
                    .find(|row| row.key == pending.0.0)
                    .ok_or_else(|| eyre!("SCCP evidence cannot use native penalty metadata"))?;
                let material = sccp::material(&original.key, &original.record)?;
                for offender in &material.offenders {
                    demand.slash(&offender.validator)?;
                }
            } else if let Some((_, peer, _, _)) = &pending.0.5 {
                if let Some(locators) = snapshot.validator_map.get(peer.public_key()) {
                    for locator in locators {
                        demand.slash(locator.validator())?;
                    }
                }
            }
        }
        Ok(demand)
    }

    /// Reserved action slots, for production-path geometry tests.
    #[cfg(test)]
    pub(super) fn action_slots(self) -> usize {
        self.actions
    }

    fn ledger_capacity(self) -> Result<usize, EvidencePreparationError> {
        self.nested_charges
            .checked_add(usize::from(self.actions != 0))
            .ok_or_else(overflow)
    }

    fn backing_bytes(self) -> Result<usize, EvidencePreparationError> {
        let values = Layout::array::<NposPenaltyAction>(self.actions).map_err(|_| overflow())?;
        let ledger =
            Layout::array::<AllocationCharge>(self.ledger_capacity()?).map_err(|_| overflow())?;
        values
            .size()
            .checked_add(ledger.size())
            .ok_or_else(overflow)
    }
}

fn overflow() -> EvidencePreparationError {
    EvidencePreparationError::Admission(AllocationRefusal::DemandOverflow)
}

/// Evidence key carried by every penalty action.
fn action_key(action: &NposPenaltyAction) -> Hash {
    match action {
        NposPenaltyAction::ConsensusSlash(slash) => slash.evidence_key,
        NposPenaltyAction::MarkConsensusEvidenceApplied(mark) => mark.evidence_key,
    }
}

/// Fixed admitted backing; values always retire before the nested charge ledger.
pub(super) struct ActionBuilder {
    values: ChargedBuffer<NposPenaltyAction>,
    charges: ChargedBuffer<AllocationCharge>,
    budget: AllocationBudget,
}

/// Borrowed immutable fields; copying them does not copy the original graphs.
pub(super) struct SlashFields<'a> {
    pub(super) evidence_key: Hash,
    pub(super) signer: u32,
    pub(super) peer_id: &'a PeerId,
    pub(super) lane_id: LaneId,
    pub(super) validator: &'a AccountId,
    pub(super) slash_id: Hash,
}

impl ActionBuilder {
    pub(super) fn new(
        demand: ActionDemand,
        budget: &AllocationBudget,
    ) -> Result<Self, EvidencePreparationError> {
        let reservation = budget
            .try_reserve_bytes(demand.backing_bytes()?)
            .map_err(EvidencePreparationError::Admission)?;
        Self::from_reservation(demand, budget, reservation)
    }

    fn from_reservation(
        demand: ActionDemand,
        budget: &AllocationBudget,
        mut reservation: AllocationReservation,
    ) -> Result<Self, EvidencePreparationError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC910"))]
        let same_pool = true;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC910")))]
        let same_pool = reservation.belongs_to(budget);
        if !same_pool || reservation.remaining_bytes() != demand.backing_bytes()? {
            return Err(EvidencePreparationError::Invariant);
        }
        let charges = ChargedBuffer::from_reservation(demand.ledger_capacity()?, &mut reservation)
            .map_err(validator_map_buffer_error)?;
        let values = ChargedBuffer::from_reservation(demand.actions, &mut reservation)
            .map_err(validator_map_buffer_error)?;
        Ok(Self {
            values,
            charges,
            budget: budget.clone(),
        })
    }

    pub(super) fn budget(&self) -> &AllocationBudget {
        &self.budget
    }

    /// Earlier actions of `evidence_key`. Planning visits pending entries in key
    /// order, so an equal earlier action can only lie in this trailing run; an
    /// out-of-order key is refused instead of escaping duplicate suppression.
    fn current_run(
        &self,
        evidence_key: Hash,
    ) -> Result<&[NposPenaltyAction], EvidencePreparationError> {
        let values = self.values.as_slice();
        #[cfg(all(test, sumeragi_core_mutation = "HC916"))]
        let ordered = true;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC916")))]
        let ordered = values
            .last()
            .is_none_or(|last| action_key(last) <= evidence_key);
        if !ordered {
            return Err(EvidencePreparationError::Invariant);
        }
        let start = values
            .iter()
            .rposition(|action| action_key(action) != evidence_key)
            .map_or(0, |index| index + 1);
        Ok(&values[start..])
    }

    pub(super) fn marker(
        &mut self,
        evidence_key: Hash,
        height: u64,
    ) -> Result<(), EvidencePreparationError> {
        let action = NposPenaltyAction::MarkConsensusEvidenceApplied(
            NposMarkConsensusEvidenceAppliedAction {
                evidence_key,
                height,
            },
        );
        if !self.current_run(evidence_key)?.contains(&action) {
            self.values
                .try_push(action)
                .map_err(|_| EvidencePreparationError::Invariant)?;
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn slash(
        &mut self,
        fields: SlashFields<'_>,
        amount: ChargedQuantity,
    ) -> Result<(), EvidencePreparationError> {
        if !amount.belongs_to(&self.budget) {
            return Err(EvidencePreparationError::Invariant);
        }
        if self.current_run(fields.evidence_key)?.iter().any(|action| {
            matches!(action,
            NposPenaltyAction::ConsensusSlash(slash) if slash.evidence_key == fields.evidence_key
                && slash.signer == fields.signer && &slash.peer_id == fields.peer_id
                && slash.lane_id == fields.lane_id && &slash.validator == fields.validator
                && slash.slash_id == fields.slash_id && &slash.amount == amount.get())
        }) {
            return Ok(());
        }
        if self.values.as_slice().len() == self.values.capacity() {
            return Err(EvidencePreparationError::Invariant);
        }
        let key_layout = fields.peer_id.public_key().retained_allocation_layout();
        let mut bytes = key_layout.size();
        let mut slots = 2_usize;
        let mut failed = false;
        fields
            .validator
            .for_each_admission_clone_layout(|layout| {
                match (bytes.checked_add(layout.size()), slots.checked_add(1)) {
                    (Some(next_bytes), Some(next_slots)) => {
                        bytes = next_bytes;
                        slots = next_slots;
                    }
                    _ => failed = true,
                }
            })
            .map_err(|_| EvidencePreparationError::Invariant)?;
        if failed {
            return Err(overflow());
        }
        // Keep one ledger slot for the final action-vector backing move.
        if slots.checked_add(1).ok_or_else(overflow)?
            > self
                .charges
                .capacity()
                .saturating_sub(self.charges.as_slice().len())
        {
            return Err(EvidencePreparationError::Invariant);
        }
        let mut reservation = self
            .budget
            .try_reserve_bytes(bytes)
            .map_err(EvidencePreparationError::Admission)?;
        let key_charge = reservation
            .try_split(key_layout)
            .map_err(|_| EvidencePreparationError::Invariant)?;
        let peer = fields
            .peer_id
            .public_key()
            .try_clone_from_charge(&self.budget, key_charge)
            .map_err(|(_, error)| match error {
                PublicKeyAllocationError::Allocation(ChargedBufferFromChargeError::Allocator {
                    layout,
                }) => EvidencePreparationError::Allocator {
                    requested_bytes: layout.size(),
                },
                _ => EvidencePreparationError::Invariant,
            })?;
        let validator =
            clone_locator_account(fields.validator, &mut reservation, &mut self.charges)?;
        // SAFETY: fixed slots were checked before extraction. The exact key, account
        // and native digits enter this immutable graph and retire before its ledger.
        let (peer, key_charge) = unsafe { peer.into_allocation_parts() };
        let (amount, amount_charge) = unsafe { amount.into_allocation_parts() };
        self.charges.push_reserved(key_charge);
        #[cfg(all(test, sumeragi_core_mutation = "HC911"))]
        drop(amount_charge);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC911")))]
        self.charges.push_reserved(amount_charge);
        self.values.push_reserved(NposPenaltyAction::ConsensusSlash(
            NposConsensusSlashAction {
                evidence_key: fields.evidence_key,
                signer: fields.signer,
                peer_id: PeerId::new(peer),
                lane_id: fields.lane_id,
                validator,
                slash_id: fields.slash_id,
                amount,
            },
        ));
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn finish(mut self) -> Result<FundedPenaltyActions, EvidencePreparationError> {
        if self.values.capacity() != 0 && self.charges.as_slice().len() == self.charges.capacity() {
            return Err(EvidencePreparationError::Invariant);
        }
        // Keep the backing in its RAII owner throughout comparisons. Even an
        // unwinding comparator must destroy the vector before refunding it.
        sort_penalty_actions(self.values.as_mut_slice());
        let Self {
            values,
            mut charges,
            budget,
        } = self;
        // SAFETY: the original fixed backing enters the retained owner below.
        // Duplicate candidates were suppressed before allocating nested storage.
        let (values, backing) = unsafe { values.into_allocation_parts() };
        if values.capacity() != 0 {
            charges.push_reserved(backing);
        } else {
            drop(backing);
        }
        // SAFETY: every actual nested layout and the original vector backing have
        // exactly one retained charge. No field extraction or growth is exposed.
        match unsafe { RetainedPayload::try_new(values, charges, &budget) } {
            Ok(owner) => Ok(FundedPenaltyActions(owner)),
            Err((values, charges, _)) => {
                drop(values);
                drop(charges);
                Err(EvidencePreparationError::Invariant)
            }
        }
    }
}

/// Compute the same clamped basis-point amount using bounded stack arithmetic.
pub(super) fn slash_amount(
    total: &Quantity,
    max_bps: u16,
    budget: &AllocationBudget,
) -> Result<ChargedQuantity, EvidencePreparationError> {
    let mut amount = QuantityAccumulator::from_quantity(total);
    amount
        .try_scale_basis_points(max_bps.min(10_000))
        .map_err(|_| EvidencePreparationError::Invariant)?;
    ChargedQuantity::try_from_accumulator(amount, budget).map_err(EvidencePreparationError::from)
}

#[cfg(test)]
#[path = "funded_actions/tests.rs"]
mod tests;
