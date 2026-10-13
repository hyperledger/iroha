//! Original-pool fixed-size reconciliation accounting, proof ids and ordered due work.
//!
//! No reconciliation mutation clones the proof-id history. Current and undo tree nodes
//! retain the original execution pool; any refusal arms the enclosing transaction abort.

use super::Error;
use crate::state::{StateTransaction, WorldReadOnly};
use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{AllocationCharge, AllocationReservation};
use iroha_data_model::{bridge::SccpNetworkV1, sccp::reconciliation::SccpReconciliationStateV1};
use mv::storage::{AdmittedStoragePolicy, StorageReadOnly};
use std::alloc::Layout;

/// One immutable route revision's reconciliation identity.
pub type Key = (SccpNetworkV1, u32);
/// Permanent source-message deduplication identity.
pub type ProofKey = (SccpNetworkV1, u32, [u8; 32]);
/// Ordered G2a rank-three reconciliation deadline.
pub type DueKey = (u64, SccpNetworkV1, u32);

/// Closed fixed-copy node policy for reconciliation State maps and exact undo maps.
pub struct ReconciliationStoragePolicy(AllocationReservation);
impl NodeFunding for ReconciliationStoragePolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("admitted reconciliation node layout")
    }
}
macro_rules! fixed_copy {
    ($key:ty, $value:ty) => {
        impl NodeCloning<$key, $value> for ReconciliationStoragePolicy {
            fn clone_key(&mut self, key: &$key) -> $key {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                *value
            }
        }
        impl ClonePlanning<$key, $value> for ReconciliationStoragePolicy {
            fn plan_key(_: &$key, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
fixed_copy!(Key, SccpReconciliationStateV1);
fixed_copy!(Key, Option<SccpReconciliationStateV1>);
fixed_copy!(Key, u128);
fixed_copy!(Key, Option<u128>);
fixed_copy!(ProofKey, u128);
fixed_copy!(ProofKey, Option<u128>);
fixed_copy!(DueKey, ());
fixed_copy!(DueKey, Option<()>);
impl AdmittedStoragePolicy for ReconciliationStoragePolicy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
/// Original current/undo map-node custody shared by the closed scalar map types.
pub type Mode = Prepaid<ReconciliationStoragePolicy>;
/// Authoritative fixed-size reconciliation records.
pub type Records = mv::storage::Storage<Key, SccpReconciliationStateV1, Mode>;
/// Authoritative permanent proven-message amounts, separate from mutable accounting.
pub type Proofs = mv::storage::Storage<ProofKey, u128, Mode>;
/// Authoritative pending-refund face sums, with zero represented by absence.
pub type Refunds = mv::storage::Storage<Key, u128, Mode>;
/// Derived ordered deadline index, reconstructed from both exact canonical map cuts.
pub type Due = mv::storage::Storage<DueKey, (), Mode>;

/// Structural relation shared by the write funnel and snapshot restoration.
#[must_use]
pub fn valid_record(key: &Key, value: &SccpReconciliationStateV1) -> bool {
    valid_key(key)
        && value.closes_at_ms > value.opened_at_ms
        && match value.rho {
            None => value.settled_face == 0,
            Some(ratio) => {
                ratio.denominator > 0
                    && ratio.backing <= ratio.denominator
                    && (ratio.backing.checked_add(value.forged_supply) == Some(ratio.denominator)
                        || (ratio.backing == 0
                            && value.forged_supply == 0
                            && ratio.denominator == 1))
            }
        }
}
/// Only real external networks and nonzero revisions own reconciliation state.
#[must_use]
pub fn valid_key(key: &Key) -> bool {
    key.0.is_external() && key.1 != 0
}

fn refusal(
    state: &mut StateTransaction<'_, '_>,
    original: mv::storage::AdmittedStorageError,
) -> Error {
    state.arm_local_storage_refusal(crate::state::StateStorageAdmissionError::World(original));
    Error::InvariantViolation("original reconciliation State allocation did not complete".into())
}

/// Borrow a retained scalar record without allocating or copying proof history.
#[must_use]
pub fn get<'a>(
    world: &'a (impl WorldReadOnly + ?Sized),
    key: &Key,
) -> Option<&'a SccpReconciliationStateV1> {
    world.sccp_reconciliations().get(key)
}

/// Replace accounting and update the due index inside the same rollback owner.
/// # Errors
/// Rejects malformed record identities and preserves original local map admission refusal.
pub fn put(
    state: &mut StateTransaction<'_, '_>,
    key: Key,
    value: SccpReconciliationStateV1,
) -> Result<(), Error> {
    if !valid_record(&key, &value) {
        return Err(Error::InvariantViolation(
            "invalid reconciliation record".into(),
        ));
    }
    let old_due = get(&*state.world, &key)
        .filter(|old| old.rho.is_none())
        .map(|old| (old.closes_at_ms, key.0, key.1));
    state
        .world
        .sccp_reconciliations
        .try_insert_admitted(key, value)
        .map_err(|(_, error)| refusal(state, error))?;
    if let Some(old_due) = old_due {
        state
            .world
            .sccp_reconciliation_due
            .try_remove_admitted(old_due)
            .map_err(|(_, error)| refusal(state, error))?;
    }
    if value.rho.is_none() {
        state
            .world
            .sccp_reconciliation_due
            .try_insert_admitted((value.closes_at_ms, key.0, key.1), ())
            .map_err(|(_, error)| refusal(state, error))?;
    }
    Ok(())
}

/// Whether the exact finalized source message has already contributed to forged supply.
#[must_use]
pub fn proven(world: &(impl WorldReadOnly + ?Sized), key: Key, message_id: &[u8; 32]) -> bool {
    world
        .sccp_reconciliation_proven()
        .get(&(key.0, key.1, *message_id))
        .is_some()
}

/// Insert one permanent proof id without mutating any row on deterministic duplicate failure.
/// # Errors
/// Rejects an invalid key, zero face, duplicate, or original local allocation refusal.
pub fn prove(
    state: &mut StateTransaction<'_, '_>,
    key: Key,
    message_id: [u8; 32],
    amount: u128,
) -> Result<(), Error> {
    if !valid_key(&key) || amount == 0 || proven(&*state.world, key, &message_id) {
        return Err(Error::InvariantViolation(
            "invalid or duplicate reconciliation proof id".into(),
        ));
    }
    state
        .world
        .sccp_reconciliation_proven
        .try_insert_admitted((key.0, key.1, message_id), amount)
        .map_err(|(_, error)| refusal(state, error))?;
    Ok(())
}

/// Pending authentic-refund face sum; absence is zero.
#[must_use]
pub fn pending_refunds(world: &(impl WorldReadOnly + ?Sized), key: &Key) -> u128 {
    world
        .sccp_pending_refund_amount()
        .get(key)
        .copied()
        .unwrap_or(0)
}
fn set_pending_refunds(
    state: &mut StateTransaction<'_, '_>,
    key: Key,
    amount: u128,
) -> Result<(), Error> {
    if !valid_key(&key) {
        return Err(Error::InvariantViolation("invalid refund sum key".into()));
    }
    if amount == 0 {
        state
            .world
            .sccp_pending_refund_amount
            .try_remove_admitted(key)
            .map_err(|(_, error)| refusal(state, error))?;
    } else {
        state
            .world
            .sccp_pending_refund_amount
            .try_insert_admitted(key, amount)
            .map_err(|(_, error)| refusal(state, error))?;
    }
    Ok(())
}
/// Add a newly pending refund's exact face amount in its original transaction.
/// # Errors
/// Rejects overflow or original local map admission refusal.
pub fn add_pending_refund(
    state: &mut StateTransaction<'_, '_>,
    key: Key,
    amount: u128,
) -> Result<(), Error> {
    let next = pending_refunds(&*state.world, &key)
        .checked_add(amount)
        .ok_or_else(|| Error::InvariantViolation("pending refund amount overflow".into()))?;
    set_pending_refunds(state, key, next)
}
/// Remove a refund only as it leaves Pending in the same transaction.
/// # Errors
/// Rejects underflow or original local map admission refusal.
pub fn sub_pending_refund(
    state: &mut StateTransaction<'_, '_>,
    key: Key,
    amount: u128,
) -> Result<(), Error> {
    let next = pending_refunds(&*state.world, &key)
        .checked_sub(amount)
        .ok_or_else(|| Error::InvariantViolation("pending refund amount underflow".into()))?;
    set_pending_refunds(state, key, next)
}

/// Borrow only the first ordered due index row; never scan historical reconciliation records.
#[must_use]
pub fn earliest_due(world: &(impl WorldReadOnly + ?Sized), time_ms: u64) -> Option<DueKey> {
    world
        .sccp_reconciliation_due()
        .iter()
        .next()
        .filter(|(key, _)| key.0 <= time_ms)
        .map(|(key, _)| *key)
}

/// Rebuild the ordered deadline index from exact current and predecessor canonical records.
/// Proof-id sums are checked separately by [`validate_proof_sums`].
/// # Errors
/// Preserves original map admission failures; callers publish only after the full restore.
pub(crate) fn rebuild_due(
    records: &Records,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<Due, crate::state::sccp_snapshot_state::SccpRestoreError> {
    use crate::state::sccp_snapshot_state::SccpRestoreError;
    let snapshot = records.snapshot();
    let due = |key: &Key, value: &SccpReconciliationStateV1| {
        value
            .rho
            .is_none()
            .then_some((value.closes_at_ms, key.0, key.1))
    };
    Due::try_restore_admitted(budget.clone(), |current, undo| {
        for (key, value) in snapshot.current().iter() {
            if let Some(key) = due(key, value) {
                current(key, ())?;
            }
        }
        for (key, old) in snapshot.revert_map().iter() {
            let old_due = old.as_ref().and_then(|value| due(key, value));
            let current_due = snapshot
                .current()
                .get(key)
                .and_then(|value| due(key, value));
            if current_due != old_due {
                if let Some(current) = current_due {
                    undo(current, None)?;
                }
            }
            if let Some(old) = old_due {
                undo(old, Some(()))?;
            }
        }
        Ok::<(), SccpRestoreError>(())
    })
    .map_err(|error| match error {
        mv::storage::AdmittedBlockError::Admission(original) => original.into(),
        mv::storage::AdmittedBlockError::Callback(original) => original,
    })
}

/// Validate permanent proof amounts against both accounting images during restoration.
/// This restore-time merge is never part of block-start progress work.
pub(crate) fn validate_proof_sums(records: &mut Records, proofs: &mut Proofs) -> bool {
    fn image<'a>(records: impl Iterator<Item=(&'a Key,&'a SccpReconciliationStateV1)>, proofs: impl Iterator<Item=(&'a ProofKey,&'a u128)>) -> bool {
        let mut proofs=proofs.peekable();
        for (key,record) in records {
            let mut sum=0u128;
            while let Some((proof,amount))=proofs.peek() {
                let group=(proof.0,proof.1);
                if group < *key { return false; }
                if group > *key { break; }
                let Some(next)=sum.checked_add(**amount) else { return false; };
                sum=next;
                proofs.next();
            }
            if sum != record.forged_supply { return false; }
        }
        proofs.next().is_none()
    }
    let records=records.history();
    let proofs=proofs.history();
    image(records.current().iter(),proofs.current().iter())
        && image(records.iter_before_block(),proofs.iter_before_block())
}

#[cfg(test)]
mod tests;
