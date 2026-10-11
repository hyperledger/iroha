//! Finite, ordered write permits retained by one prepared quantity operation.
//!
//! The complete-effect preparation owner supplies the original sequence before
//! execution. Each exact typed write consumes one permit, including repeated keys
//! and unchanged quantities. Public callback state cannot reconstruct a permit.

use super::fastpq_quantity_archive::{QuantityBalanceInput, QuantityKindInput};
use super::fastpq_quantity_capture::QuantityCaptureIssue;
use crate::execution_attempt::ExecutionDeferred;
use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer};
#[cfg(test)]
use iroha_data_model::fastpq::FastpqExecutionEffectV1;
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    fastpq::FastpqExecutionAssetV1,
};
use iroha_primitives::numeric::Quantity;
use std::alloc::Layout;

/// Exact typed World key; a balance can never substitute for aggregate supply.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum QuantityWriteKey {
    /// Canonical account/definition/dataspace balance key.
    Balance(AssetId),
    /// Canonical aggregate-supply definition key.
    Supply(AssetDefinitionId),
    /// Actual definition/incarnation erasure; the quantity projection is its zero supply.
    /// Presence and exact incarnation are checked separately before releasing this port.
    Retire(FastpqExecutionAssetV1),
}

/// An exact storage projection transition expected by one prepared operation.
pub(super) struct ExpectedQuantityWrite<K, Q> {
    pub(super) key: K,
    pub(super) before: Q,
    pub(super) after: Q,
}

/// Finite preparation failure; messages and caller-supplied evidence are not retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum QuantityWritePlanError {
    /// The operation exceeds the original finite write-port reservation.
    Capacity,
    /// Original physical refusal, retained without inventing a retry observation.
    Deferred(ExecutionDeferred),
    /// An exact key, preimage, postimage or ordered occurrence did not match.
    Mismatch,
    /// A consumed or interrupted plan cannot be reused to mint additional permits.
    Exhausted,
    /// Not every originally reserved write was consumed.
    Incomplete,
}

/// Prepared sequence whose cursor advances only through the original write owner.
pub(super) struct QuantityWritePlan<K, Q> {
    writes: ChargedBuffer<ExpectedQuantityWrite<K, Q>>,
    key_order: ChargedBuffer<usize>,
    lifecycles: Option<
        ChargedBuffer<(
            AssetDefinitionId,
            iroha_data_model::nexus::AxtAssetIncarnationV1,
        )>,
    >,
    // Declared after payload: cloned nested storage drops before original credits.
    _nested_charges: ChargedBuffer<AllocationCharge>,
    consumed: usize,
    failed: bool,
}

/// A single consumed occurrence, usable only by the original storage mutation function.
pub(super) struct QuantityWritePermit<'plan, K, Q> {
    expected: &'plan ExpectedQuantityWrite<K, Q>,
    consumed: &'plan mut usize,
    failed: &'plan mut bool,
    applied: bool,
}

impl<K, Q> QuantityWritePermit<'_, K, Q> {
    /// Inspect the exact storage projection while this unique permit is retained.
    #[cfg(test)]
    pub(super) fn parts(&self) -> (&K, &Q, &Q) {
        (
            &self.expected.key,
            &self.expected.before,
            &self.expected.after,
        )
    }

    /// Advance only after the exact original storage mutation returned successfully.
    /// The storage owner calls this without handing the permit to user callbacks.
    pub(super) fn applied(mut self) {
        *self.consumed += 1;
        self.applied = true;
    }
}

impl<K, Q> Drop for QuantityWritePermit<'_, K, Q> {
    fn drop(&mut self) {
        if !self.applied {
            *self.failed = true;
        }
    }
}

impl<K: Ord, Q: Eq> QuantityWritePlan<K, Q> {
    /// Retain the already reserved exact sequence; never silently truncate excess ports.
    #[cfg(test)]
    pub(super) fn new(
        writes: Vec<ExpectedQuantityWrite<K, Q>>,
        reserved_ports: usize,
    ) -> Result<Self, QuantityWritePlanError> {
        if writes.len() > reserved_ports || writes.capacity() > reserved_ports {
            return Err(QuantityWritePlanError::Capacity);
        }
        let layout = Layout::array::<ExpectedQuantityWrite<K, Q>>(writes.len())
            .map_err(|_| QuantityWritePlanError::Capacity)?;
        let order_layout =
            Layout::array::<usize>(writes.len()).map_err(|_| QuantityWritePlanError::Capacity)?;
        let budget = AllocationBudget::new(
            layout
                .size()
                .checked_add(order_layout.size())
                .ok_or(QuantityWritePlanError::Capacity)?,
        );
        let mut owned = ChargedBuffer::new(writes.len(), &budget)
            .map_err(|_| QuantityWritePlanError::Capacity)?;
        for value in writes {
            owned.push_reserved(value);
        }
        let mut key_order = ChargedBuffer::new(owned.as_slice().len(), &budget)
            .map_err(|_| QuantityWritePlanError::Capacity)?;
        for index in 0..owned.as_slice().len() {
            key_order.push_reserved(index);
        }
        key_order.as_mut_slice().sort_unstable_by(|left, right| {
            owned.as_slice()[*left]
                .key
                .cmp(&owned.as_slice()[*right].key)
                .then(left.cmp(right))
        });
        Ok(Self {
            writes: owned,
            key_order,
            lifecycles: None,
            _nested_charges: ChargedBuffer::new(0, &budget)
                .map_err(|_| QuantityWritePlanError::Capacity)?,
            consumed: 0,
            failed: false,
        })
    }

    /// Validate all public and live storage fields before releasing one occurrence.
    ///
    /// A failed probe poisons this operation. A caller cannot recover by trying
    /// another key, or by supplying a later expected final state for a repeated key.
    #[cfg(test)]
    pub(super) fn consume(
        &mut self,
        key: &K,
        before: &Q,
        after: &Q,
    ) -> Result<QuantityWritePermit<'_, K, Q>, QuantityWritePlanError> {
        self.consume_matching(|expected| expected == key, before, after)
    }

    fn consume_matching(
        &mut self,
        matches_key: impl FnOnce(&K) -> bool,
        before: &Q,
        after: &Q,
    ) -> Result<QuantityWritePermit<'_, K, Q>, QuantityWritePlanError> {
        if self.failed || self.consumed == self.writes.as_slice().len() {
            self.failed = true;
            return Err(QuantityWritePlanError::Exhausted);
        }
        let expected = &self.writes.as_slice()[self.consumed];
        if !matches_key(&expected.key) || &expected.before != before || &expected.after != after {
            self.failed = true;
            return Err(QuantityWritePlanError::Mismatch);
        }
        Ok(QuantityWritePermit {
            expected,
            consumed: &mut self.consumed,
            failed: &mut self.failed,
            applied: false,
        })
    }

    /// Retain every exact lifecycle alongside the physical write projections.
    pub(super) fn lifecycles(
        &self,
    ) -> &[(
        AssetDefinitionId,
        iroha_data_model::nexus::AxtAssetIncarnationV1,
    )] {
        self.lifecycles
            .as_ref()
            .map_or(&[], ChargedBuffer::as_slice)
    }

    /// Borrow all projections in canonical key/occurrence order without cloning or allocation.
    pub(super) fn ordered_projections(&self) -> impl Iterator<Item = (&K, &Q, &Q)> {
        self.key_order.as_slice().iter().map(|index| {
            let row = &self.writes.as_slice()[*index];
            (&row.key, &row.before, &row.after)
        })
    }

    /// Count only ports the original storage owner acknowledged after actual mutation.
    pub(super) fn applied_count(&self) -> usize {
        self.consumed
    }

    /// Seal only after every occurrence was consumed without any failed probe.
    pub(super) fn finish(self) -> Result<(), QuantityWritePlanError> {
        if self.failed {
            return Err(QuantityWritePlanError::Mismatch);
        }
        if self.consumed != self.writes.as_slice().len() {
            return Err(QuantityWritePlanError::Incomplete);
        }
        Ok(())
    }
}

impl<K, Q> std::fmt::Debug for QuantityWritePlan<K, Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuantityWritePlan")
            .field("ports", &self.writes.as_slice().len())
            .field("consumed", &self.consumed)
            .field("failed", &self.failed)
            .finish()
    }
}

enum PortKey<'a> {
    Balance(QuantityBalanceInput<'a>),
    Supply(
        &'a AssetDefinitionId,
        iroha_data_model::nexus::AxtAssetIncarnationV1,
    ),
    Retire(
        &'a AssetDefinitionId,
        iroha_data_model::nexus::AxtAssetIncarnationV1,
    ),
}

#[expect(
    single_use_lifetimes,
    reason = "anonymous lifetimes in impl Trait are unstable on the pinned Rust compiler"
)]
fn visit_ports<'a>(
    kinds: impl Iterator<Item = Result<QuantityKindInput<'a>, QuantityCaptureIssue>>,
    mut visit: impl FnMut(PortKey<'_>, &Quantity, &Quantity) -> Result<(), QuantityWritePlanError>,
) -> Result<(), QuantityWritePlanError> {
    for kind in kinds {
        match kind.map_err(|_| QuantityWritePlanError::Mismatch)? {
            QuantityKindInput::Retire(definition, incarnation) => {
                let zero = Quantity::zero();
                visit(PortKey::Retire(definition, incarnation), &zero, &zero)?;
            }
            QuantityKindInput::Transfer(value) if value.source == value.destination => {
                visit(
                    PortKey::Balance(value.source),
                    value.source_before,
                    value.destination_after,
                )?;
            }
            QuantityKindInput::Transfer(value) => {
                visit(
                    PortKey::Balance(value.source),
                    value.source_before,
                    value.source_after,
                )?;
                visit(
                    PortKey::Balance(value.destination),
                    value.destination_before,
                    value.destination_after,
                )?;
            }
            QuantityKindInput::Mint(value) | QuantityKindInput::Burn(value) => {
                visit(
                    PortKey::Balance(value.balance),
                    value.balance_before,
                    value.balance_after,
                )?;
                visit(
                    PortKey::Supply(value.balance.definition, value.balance.incarnation),
                    value.supply_before,
                    value.supply_after,
                )?;
            }
        }
    }
    Ok(())
}

fn prepaid_refusal(error: iroha_allocation::PrepaidBufferError) -> QuantityWritePlanError {
    use iroha_allocation::{ChargedBufferError, PrepaidBufferError};
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(refusal)) => {
            QuantityWritePlanError::Deferred(refusal.into())
        }
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { .. }) => {
            QuantityWritePlanError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        }
        PrepaidBufferError::Reservation(_) => QuantityWritePlanError::Capacity,
    }
}

impl QuantityWritePlan<QuantityWriteKey, Quantity> {
    /// Preserve each original teardown owner's supply-before-removal write order.
    /// This consumes no new allocation or permit: only a fresh exact two-port
    /// complete-balance burn prepared by the original supply owner may be ordered.
    pub(super) fn order_supply_before_complete_removal(
        &mut self,
        id: &AssetId,
        amount: &Quantity,
    ) -> Result<(), QuantityWritePlanError> {
        let writes = self.writes.as_slice();
        if self.failed || self.consumed != 0 {
            self.failed = true;
            return Err(QuantityWritePlanError::Exhausted);
        }
        if writes.len() != 2
            || self.key_order.as_slice() != [0, 1]
            || !matches!(&writes[0].key, QuantityWriteKey::Balance(value) if value == id)
            || &writes[0].before != amount
            || !writes[0].after.is_zero()
            || !matches!(&writes[1].key, QuantityWriteKey::Supply(value) if value == id.definition())
        {
            self.failed = true;
            return Err(QuantityWritePlanError::Mismatch);
        }
        self.writes.as_mut_slice().swap(0, 1);
        // Preserve canonical-key projection order after changing physical order.
        self.key_order.as_mut_slice().swap(0, 1);
        if let Some(lifecycles) = self.lifecycles.as_mut() {
            lifecycles.as_mut_slice().swap(0, 1);
        }
        Ok(())
    }

    /// Reserve all port backing, ledger backing and exact nested clone layouts atomically
    /// from this transaction's original execution pool, before making any port clone.
    #[cfg(test)]
    pub(super) fn from_effects(
        effects: &[FastpqExecutionEffectV1],
        max_ports: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityWritePlanError> {
        Self::from_inputs(
            effects.iter().map(|effect| Ok((&effect.kind).into())),
            max_ports,
            budget,
        )
    }

    /// Prepare the same original write permits directly from borrowed business facts.
    /// No complete proof-tape allocation is required for mutation coverage.
    pub(super) fn from_inputs<'a, I>(
        kinds: I,
        max_ports: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityWritePlanError>
    where
        I: Clone + Iterator<Item = Result<QuantityKindInput<'a>, QuantityCaptureIssue>>,
    {
        let mut ports = 0usize;
        let mut nested_count = 0usize;
        let mut nested_bytes = 0usize;
        visit_ports(kinds.clone(), |key, before, after| {
            ports = ports.checked_add(1).ok_or_else(|| {
                QuantityWritePlanError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?;
            if ports > max_ports {
                return Err(QuantityWritePlanError::Capacity);
            }
            let mut add = |layout: Layout| -> Result<(), QuantityWritePlanError> {
                nested_count = nested_count.checked_add(1).ok_or_else(|| {
                    QuantityWritePlanError::Deferred(
                        iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                    )
                })?;
                nested_bytes = nested_bytes.checked_add(layout.size()).ok_or_else(|| {
                    QuantityWritePlanError::Deferred(
                        iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                    )
                })?;
                Ok(())
            };
            if let PortKey::Balance(balance) = key {
                let mut failure = None;
                balance
                    .account
                    .for_each_admission_clone_layout(|layout| {
                        if failure.is_none() {
                            failure = add(layout).err();
                        }
                    })
                    .map_err(|_| {
                        QuantityWritePlanError::Deferred(
                            iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                        )
                    })?;
                if let Some(error) = failure {
                    return Err(error);
                }
            }
            add(before.admission_clone_layout().map_err(|_| {
                QuantityWritePlanError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?)?;
            add(after.admission_clone_layout().map_err(|_| {
                QuantityWritePlanError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?)
        })?;
        let backing = Layout::array::<ExpectedQuantityWrite<QuantityWriteKey, Quantity>>(ports)
            .map_err(|_| {
                QuantityWritePlanError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?;
        let key_order_layout = Layout::array::<usize>(ports).map_err(|_| {
            QuantityWritePlanError::Deferred(
                iroha_allocation::AllocationRefusal::DemandOverflow.into(),
            )
        })?;
        let lifecycle_layout = Layout::array::<(
            AssetDefinitionId,
            iroha_data_model::nexus::AxtAssetIncarnationV1,
        )>(ports)
        .map_err(|_| {
            QuantityWritePlanError::Deferred(
                iroha_allocation::AllocationRefusal::DemandOverflow.into(),
            )
        })?;
        let ledger = Layout::array::<AllocationCharge>(nested_count).map_err(|_| {
            QuantityWritePlanError::Deferred(
                iroha_allocation::AllocationRefusal::DemandOverflow.into(),
            )
        })?;
        let bytes = nested_bytes
            .checked_add(backing.size())
            .and_then(|value| value.checked_add(ledger.size()))
            .and_then(|value| value.checked_add(key_order_layout.size()))
            .and_then(|value| value.checked_add(lifecycle_layout.size()))
            .ok_or_else(|| {
                QuantityWritePlanError::Deferred(
                    iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                )
            })?;
        let mut reservation = budget
            .try_reserve_bytes(bytes)
            .map_err(|error| QuantityWritePlanError::Deferred(error.into()))?;
        // Local declaration order retains charges until every partially constructed port drops.
        let mut charges = ChargedBuffer::from_reservation(nested_count, &mut reservation)
            .map_err(prepaid_refusal)?;
        let mut writes =
            ChargedBuffer::from_reservation(ports, &mut reservation).map_err(prepaid_refusal)?;
        let mut key_order =
            ChargedBuffer::from_reservation(ports, &mut reservation).map_err(prepaid_refusal)?;
        let mut lifecycles =
            ChargedBuffer::from_reservation(ports, &mut reservation).map_err(prepaid_refusal)?;
        fn retain(
            reservation: &mut AllocationReservation,
            charges: &mut ChargedBuffer<AllocationCharge>,
            layout: Layout,
        ) -> Result<(), QuantityWritePlanError> {
            let charge = reservation
                .try_split(layout)
                .map_err(|_| QuantityWritePlanError::Capacity)?;
            charges.try_push(charge).map_err(|charge| {
                drop(charge);
                QuantityWritePlanError::Capacity
            })
        }
        visit_ports(kinds, |key, before, after| {
            let (definition, incarnation) = match &key {
                PortKey::Balance(balance) => (balance.definition, balance.incarnation),
                PortKey::Supply(definition, incarnation)
                | PortKey::Retire(definition, incarnation) => (*definition, *incarnation),
            };
            lifecycles.push_reserved((definition.clone(), incarnation));
            let key = match key {
                PortKey::Balance(balance) => {
                    let mut failed = false;
                    balance
                        .account
                        .for_each_admission_clone_layout(|layout| {
                            if retain(&mut reservation, &mut charges, layout).is_err() {
                                failed = true;
                            }
                        })
                        .map_err(|_| {
                            QuantityWritePlanError::Deferred(
                                iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                            )
                        })?;
                    if failed {
                        return Err(QuantityWritePlanError::Capacity);
                    }
                    QuantityWriteKey::Balance(AssetId::with_scope(
                        balance.definition.clone(),
                        balance.account.try_clone_for_admission().map_err(|_| {
                            QuantityWritePlanError::Deferred(
                                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                            )
                        })?,
                        balance.scope,
                    ))
                }
                PortKey::Supply(definition, _) => QuantityWriteKey::Supply(definition.clone()),
                PortKey::Retire(definition, incarnation) => {
                    QuantityWriteKey::Retire(FastpqExecutionAssetV1 {
                        definition: definition.clone(),
                        incarnation,
                    })
                }
            };
            retain(
                &mut reservation,
                &mut charges,
                before.admission_clone_layout().map_err(|_| {
                    QuantityWritePlanError::Deferred(
                        iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                    )
                })?,
            )?;
            let before = before.try_clone_for_admission().map_err(|_| {
                QuantityWritePlanError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
            retain(
                &mut reservation,
                &mut charges,
                after.admission_clone_layout().map_err(|_| {
                    QuantityWritePlanError::Deferred(
                        iroha_allocation::AllocationRefusal::DemandOverflow.into(),
                    )
                })?,
            )?;
            let after = after.try_clone_for_admission().map_err(|_| {
                QuantityWritePlanError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            })?;
            writes
                .try_push(ExpectedQuantityWrite { key, before, after })
                .map_err(|value| {
                    drop(value);
                    QuantityWritePlanError::Capacity
                })
        })?;
        for index in 0..ports {
            key_order.push_reserved(index);
        }
        key_order.as_mut_slice().sort_unstable_by(|left, right| {
            writes.as_slice()[*left]
                .key
                .cmp(&writes.as_slice()[*right].key)
                .then(left.cmp(right))
        });
        if reservation.remaining_bytes() != 0 {
            return Err(QuantityWritePlanError::Capacity);
        }
        Ok(Self {
            writes,
            key_order,
            lifecycles: Some(lifecycles),
            _nested_charges: charges,
            consumed: 0,
            failed: false,
        })
    }

    pub(super) fn consume_balance(
        &mut self,
        key: &AssetId,
        before: &Quantity,
        after: &Quantity,
    ) -> Result<QuantityWritePermit<'_, QuantityWriteKey, Quantity>, QuantityWritePlanError> {
        self.consume_matching(
            |expected| matches!(expected, QuantityWriteKey::Balance(value) if value == key),
            before,
            after,
        )
    }

    /// Consume the original lifecycle erasure only for its retained live incarnation
    /// and zero supply. No generic supply/balance permit can substitute for it.
    pub(super) fn consume_retirement(
        &mut self,
        key: &AssetDefinitionId,
        incarnation: Option<iroha_data_model::nexus::AxtAssetIncarnationV1>,
        before: Option<&Quantity>,
    ) -> Result<QuantityWritePermit<'_, QuantityWriteKey, Quantity>, QuantityWritePlanError> {
        let Some(before) = before else {
            self.failed = true;
            return Err(QuantityWritePlanError::Mismatch);
        };
        self.consume_matching(
            |expected| {
                matches!(expected, QuantityWriteKey::Retire(asset)
                if &asset.definition == key && Some(asset.incarnation) == incarnation)
            },
            before,
            &Quantity::zero(),
        )
    }

    pub(super) fn consume_supply(
        &mut self,
        key: &AssetDefinitionId,
        before: &Quantity,
        after: &Quantity,
    ) -> Result<QuantityWritePermit<'_, QuantityWriteKey, Quantity>, QuantityWritePlanError> {
        self.consume_matching(
            |expected| matches!(expected, QuantityWriteKey::Supply(value) if value == key),
            before,
            after,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> QuantityWritePlan<u64, u64> {
        QuantityWritePlan::new(
            vec![
                ExpectedQuantityWrite {
                    key: 1,
                    before: 10,
                    after: 9,
                },
                ExpectedQuantityWrite {
                    key: 2,
                    before: 0,
                    after: 1,
                },
                ExpectedQuantityWrite {
                    key: 1,
                    before: 9,
                    after: 14,
                },
            ],
            3,
        )
        .unwrap()
    }

    #[test]
    fn exact_repeated_key_sequence_consumes_distinct_original_occurrences() {
        let mut plan = plan();
        let permit = plan.consume(&1, &10, &9).unwrap();
        assert_eq!(permit.parts(), (&1, &10, &9));
        permit.applied();
        plan.consume(&2, &0, &1).unwrap().applied();
        plan.consume(&1, &9, &14).unwrap().applied();
        assert_eq!(plan.finish(), Ok(()));
    }

    #[test]
    fn wrong_key_before_after_and_reordered_port_poison_future_consumption() {
        for (key, before, after) in [(3, 10, 9), (1, 11, 9), (1, 10, 8), (2, 0, 1), (1, 9, 14)] {
            let mut plan = plan();
            assert!(matches!(
                plan.consume(&key, &before, &after),
                Err(QuantityWritePlanError::Mismatch)
            ));
            assert!(matches!(
                plan.consume(&1, &10, &9),
                Err(QuantityWritePlanError::Exhausted)
            ));
            assert_eq!(plan.finish(), Err(QuantityWritePlanError::Mismatch));
        }
    }

    #[test]
    fn omitted_or_extra_ports_and_unreserved_capacity_never_seal() {
        assert_eq!(plan().finish(), Err(QuantityWritePlanError::Incomplete));
        let mut plan = plan();
        plan.consume(&1, &10, &9).unwrap().applied();
        plan.consume(&2, &0, &1).unwrap().applied();
        plan.consume(&1, &9, &14).unwrap().applied();
        assert!(matches!(
            plan.consume(&1, &9, &14),
            Err(QuantityWritePlanError::Exhausted)
        ));
        assert_eq!(plan.finish(), Err(QuantityWritePlanError::Mismatch));
        assert!(matches!(
            QuantityWritePlan::new(
                vec![ExpectedQuantityWrite {
                    key: 1,
                    before: 1,
                    after: 1
                }],
                0
            ),
            Err(QuantityWritePlanError::Capacity)
        ));
        let empty = QuantityWritePlan::<u64, u64>::new(vec![], 0).unwrap();
        assert_eq!(empty.finish(), Ok(()));
        let overallocated = Vec::<ExpectedQuantityWrite<u64, u64>>::with_capacity(8);
        assert!(matches!(
            QuantityWritePlan::new(overallocated, 1),
            Err(QuantityWritePlanError::Capacity)
        ));
    }

    #[test]
    fn dropped_or_unwinding_permit_poison_the_original_operation() {
        let mut abandoned = plan();
        drop(abandoned.consume(&1, &10, &9).unwrap());
        assert_eq!(abandoned.finish(), Err(QuantityWritePlanError::Mismatch));
        let mut interrupted = plan();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = interrupted.consume(&1, &10, &9).unwrap();
            panic!("interrupt the actual write owner");
        }));
        assert!(failure.is_err());
        assert_eq!(interrupted.finish(), Err(QuantityWritePlanError::Mismatch));
    }

    #[test]
    fn canonical_key_index_keeps_original_repeated_occurrences_without_reordering_ports() {
        let mut plan = plan();
        let projections = plan
            .ordered_projections()
            .map(|(key, before, after)| (*key, *before, *after))
            .collect::<Vec<_>>();
        assert_eq!(projections, vec![(1, 10, 9), (1, 9, 14), (2, 0, 1)]);
        plan.consume(&1, &10, &9).unwrap().applied();
        plan.consume(&2, &0, &1).unwrap().applied();
        plan.consume(&1, &9, &14).unwrap().applied();
        assert_eq!(plan.finish(), Ok(()));
    }

    fn removal_plan(amount: u32) -> (QuantityWritePlan<QuantityWriteKey, Quantity>, AssetId) {
        let domain =
            iroha_model_base::domain::DomainId::try_new("quantity-ports", "universal").unwrap();
        let definition =
            AssetDefinitionId::derive_from_components(domain, "units".parse().unwrap());
        let id = AssetId::of(definition.clone(), iroha_test_samples::BOB_ID.clone());
        let plan = QuantityWritePlan::new(
            vec![
                ExpectedQuantityWrite {
                    key: QuantityWriteKey::Balance(id.clone()),
                    before: Quantity::from(amount),
                    after: Quantity::zero(),
                },
                ExpectedQuantityWrite {
                    key: QuantityWriteKey::Supply(definition),
                    before: Quantity::from(10 + amount),
                    after: Quantity::from(10_u32),
                },
            ],
            2,
        )
        .unwrap();
        (plan, id)
    }

    #[test]
    fn account_removal_orders_exact_supply_first_without_changing_canonical_projections() {
        for amount in [0_u32, 3] {
            let (mut plan, id) = removal_plan(amount);
            let before = plan
                .ordered_projections()
                .map(|(key, before, after)| (key.clone(), before.clone(), after.clone()))
                .collect::<Vec<_>>();
            plan.order_supply_before_complete_removal(&id, &Quantity::from(amount))
                .unwrap();
            let after = plan
                .ordered_projections()
                .map(|(key, before, after)| (key.clone(), before.clone(), after.clone()))
                .collect::<Vec<_>>();
            assert_eq!(before, after);
            plan.consume_supply(
                id.definition(),
                &Quantity::from(10 + amount),
                &Quantity::from(10_u32),
            )
            .unwrap()
            .applied();
            plan.consume_balance(&id, &Quantity::from(amount), &Quantity::zero())
                .unwrap()
                .applied();
            assert_eq!(plan.finish(), Ok(()));
        }
    }

    #[test]
    fn account_removal_ordering_refuses_wrong_key_partial_balance_and_reuse() {
        for mutation in 0..5 {
            let (mut plan, id) = removal_plan(3);
            match mutation {
                0 => plan.writes.as_mut_slice()[0].before = Quantity::from(4_u32),
                1 => plan.writes.as_mut_slice()[0].after = Quantity::from(1_u32),
                2 => {
                    plan.writes.as_mut_slice()[0].key = QuantityWriteKey::Balance(AssetId::of(
                        id.definition().clone(),
                        iroha_test_samples::ALICE_ID.clone(),
                    ))
                }
                3 => plan
                    .order_supply_before_complete_removal(&id, &Quantity::from(3_u32))
                    .unwrap(),
                4 => plan
                    .consume_balance(&id, &Quantity::from(3_u32), &Quantity::zero())
                    .unwrap()
                    .applied(),
                _ => unreachable!(),
            }
            assert!(
                plan.order_supply_before_complete_removal(&id, &Quantity::from(3_u32))
                    .is_err()
            );
            assert!(
                plan.order_supply_before_complete_removal(&id, &Quantity::from(3_u32))
                    .is_err()
            );
            assert_eq!(plan.finish(), Err(QuantityWritePlanError::Mismatch));
        }
    }

    #[test]
    fn account_removal_missing_reordered_stale_and_extra_ports_cannot_seal() {
        for mutation in 0..4 {
            let (mut plan, id) = removal_plan(3);
            plan.order_supply_before_complete_removal(&id, &Quantity::from(3_u32))
                .unwrap();
            if mutation == 0 {
                assert!(
                    plan.consume_balance(&id, &Quantity::from(3_u32), &Quantity::zero())
                        .is_err()
                );
            } else if mutation == 1 {
                assert!(
                    plan.consume_supply(
                        id.definition(),
                        &Quantity::from(12_u32),
                        &Quantity::from(10_u32)
                    )
                    .is_err()
                );
            } else {
                plan.consume_supply(
                    id.definition(),
                    &Quantity::from(13_u32),
                    &Quantity::from(10_u32),
                )
                .unwrap()
                .applied();
                if mutation == 3 {
                    plan.consume_balance(&id, &Quantity::from(3_u32), &Quantity::zero())
                        .unwrap()
                        .applied();
                    assert!(
                        plan.consume_balance(&id, &Quantity::from(3_u32), &Quantity::zero())
                            .is_err()
                    );
                }
            }
            assert!(plan.finish().is_err());
        }
    }
}
