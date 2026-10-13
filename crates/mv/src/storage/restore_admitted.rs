//! Stream originally owned authenticated snapshot entries into original admitted maps.

use super::*;
use concread::bptree::{ClonePlanning, Prepaid};
use iroha_allocation::AllocationBudget;

impl<K, V, P> Storage<K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Restore owned current values and exact undo preimages directly.
    ///
    /// The source callback feeds one already admitted owned entry at a time. Its retained allocation
    /// custody must move with the value; this method funds map nodes only.
    /// Every insertion admits its original map plan before allocating; no
    /// intermediate untracked map or post-load recharge exists. Both maps stay
    /// private until the complete callback accepts the source schema.
    /// Callback or capacity refusal drops the entire original private restore.
    ///
    /// The callback owns canonical ordering, duplicate rejection and source
    /// authentication. Input decoding/work and native runtime control are not
    /// inferred by node admission. This interface cannot publish a partial map.
    pub fn try_restore_admitted<E>(
        budget: AllocationBudget,
        restore: impl FnOnce(
            &mut dyn FnMut(K, V) -> Result<(), AdmittedStorageError>,
            &mut dyn FnMut(K, Option<V>) -> Result<(), AdmittedStorageError>,
        ) -> Result<(), E>,
    ) -> Result<Self, AdmittedBlockError<E>> {
        budget.with_deferred_refund_notifications(|_| {
            let target =
                Self::try_new_admitted(budget.clone()).map_err(AdmittedBlockError::Admission)?;
            let AdmittedWriters { mut writers, next } = target
                .open_admitted_writers()
                .map_err(AdmittedBlockError::Admission)?;
            {
                let OriginalWriters { revert, blocks } = writers.as_mut();
                let mut current_entry = |key, value| {
                    blocks
                        .try_insert_admitted(key, value, |demand| admit::<P>(&budget, demand))
                        .map(|_| ())
                        .map_err(|(_input, error)| edit_error(error))
                };
                let mut undo_entry = |key, value| {
                    revert
                        .try_insert_admitted(key, value, |demand| admit::<P>(&budget, demand))
                        .map(|_| ())
                        .map_err(|(_input, error)| edit_error(error))
                };
                restore(&mut current_entry, &mut undo_entry)
                    .map_err(AdmittedBlockError::Callback)?;
            }
            let predecessor = target.publication.capture();
            writers.prepare_publication(&predecessor, true);
            let mut next = Some(next);
            writers.publish_prepared(&mut next);
            drop(writers);
            Ok(target)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use concread::bptree::{NodeCloning, NodeFunding};
    use std::alloc::Layout;

    struct Policy(AllocationReservation);
    impl NodeFunding for Policy {
        type Charge = AllocationCharge;
        fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
            self.0.try_split(layout).expect("original planned layout")
        }
    }
    impl<V: Copy> NodeCloning<u64, V> for Policy {
        fn clone_key(&mut self, key: &u64) -> u64 {
            *key
        }
        fn clone_value(&mut self, value: &V) -> V {
            *value
        }
    }
    impl<V: Copy> ClonePlanning<u64, V> for Policy {
        fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
            Ok(())
        }
        fn plan_value(_: &V, _: &mut AllocationDemand) -> Result<(), PlanningError> {
            Ok(())
        }
    }
    impl AdmittedStoragePolicy for Policy {
        fn from_admission(admission: AllocationReservation) -> Self {
            Self(admission)
        }
        fn admission(&self) -> &AllocationReservation {
            &self.0
        }
    }
    type Target = Storage<u64, u64, Prepaid<Policy>>;

    #[test]
    fn original_pool_handle_and_refusals_preserve_exact_retry_observation() {
        let budget = AllocationBudget::new(1 << 20);
        let target = Target::try_new_admitted(budget.clone()).unwrap();
        let held = target.allocation_budget().try_reserve_bytes(7).unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            Target::initial_allocation_demand().unwrap().bytes() + 7
        );
        let notification = crate::ReleaseNotification::default();
        let release = notification.observe();
        let busy = AdmittedStorageError::Busy {
            role: super::super::StorageRole::Current,
            release: release.clone(),
        };
        assert_eq!(busy.release_wait(), Some(&release));
        assert_eq!(busy.clone(), busy);
        let capacity =
            AdmittedStorageError::Allocation(iroha_allocation::AllocationRefusal::Capacity {
                requested_bytes: 9,
                reserved_bytes: 8,
                limit_bytes: 10,
                release: release.clone(),
            });
        assert_eq!(capacity.release_wait(), Some(&release));
        assert!(AdmittedStorageError::ScopeIdentity.release_wait().is_none());
        assert!(
            AdmittedStorageError::Planning(concread::bptree::PlanningError::Overflow)
                .release_wait()
                .is_none()
        );
        assert!(
            busy.to_string()
                .contains("original storage admission refused")
        );
        drop(held);
        drop(target);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn streamed_admitted_restore_retains_exact_current_and_undo_in_one_pool() {
        let budget = AllocationBudget::new(1 << 20);
        let target = Target::try_restore_admitted(budget.clone(), |current, undo| {
            for (key, value) in [(1, Some(10)), (2, Some(20)), (3, None), (4, None)] {
                undo(key, value)?;
            }
            for (key, value) in [(1, 11), (3, 30)] {
                current(key, value)?;
            }
            Ok::<_, AdmittedStorageError>(())
        })
        .unwrap();
        assert_eq!(target.view().get(&1), Some(&11));
        assert_eq!(target.view().get(&2), None);
        let snapshot = target.snapshot();
        assert_eq!(snapshot.revert_map().get(&1), Some(&Some(10)));
        assert_eq!(snapshot.revert_map().get(&2), Some(&Some(20)));
        assert_eq!(snapshot.revert_map().get(&3), Some(&None));
        assert_eq!(snapshot.revert_map().get(&4), Some(&None));
        let bytes = budget.reserved_bytes();
        // These inline records fit the original leaf counts. Restore retires
        // both replaced empty readers and private writer shells after publish.
        assert_eq!(bytes, Target::initial_allocation_demand().unwrap().bytes());
        drop(snapshot);
        drop(target);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn streamed_admitted_restore_refusal_discards_original_partial_restore() {
        let budget = AllocationBudget::new(1 << 20);
        let result = Target::try_restore_admitted(budget.clone(), |current, undo| {
            undo(1, Some(10))?;
            let held = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let result = current(1, 11);
            assert!(matches!(result, Err(AdmittedStorageError::Allocation(_))));
            drop(held);
            result
        });
        assert!(matches!(
            result,
            Err(AdmittedBlockError::Callback(
                AdmittedStorageError::Allocation(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        let target =
            Target::try_restore_admitted(budget.clone(), |current, _| current(1, 11)).unwrap();
        assert_eq!(target.view().get(&1), Some(&11));
        drop(target);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn streamed_admitted_restore_initial_refusal_precedes_source_callback() {
        let bytes = Target::initial_allocation_demand().unwrap().bytes();
        let budget = AllocationBudget::new(bytes - 1);
        let result = Target::try_restore_admitted::<()>(budget.clone(), |_, _| {
            panic!("source is not consumed before original startup admission")
        });
        assert!(matches!(
            result,
            Err(AdmittedBlockError::Admission(
                AdmittedStorageError::Allocation(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    // A closed shallow-sharing policy for a genuinely non-Copy retained value.
    // The payload's original prepaid shell is shared, never cloned into a new pool.
    type Retained = iroha_allocation::ChargedShared<u64>;
    struct RetainedPolicy(AllocationReservation);
    impl NodeFunding for RetainedPolicy {
        type Charge = AllocationCharge;
        fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
            self.0.try_split(layout).expect("original planned node")
        }
    }
    macro_rules! retained_policy {
        ($value:ty) => {
            impl NodeCloning<u64, $value> for RetainedPolicy {
                fn clone_key(&mut self, key: &u64) -> u64 {
                    *key
                }
                fn clone_value(&mut self, value: &$value) -> $value {
                    value.clone()
                }
            }
            impl ClonePlanning<u64, $value> for RetainedPolicy {
                fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                    Ok(())
                }
                fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                    Ok(())
                }
            }
        };
    }
    retained_policy!(Retained);
    retained_policy!(Option<Retained>);
    impl AdmittedStoragePolicy for RetainedPolicy {
        fn from_admission(admission: AllocationReservation) -> Self {
            Self(admission)
        }
        fn admission(&self) -> &AllocationReservation {
            &self.0
        }
    }
    type RetainedTarget = Storage<u64, Retained, Prepaid<RetainedPolicy>>;

    fn retained(value: u64, budget: &AllocationBudget) -> Retained {
        let mut reservation = budget.try_reserve(Retained::allocation_layout()).unwrap();
        Retained::from_reservation(value, &mut reservation).unwrap()
    }

    #[test]
    fn non_copy_restore_shares_original_current_and_exact_undo_owners() {
        let budget = AllocationBudget::new(1 << 20);
        let current = retained(11, &budget);
        let predecessor = retained(10, &budget);
        let inserted = retained(30, &budget);
        let payload_bytes = 3 * Retained::allocation_layout().size();
        let target = RetainedTarget::try_restore_admitted(budget.clone(), |put, undo| {
            undo(1, Some(predecessor.clone()))?;
            undo(3, None)?;
            put(1, current.clone())?;
            put(3, inserted.clone())
        })
        .unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            payload_bytes + RetainedTarget::initial_allocation_demand().unwrap().bytes()
        );
        let snapshot = target.snapshot();
        assert!(Retained::ptr_eq(
            snapshot.current().get(&1).unwrap(),
            &current
        ));
        assert!(Retained::ptr_eq(
            snapshot.current().get(&3).unwrap(),
            &inserted
        ));
        assert!(Retained::ptr_eq(
            snapshot.revert_map().get(&1).unwrap().as_ref().unwrap(),
            &predecessor
        ));
        assert!(snapshot.revert_map().get(&3).unwrap().is_none());
        let bytes = budget.reserved_bytes();
        budget.set_limit_bytes(0);
        let view = target.view();
        assert!(Retained::ptr_eq(view.get(&1).unwrap(), &current));
        assert_eq!(
            budget.reserved_bytes(),
            bytes,
            "readers share the original owners"
        );
        drop(view);
        assert!(snapshot.current().get(&1).unwrap().belongs_to(&budget));
        assert!(
            snapshot
                .revert_map()
                .get(&1)
                .unwrap()
                .as_ref()
                .unwrap()
                .belongs_to(&budget)
        );
        drop(snapshot);
        drop(target);
        assert_eq!(budget.reserved_bytes(), payload_bytes);
        drop((current, predecessor, inserted));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn non_copy_restore_refusal_releases_private_maps_but_keeps_input_custody() {
        let budget = AllocationBudget::new(1 << 20);
        let predecessor = retained(10, &budget);
        let current = retained(11, &budget);
        let payload_bytes = 2 * Retained::allocation_layout().size();
        let result = RetainedTarget::try_restore_admitted(budget.clone(), |put, undo| {
            undo(1, Some(predecessor.clone()))?;
            let held = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let refusal = put(1, current.clone());
            assert!(matches!(refusal, Err(AdmittedStorageError::Allocation(_))));
            drop(held);
            refusal
        });
        assert!(matches!(
            result,
            Err(AdmittedBlockError::Callback(
                AdmittedStorageError::Allocation(_)
            ))
        ));
        assert_eq!(budget.reserved_bytes(), payload_bytes);
        assert!(predecessor.belongs_to(&budget));
        assert!(current.belongs_to(&budget));
        let target = RetainedTarget::try_restore_admitted(budget.clone(), |put, undo| {
            undo(1, Some(predecessor.clone()))?;
            put(1, current.clone())
        })
        .unwrap();
        assert!(Retained::ptr_eq(target.view().get(&1).unwrap(), &current));
        drop(target);
        assert_eq!(budget.reserved_bytes(), payload_bytes);
        drop((current, predecessor));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
