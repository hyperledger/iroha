//! Prepaid host-protected return PCs for deployable contract calls.
//!
//! A funded VM allocates the complete bounded backing on its first nested call.
//! The original State execution charge stays with that backing through warm
//! reuse, worker copies, cache eviction, and the final VM owner.

use std::ops::Deref;

use iroha_allocation::AllocationBudget;

use crate::{
    VMError,
    cache_memory::OwnedVec,
    error::ExecutionDeferral,
    execution_memory::{ExecutionBuffer, ExecutionMemoryLease, ExecutionMemoryPlan},
    limits::MAX_CONTRACT_CALL_DEPTH,
};

enum Storage {
    Local(OwnedVec<u64>),
    Funded {
        budget: AllocationBudget,
        values: Option<ExecutionBuffer<u64>>,
    },
}

/// Owns the return-PC backing and its allocation-lifetime charges together.
pub(crate) struct ContractReturnStack(Storage);

impl Default for ContractReturnStack {
    fn default() -> Self {
        Self(Storage::Local(OwnedVec::default()))
    }
}

impl ContractReturnStack {
    /// Bind future backing allocation to the State-owned active execution pool.
    pub(crate) fn with_memory_budget(budget: &AllocationBudget) -> Self {
        Self(Storage::Funded {
            budget: budget.clone(),
            values: None,
        })
    }

    /// Complete any backing allocation before call gas or frame authority changes.
    pub(crate) fn preflight_one(&mut self) -> Result<(), VMError> {
        if self.len() >= MAX_CONTRACT_CALL_DEPTH {
            return Err(VMError::AssertionFailed);
        }
        match &mut self.0 {
            Storage::Local(values) => values
                .try_reserve_one()
                .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)),
            Storage::Funded { budget, values } => {
                if values.is_none() {
                    let plan = ExecutionMemoryPlan::array::<u64>(MAX_CONTRACT_CALL_DEPTH)
                        .map_err(VMError::AllocationDeferred)?;
                    let mut lease = ExecutionMemoryLease::reserve(budget, plan)
                        .map_err(VMError::AllocationDeferred)?;
                    *values = Some(
                        ExecutionBuffer::new(MAX_CONTRACT_CALL_DEPTH, &mut lease).map_err(
                            |_| {
                                VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
                            },
                        )?,
                    );
                }
                Ok(())
            }
        }
    }

    /// Install a return PC only after `preflight_one` succeeded.
    pub(crate) fn push_reserved(&mut self, return_pc: u64) {
        match &mut self.0 {
            Storage::Local(values) => values.insert_reserved(values.len(), return_pc),
            Storage::Funded { values, .. } => values
                .as_mut()
                .expect("funded return stack was preflighted")
                .append(&[return_pc])
                .expect("protected call depth is bounded"),
        }
    }

    /// Remove the most recent return PC without releasing live backing credit.
    pub(crate) fn pop(&mut self) -> Option<u64> {
        match &mut self.0 {
            Storage::Local(values) => values.pop(),
            Storage::Funded { values, .. } => {
                let values = values.as_mut()?;
                let previous = values.as_slice().last().copied()?;
                values.truncate(values.as_slice().len() - 1);
                Some(previous)
            }
        }
    }

    /// Clear call state while keeping the backing and its owner for reuse.
    pub(crate) fn clear(&mut self) {
        match &mut self.0 {
            Storage::Local(values) => values.clear(),
            Storage::Funded { values, .. } => {
                if let Some(values) = values {
                    values.truncate(0);
                }
            }
        }
    }

    /// Drop spare local capacity; a funded backing remains owned by its VM.
    pub(crate) fn compact_for_cache(&mut self) {
        match &mut self.0 {
            Storage::Local(values) => values.clear_and_shrink(),
            Storage::Funded { values, .. } => {
                if let Some(values) = values {
                    values.truncate(0);
                }
            }
        }
    }

    /// Copy a test snapshot's return PCs with an independent prepaid backing.
    #[cfg(test)]
    pub(crate) fn try_copy_exact(&self) -> Result<Self, VMError> {
        match &self.0 {
            Storage::Local(values) => values
                .try_copy_exact()
                .map(|values| Self(Storage::Local(values)))
                .map_err(|_| VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)),
            Storage::Funded { budget, values } => {
                let mut copy = Self::with_memory_budget(budget);
                if let Some(values) = values {
                    copy.preflight_one()?;
                    let Storage::Funded {
                        values: Some(destination),
                        ..
                    } = &mut copy.0
                    else {
                        unreachable!("preflight installed the funded backing")
                    };
                    destination
                        .append(values.as_slice())
                        .expect("source return stack fits its fixed capacity");
                }
                Ok(copy)
            }
        }
    }

    /// Admit the existing backing to aggregate idle retention.
    pub(crate) fn try_retain(&self) -> bool {
        match &self.0 {
            Storage::Local(values) => values.try_retain(),
            Storage::Funded { values, .. } => {
                values.as_ref().is_none_or(ExecutionBuffer::try_retain)
            }
        }
    }

    /// Move a retained backing to active cache accounting on checkout.
    pub(crate) fn make_active(&self) {
        match &self.0 {
            Storage::Local(values) => values.make_active(),
            Storage::Funded { values, .. } => {
                if let Some(values) = values {
                    values.activate();
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn try_push(&mut self, return_pc: u64) -> Result<(), VMError> {
        self.preflight_one()?;
        self.push_reserved(return_pc);
        Ok(())
    }
}

impl Deref for ContractReturnStack {
    type Target = [u64];

    fn deref(&self) -> &[u64] {
        match &self.0 {
            Storage::Local(values) => values,
            Storage::Funded { values, .. } => {
                values.as_ref().map_or(&[], ExecutionBuffer::as_slice)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKING_BYTES: usize = MAX_CONTRACT_CALL_DEPTH * std::mem::size_of::<u64>();

    #[test]
    fn funded_return_stack_refuses_before_allocating_or_mutating() {
        let budget = AllocationBudget::new(BACKING_BYTES - 1);
        let mut stack = ContractReturnStack::with_memory_budget(&budget);
        assert!(matches!(
            stack.preflight_one(),
            Err(VMError::AllocationDeferred(_))
        ));
        assert!(stack.is_empty());
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(BACKING_BYTES);
        stack.try_push(7).unwrap();
        assert_eq!(&*stack, &[7]);
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        assert_eq!(stack.pop(), Some(7));
        stack.clear();
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        drop(stack);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn worker_copy_and_idle_compaction_keep_each_original_owner_alive() {
        let budget = AllocationBudget::new(BACKING_BYTES * 2);
        let mut stack = ContractReturnStack::with_memory_budget(&budget);
        stack.try_push(11).unwrap();
        stack.try_push(13).unwrap();
        let mut copy = stack.try_copy_exact().unwrap();
        assert_eq!(&*copy, &[11, 13]);
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES * 2);
        stack.clear();
        stack.compact_for_cache();
        assert!(stack.is_empty());
        let _admitted_to_retention = stack.try_retain();
        budget.set_limit_bytes(0);
        stack.make_active();
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES * 2);
        drop(stack);
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        assert_eq!(copy.pop(), Some(13));
        drop(copy);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn protected_depth_limit_retains_full_lifo_stack_on_refusal_and_reuses_popped_slot() {
        let budget = AllocationBudget::new(BACKING_BYTES);
        let mut stack = ContractReturnStack::with_memory_budget(&budget);
        assert!(stack.is_empty()); // The root sentinel is not a nested return PC.
        for return_pc in 0..MAX_CONTRACT_CALL_DEPTH as u64 {
            stack.try_push(return_pc).unwrap();
        }
        assert_eq!(stack.len(), MAX_CONTRACT_CALL_DEPTH);
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        for _ in 0..2 {
            assert!(matches!(
                stack.try_push(u64::MAX),
                Err(VMError::AssertionFailed)
            ));
            assert_eq!(stack.len(), MAX_CONTRACT_CALL_DEPTH);
            assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        }
        assert_eq!(stack.pop(), Some(MAX_CONTRACT_CALL_DEPTH as u64 - 1));
        stack.try_push(u64::MAX).unwrap();
        assert_eq!(stack.pop(), Some(u64::MAX));
        for expected in (0..MAX_CONTRACT_CALL_DEPTH as u64 - 1).rev() {
            assert_eq!(stack.pop(), Some(expected));
        }
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());
        assert_eq!(budget.reserved_bytes(), BACKING_BYTES);
        drop(stack);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn local_stack_keeps_standalone_behavior_and_releases_spare_cache_capacity() {
        let mut stack = ContractReturnStack::default();
        stack.try_push(3).unwrap();
        let copy = stack.try_copy_exact().unwrap();
        assert_eq!(&*copy, &[3]);
        assert_eq!(stack.pop(), Some(3));
        stack.compact_for_cache();
        assert!(stack.is_empty());
    }
}
