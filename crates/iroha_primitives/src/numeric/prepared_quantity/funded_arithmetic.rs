//! Exact original-pool custody for inline arithmetic results and borrowed copies.

use super::*;

impl ChargedQuantity {
    /// Copy a borrowed quantity into exactly admitted immutable native digits.
    ///
    /// No arithmetic scratch is allocated. The returned owner destroys the copied
    /// value before refunding its original pool, including during unwinding.
    ///
    /// # Errors
    /// Preserves the original capacity observation or physical allocator refusal.
    pub fn try_copy(
        source: &Quantity,
        budget: &AllocationBudget,
    ) -> Result<Self, ChargedBufferError> {
        Self::try_from_accumulator(QuantityAccumulator::from_quantity(source), budget)
    }

    /// Materialize one inline result with its exact original-pool digit charge.
    ///
    /// # Errors
    /// Capacity exhaustion retains the original release observation. Physical
    /// allocator failure is distinct and never invents a release wait.
    pub fn try_from_accumulator(
        aggregate: QuantityAccumulator,
        budget: &AllocationBudget,
    ) -> Result<Self, ChargedBufferError> {
        let layout = aggregate
            .admission_layout()
            .map_err(|_| iroha_allocation::AllocationRefusal::DemandOverflow)?;
        let charge = budget
            .try_reserve(layout)?
            .try_split(layout)
            .expect("the reservation covers the exact native digits");
        Self::try_from_accumulator_charge(aggregate, budget, charge).map_err(|(_, error)| {
            match error {
                QuantityBackingError::Allocation(ChargedBufferFromChargeError::Allocator {
                    layout,
                }) => ChargedBufferError::Allocator {
                    requested_bytes: layout.size(),
                },
                _ => unreachable!("fresh exact original charge matches the inline result"),
            }
        })
    }

    /// Materialize inline arithmetic using an already partitioned original charge.
    ///
    /// No admission, refund or replacement occurs on failure: the exact charge
    /// is returned beside the cause. The copyable inline source remains available
    /// to retry after allocator recovery; a capacity release cannot help that case.
    ///
    /// # Errors
    /// Returns the unchanged charge on foreign pool, layout mismatch or allocator
    /// refusal. Both size and alignment must equal the actual native-digit layout.
    pub fn try_from_accumulator_charge(
        aggregate: QuantityAccumulator,
        budget: &AllocationBudget,
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, QuantityBackingError)> {
        if !charge.belongs_to(budget) {
            return Err((charge, QuantityBackingError::ForeignPool));
        }
        let layout = match aggregate.admission_layout() {
            Ok(layout) => layout,
            Err(_) => {
                return Err((
                    charge,
                    QuantityBackingError::Allocation(ChargedBufferFromChargeError::DemandOverflow),
                ));
            }
        };
        if charge.layout() != layout {
            let actual = charge.layout();
            return Err((
                charge,
                QuantityBackingError::Allocation(ChargedBufferFromChargeError::LayoutMismatch {
                    expected: layout,
                    actual,
                }),
            ));
        }
        match aggregate.try_into_quantity() {
            Ok(value) => Ok(Self { value, charge }),
            Err(BigIntAdmissionCloneError::Allocator { .. }) => Err((
                charge,
                QuantityBackingError::Allocation(ChargedBufferFromChargeError::Allocator {
                    layout,
                }),
            )),
            Err(_) => Err((
                charge,
                QuantityBackingError::Allocation(ChargedBufferFromChargeError::DemandOverflow),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
