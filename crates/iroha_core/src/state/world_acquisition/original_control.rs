//! Original-pool World shell and Cell successor custody before physical writers.
//!
//! This covers these exact allocations only. EBR generations, release controls,
//! nested values and mutation growth remain separate admission obligations.

use super::{CellAcquisition, OrdinaryAcquisition, WorldFieldAcquisition};
use crate::state::{Storage, TriggerSet, WorldBlockFields};
use iroha_allocation::{
    AllocationBudget, AllocationReservation, ChargedBuffer, ChargedBufferError, PrepaidBufferError,
};
use mv::{
    Key, Value,
    cell::{Cell, CellAllocationCharges, CellPublicationSuccessor, CellPublicationSuccessorError},
    storage::AdmittedStorageError,
};
use std::{
    alloc::Layout,
    ops::{Deref, DerefMut},
};

/// One fixed backing allocation remains original through all World phases.
/// The Vec destroys fields in place, then frees backing, then refunds its charge.
/// It is private, unique, cannot grow, and is never copied into another heap shell.
pub(in crate::state) struct OriginalWorldFields<'world> {
    values: ChargedBuffer<WorldBlockFields<'world>>,
    // Initialized fields in the sole exhaustive placement order, while len is 0.
    // A completed World resets this to zero and lets the Vec drop it in place.
    initialized: usize,
}

impl<'world> OriginalWorldFields<'world> {
    pub(in crate::state) fn layout() -> Layout {
        Layout::new::<WorldBlockFields<'world>>()
    }

    pub(in crate::state) fn reserve(
        parent: &mut AllocationReservation,
    ) -> Result<Self, AdmittedStorageError> {
        ChargedBuffer::from_reservation(1, parent)
            .map(|values| Self {
                values,
                initialized: 0,
            })
            .map_err(|error| match error {
                PrepaidBufferError::Reservation(error) => AdmittedStorageError::PolicyDemand {
                    expected_bytes: error.requested_bytes,
                    remaining_bytes: error.remaining_bytes,
                },
                PrepaidBufferError::Allocation(ChargedBufferError::Admission(error)) => {
                    AdmittedStorageError::Allocation(error)
                }
                PrepaidBufferError::Allocation(ChargedBufferError::Allocator {
                    requested_bytes,
                }) => AdmittedStorageError::Allocator {
                    layout: Layout::from_size_align(requested_bytes, Self::layout().align())
                        .expect("original World layout"),
                },
            })
    }

    #[cfg(test)]
    pub(in crate::state) fn belongs_to(&self, source: &AllocationBudget) -> bool {
        self.values.belongs_to(source)
    }
}

impl<'world> Deref for OriginalWorldFields<'world> {
    type Target = WorldBlockFields<'world>;
    fn deref(&self) -> &Self::Target {
        self.values
            .as_slice()
            .first()
            .expect("original World fields")
    }
}
impl DerefMut for OriginalWorldFields<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.values
            .as_mut_slice()
            .first_mut()
            .expect("original World fields")
    }
}

#[path = "placement.rs"]
mod placement;
#[cfg(test)]
pub(super) use placement::with_placement_failure;
pub(in crate::state) use placement::{ReleaseWorldAcquisition, WorldPlacement};

/// Source-type dispatch covers the sole World inventory without another field list.
pub(in crate::state) trait OriginalControlSource {
    type Acquisition<'a>: WorldFieldAcquisition
    where
        Self: 'a;
    fn successor_layout(&self) -> Option<Layout>;
    fn generation_layouts(&self) -> [Option<Layout>; 2] {
        [None, None]
    }
    fn original_acquisition<'a>(
        &'a self,
        budget: &AllocationBudget,
        parent: &mut AllocationReservation,
    ) -> Result<Self::Acquisition<'a>, AdmittedStorageError>;
}

/// Account for one store before reserving the complete World control inventory.
/// Per-store iterators must leave the stack before acquisition starts; a macro
/// expansion of every iterator otherwise retains all of them in the World frame.
#[inline(never)]
pub(in crate::state) fn add_original_control_demand<S: OriginalControlSource>(
    source: &S,
    demand: &mut usize,
) -> Result<(), AdmittedStorageError> {
    for layout in source
        .generation_layouts()
        .into_iter()
        .chain([source.successor_layout()])
        .flatten()
    {
        *demand = demand
            .checked_add(layout.size())
            .ok_or(AdmittedStorageError::Allocation(
                iroha_allocation::AllocationRefusal::DemandOverflow,
            ))?;
    }
    Ok(())
}

/// Fill one original inert slot without returning its large acquisition value
/// through the complete World census frame. No physical acquisition occurs here.
#[inline(never)]
pub(in crate::state) fn initialize_original_field<'a, S: OriginalControlSource>(
    slot: &mut Option<S::Acquisition<'a>>,
    target: &'a S,
    budget: &AllocationBudget,
    parent: &mut AllocationReservation,
) -> Result<(), AdmittedStorageError> {
    assert!(slot.is_none(), "original acquisition slot is one-shot");
    *slot = Some(target.original_acquisition(budget, parent)?);
    Ok(())
}

/// Split and allocate one actual Cell successor before any physical acquisition.
/// The original parent and token must belong to the same configured execution pool.
pub(in crate::state) fn original_cell<'a, V: Value>(
    target: &'a Cell<V>,
    budget: &AllocationBudget,
    parent: &mut AllocationReservation,
) -> Result<mv::cell::BlockAcquisitionSlot<'a, V>, AdmittedStorageError> {
    if !parent.belongs_to(budget) {
        return Err(AdmittedStorageError::PolicyIdentity);
    }
    let layout = CellPublicationSuccessor::allocation_layout();
    let charge = parent
        .try_split(layout)
        .map_err(|error| AdmittedStorageError::PolicyDemand {
            expected_bytes: error.requested_bytes,
            remaining_bytes: error.remaining_bytes,
        })?;
    let successor =
        CellPublicationSuccessor::try_from_charge(budget, charge).map_err(|(charge, error)| {
            // No writer or new token exists on refusal. Reclaim only this unused charge.
            drop(charge);
            match error {
                CellPublicationSuccessorError::ForeignPool => AdmittedStorageError::PolicyIdentity,
                CellPublicationSuccessorError::LayoutMismatch { expected, actual } => {
                    AdmittedStorageError::PolicyDemand {
                        expected_bytes: expected.size(),
                        remaining_bytes: actual.size(),
                    }
                }
                CellPublicationSuccessorError::Allocator { layout } => {
                    AdmittedStorageError::Allocator { layout }
                }
            }
        })?;
    // EBR allocations are deliberately still untracked. The prepaid token funds
    // only its actual shared identity, never these separate generation allocations.
    let charges =
        CellAllocationCharges::new(concread::ebrcell::Untracked, concread::ebrcell::Untracked);
    target
        .try_block_acquisition_with_successor(charges, successor, budget)
        .map_err(|(_charges, _successor)| AdmittedStorageError::PolicyIdentity)
}

impl<V: Value> OriginalControlSource for Cell<V> {
    type Acquisition<'a>
        = CellAcquisition<'a, V>
    where
        Self: 'a;
    fn successor_layout(&self) -> Option<Layout> {
        Some(CellPublicationSuccessor::allocation_layout())
    }
    fn original_acquisition<'a>(
        &'a self,
        budget: &AllocationBudget,
        parent: &mut AllocationReservation,
    ) -> Result<Self::Acquisition<'a>, AdmittedStorageError> {
        original_cell(self, budget, parent).map(CellAcquisition)
    }
}

impl<V: Value> OriginalControlSource for Cell<V, iroha_allocation::AllocationCharge> {
    type Acquisition<'a>
        = CellAcquisition<'a, V, iroha_allocation::AllocationCharge>
    where
        Self: 'a;
    fn successor_layout(&self) -> Option<Layout> {
        Some(CellPublicationSuccessor::allocation_layout())
    }
    fn generation_layouts(&self) -> [Option<Layout>; 2] {
        Cell::<V, iroha_allocation::AllocationCharge>::allocation_layouts().map(Some)
    }
    fn original_acquisition<'a>(
        &'a self,
        budget: &AllocationBudget,
        parent: &mut AllocationReservation,
    ) -> Result<Self::Acquisition<'a>, AdmittedStorageError> {
        if !parent.belongs_to(budget) {
            return Err(AdmittedStorageError::PolicyIdentity);
        }
        let [current, undo] = Cell::<V, iroha_allocation::AllocationCharge>::allocation_layouts();
        let split = |parent: &mut AllocationReservation, layout| {
            parent
                .try_split(layout)
                .map_err(|error| AdmittedStorageError::PolicyDemand {
                    expected_bytes: error.requested_bytes,
                    remaining_bytes: error.remaining_bytes,
                })
        };
        let current = split(parent, current)?;
        let undo = split(parent, undo)?;
        let successor_charge = split(parent, CellPublicationSuccessor::allocation_layout())?;
        let successor = CellPublicationSuccessor::try_from_charge(budget, successor_charge)
            .map_err(|(charge, error)| {
                drop(charge);
                match error {
                    CellPublicationSuccessorError::ForeignPool => {
                        AdmittedStorageError::PolicyIdentity
                    }
                    CellPublicationSuccessorError::LayoutMismatch { expected, actual } => {
                        AdmittedStorageError::PolicyDemand {
                            expected_bytes: expected.size(),
                            remaining_bytes: actual.size(),
                        }
                    }
                    CellPublicationSuccessorError::Allocator { layout } => {
                        AdmittedStorageError::Allocator { layout }
                    }
                }
            })?;
        let backing = mv::cell::CellGenerationBacking::try_from_charges(
            budget,
            CellAllocationCharges::new(current, undo),
        )
        .map_err(|(charges, error)| {
            drop(charges);
            match error {
                mv::cell::CellGenerationBackingError::ForeignPool => {
                    AdmittedStorageError::PolicyIdentity
                }
                mv::cell::CellGenerationBackingError::LayoutMismatch { expected, actual } => {
                    AdmittedStorageError::PolicyDemand {
                        expected_bytes: expected.size(),
                        remaining_bytes: actual.size(),
                    }
                }
                mv::cell::CellGenerationBackingError::Allocator { layout } => {
                    AdmittedStorageError::Allocator { layout }
                }
            }
        })?;
        self.try_block_acquisition_with_backing(backing, successor, budget)
            .map(CellAcquisition)
            .map_err(|_| AdmittedStorageError::PolicyIdentity)
    }
}

impl<K: Key, V: Value> OriginalControlSource for Storage<K, V> {
    type Acquisition<'a>
        = OrdinaryAcquisition<mv::storage::BlockAcquisitionSlot<'a, K, V>>
    where
        Self: 'a;
    fn successor_layout(&self) -> Option<Layout> {
        None
    }
    fn original_acquisition<'a>(
        &'a self,
        _: &AllocationBudget,
        _: &mut AllocationReservation,
    ) -> Result<Self::Acquisition<'a>, AdmittedStorageError> {
        Ok(OrdinaryAcquisition(self.block_acquisition()))
    }
}

impl OriginalControlSource for TriggerSet {
    type Acquisition<'a>
        = OrdinaryAcquisition<crate::smartcontracts::isi::triggers::set::SetBlockAcquisition<'a>>
    where
        Self: 'a;
    fn successor_layout(&self) -> Option<Layout> {
        None
    }
    fn original_acquisition<'a>(
        &'a self,
        _: &AllocationBudget,
        _: &mut AllocationReservation,
    ) -> Result<Self::Acquisition<'a>, AdmittedStorageError> {
        Ok(OrdinaryAcquisition(self.block_acquisition()))
    }
}
