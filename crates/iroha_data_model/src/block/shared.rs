//! One immutable canonical block graph and its exact original shared-control custody.
//!
//! This runtime owner has no codec, mutable escape or untracked constructor. The wire remains
//! `SignedBlockWire`; sharing retains the original allocation and never clones its nested graph.
//! Nested decoded or executed allocations remain separately admitted obligations.

use std::{alloc::Layout, fmt, ops::Deref};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, ChargedShared,
    PrepaidSharedError, ReservedChargedShared, SharedFromChargeError,
};

use super::SignedBlock;

/// Immutable original block shared by execution, durable storage and its readers.
#[derive(Clone)]
pub struct SharedSignedBlock(ChargedShared<SignedBlock>);

/// Prepaid block control shell held before consuming the original execution.
pub struct ReservedSharedSignedBlock(ReservedChargedShared<SignedBlock>);

/// Local resource refusal before the original block can become a shared owner.
#[derive(Debug)]
pub enum SharedBlockAdmissionError {
    /// The original pool refused the exact control layout before allocation.
    Admission(AllocationRefusal),
    /// Prepaid control allocation was refused; no original block was consumed.
    Allocation(PrepaidSharedError),
}

impl fmt::Display for SharedBlockAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SharedBlockAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Admission(error) => error,
            Self::Allocation(error) => error,
        })
    }
}

impl SharedSignedBlock {
    /// Exact layout of the shared control, inline block and original charge.
    pub fn allocation_layout() -> Layout {
        ChargedShared::<SignedBlock>::allocation_layout()
    }

    /// Admit and allocate the shell before consuming any block or certificate.
    ///
    /// # Errors
    /// Returns the original pool's typed refusal or a physical allocator refusal.
    pub fn reserve(
        budget: &AllocationBudget,
    ) -> Result<ReservedSharedSignedBlock, SharedBlockAdmissionError> {
        let mut reservation = budget
            .try_reserve(Self::allocation_layout())
            .map_err(SharedBlockAdmissionError::Admission)?;
        ChargedShared::reserve_from(&mut reservation)
            .map(ReservedSharedSignedBlock)
            .map_err(SharedBlockAdmissionError::Allocation)
    }

    /// Construct a block shell with an already retained exact original charge.
    ///
    /// # Errors
    /// Returns the same charge on layout mismatch or physical allocation refusal.
    /// The caller retains it across retry; no replacement credit is acquired.
    pub fn reserve_from_charge(
        charge: AllocationCharge,
    ) -> Result<ReservedSharedSignedBlock, (AllocationCharge, SharedFromChargeError)> {
        ChargedShared::reserve_from_charge(charge).map(ReservedSharedSignedBlock)
    }
    /// Share the unchanged original graph using explicitly supplied allocation authority.
    ///
    /// # Errors
    /// Returns the original block unchanged on admission or physical allocation refusal.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the original graph without allocating"
    )]
    pub fn try_new(
        block: SignedBlock,
        budget: &AllocationBudget,
    ) -> Result<Self, (SignedBlock, SharedBlockAdmissionError)> {
        match Self::reserve(budget) {
            Ok(shell) => Ok(shell.initialize(block)),
            Err(error) => Err((block, error)),
        }
    }

    /// Move the original block into control funded from its existing prepaid parent.
    ///
    /// # Errors
    /// Returns the unchanged block on a short parent or physical allocation refusal.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns the original graph without allocating"
    )]
    pub fn from_reservation(
        block: SignedBlock,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, (SignedBlock, SharedBlockAdmissionError)> {
        ChargedShared::from_reservation(block, reservation)
            .map(Self)
            .map_err(|(block, error)| (block, SharedBlockAdmissionError::Allocation(error)))
    }

    /// Whether both handles retain the same original block allocation.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        ChargedShared::ptr_eq(&left.0, &right.0)
    }

    /// Whether this control remains funded by the supplied original pool.
    /// This does not grant execution authority or assert admission of nested allocations.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
}

impl ReservedSharedSignedBlock {
    /// Consume the prepaid shell and move the original block without any allocation.
    pub fn initialize(self, block: SignedBlock) -> SharedSignedBlock {
        SharedSignedBlock(self.0.initialize(block))
    }
}

impl Deref for SharedSignedBlock {
    type Target = SignedBlock;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<SignedBlock> for SharedSignedBlock {
    fn as_ref(&self) -> &SignedBlock {
        self
    }
}

impl fmt::Debug for SharedSignedBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), formatter)
    }
}

impl PartialEq for SharedSignedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for SharedSignedBlock {}

#[cfg(all(test, feature = "transparent_api"))]
mod tests;
