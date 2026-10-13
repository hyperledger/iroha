//! Original State acquisition custody before executing-block materialization.
//!
//! World is the existing inventory-owned aggregate. The four runtime Cells use
//! their original native acquisition slots, retained here during callee unwind.

use super::*;
use mv::{BlockAcquisition, BlockMode, BlockRetirement};

// One declaration generates pending/completed Cell phases and their retirement.
// No second World inventory or reconstructed payload generation is introduced.
macro_rules! runtime_cells {
    ($($field:ident: $value:ty => $charge:ty, $acquire:path),+ $(,)?) => {
        struct PendingCells<'state> {
            $($field: Option<mv::cell::BlockAcquisitionSlot<'state, $value, $charge>>,)+
        }

        struct AcquiredCells<'state> {
            $($field: Option<CellBlock<'state, $value, $charge>>,)+
        }

        enum CellPhase<'state> {
            Empty,
            Pending(PendingCells<'state>),
            Acquired(AcquiredCells<'state>),
        }

        impl<'state> CellPhase<'state> {
            fn admit(state: &'state State, budget: &iroha_allocation::AllocationBudget) -> Result<Self, StateStorageAdmissionError> {
                let layout = mv::cell::CellPublicationSuccessor::allocation_layout();
                let mut demand = 0_usize;
                $(let _ = &state.$field;
                  demand = demand.checked_add(layout.size()).ok_or_else(||
                      StateStorageAdmissionError::World(mv::storage::AdmittedStorageError::Allocation(iroha_allocation::AllocationRefusal::DemandOverflow)))?;)+
                let mut parent = budget.try_reserve_bytes(demand)
                    .map_err(mv::storage::AdmittedStorageError::Allocation)?;
                // All four original tokens exist before World can acquire its
                // first writer. A partial allocation refusal has no physical locks.
                let pending = PendingCells {
                    $($field: Some($acquire(&state.$field, budget, &mut parent)?),)+
                };
                assert_eq!(parent.remaining_bytes(), 0, "complete State Cell successor inventory");
                Ok(Self::Pending(pending))
            }

            fn initialize(&mut self, mode: BlockMode) -> Result<(), StateStorageAdmissionError> {
                let Self::Pending(pending) = self else {
                    panic!("original pending State Cells");
                };
                $(pending.$field.as_mut().expect("original State Cell slot").try_initialize(mode).map_err(StateStorageAdmissionError::World)?;)+
                // All native/user work completed while the enclosing State owner
                // retained these slots. These transfers only move checked originals.
                let Self::Pending(mut pending) = std::mem::replace(self, Self::Empty) else {
                    unreachable!("original initialized State Cell slots");
                };
                *self = Self::Acquired(AcquiredCells {
                    $($field: Some(pending.$field.take().expect("original State Cell slot").into_block()),)+
                });
                Ok(())
            }

            fn release(&mut self) {
                match self {
                    Self::Empty => {},
                    Self::Pending(pending) => {
                        $(if let Some(field) = pending.$field.as_mut() { field.release(); })+
                    }
                    Self::Acquired(acquired) => {
                        $(if let Some(field) = acquired.$field.as_mut() { field.release_writers(); })+
                    }
                }
            }
        }

        /// Exact completed originals; consuming these fields ends joint custody.
        pub(in crate::state) struct AcquiredRuntimeBlockFields<'state> {
            pub(in crate::state) world: WorldBlock<'state>,
            pub(in crate::state) transactions: TransactionsBlock<'state>,
            $(pub(in crate::state) $field: CellBlock<'state, $value, $charge>,)+
            pub(in crate::state) projection: CanonicalRuntimeProjection,
            pub(in crate::state) block_hashes: BlockHashesBlock<'state>,
            #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
            pub(in crate::state) da_rewind_releases: Option<da_hydration::DaRewindReleases<'state>>,
        }

        impl AcquiredRuntimeBlockFields<'_> {
            fn release(&mut self) {
                self.world.release_writers();
                self.transactions.release_writers();
                $(self.$field.release_writers();)+
            }
        }

        impl<'state> RuntimeBlockAcquisition<'state> {
            pub(super) fn finish(
                &mut self,
                projection: &mut Option<CanonicalRuntimeProjection>,
            ) -> AcquiredRuntimeBlock<'state> {
                // Borrow the caller's pending owner and metadata. A by-value
                // receiver adds another complete World temporary to the native
                // acquisition frame, even before the final handoff is reached.
                let original = self;
                assert!(original.complete, "original State acquisition did not complete");
                let CellPhase::Acquired(cells) = &original.cells else {
                    unreachable!("original acquired State Cells");
                };
                assert!(original.world.is_some() && original.transactions.is_some());
                assert!(original.block_hashes.is_some());
                $(assert!(cells.$field.is_some());)+
                assert!(projection.is_some());
                // All checks precede any extraction. A second finish remains
                // terminal, and the outlined closure borrows every original.
                original.complete = false;
                finish_runtime_acquisition(|| {
                    let CellPhase::Acquired(cells) = &mut original.cells else {
                        unreachable!("original acquired State Cells");
                    };
                    AcquiredRuntimeBlock {
                        target: original.target,
                        fields: Some(AcquiredRuntimeBlockFields {
                            world: original.world.take().expect("original State World"),
                            transactions: original.transactions.take().expect("original State membership"),
                            $($field: cells.$field.take().expect("original State Cell"),)+
                            projection: projection.take().expect("original prepared runtime projection"),
                            block_hashes: original.block_hashes.take().expect("original funded hash successor"),
                            #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
                            da_rewind_releases: None,
                        }),
                    }
                })
            }
        }
    };
}

runtime_cells! {
    commit_topology: Vec<PeerId> => concread::ebrcell::Untracked, crate::state::world_acquisition::original_cell,
    prev_commit_topology: Vec<PeerId> => concread::ebrcell::Untracked, crate::state::world_acquisition::original_cell,
    canonical_runtime: SnapshotNexusRuntime => concread::ebrcell::Untracked, crate::state::world_acquisition::original_cell,
    native_execution_tip: Option<NativeExecutionTip> => iroha_allocation::AllocationCharge, crate::state::native_execution_tip::original_cell,
}

/// Complete original acquisition, armed throughout State input preparation.
pub(in crate::state) struct AcquiredRuntimeBlock<'state> {
    target: &'state State,
    fields: Option<AcquiredRuntimeBlockFields<'state>>,
}

impl<'state> AcquiredRuntimeBlock<'state> {
    /// Check this exact State owner without reacquiring or projecting its values.
    pub(in crate::state) fn belongs_to(&self, state: &State) -> bool {
        std::ptr::eq(self.target, state)
    }

    /// Borrow the exact acquired originals and their checked projections.
    pub(in crate::state) fn fields(&self) -> &AcquiredRuntimeBlockFields<'state> {
        self.fields
            .as_ref()
            .expect("original acquired State fields")
    }

    /// Retain the actual rewind notices before entering its fallible engine.
    #[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
    pub(in crate::state) fn rewind_da_indexes_to_height(
        &mut self,
        target_height: u64,
    ) -> Result<(), da_hydration::DaIndexHydrationError> {
        let fields = self
            .fields
            .as_mut()
            .expect("original acquired State fields");
        let releases = fields
            .da_rewind_releases
            .get_or_insert_with(|| da_hydration::DaRewindReleases::new(self.target));
        self.target
            .rewind_da_indexes_to_height_with_releases(target_height, releases)
    }

    /// Transfer only after every fallible constructor input is prepared.
    /// The caller must immediately install these originals in the executing owner.
    pub(in crate::state) fn into_fields(mut self) -> AcquiredRuntimeBlockFields<'state> {
        self.fields.take().expect("original acquired State fields")
    }
}

impl Drop for AcquiredRuntimeBlock<'_> {
    fn drop(&mut self) {
        if let Some(fields) = self.fields.as_mut() {
            fields.release();
        }
    }
}

// Slot acquisition and completed result temporaries must not share a deep
// native constructor frame. The closure borrows the original aggregate.
#[inline(never)]
fn finish_runtime_acquisition<'state>(
    finish: impl FnOnce() -> AcquiredRuntimeBlock<'state>,
) -> AcquiredRuntimeBlock<'state> {
    finish()
}

/// Partial original State ownership; installed before any later Cell initializes.
pub(super) struct RuntimeBlockAcquisition<'state> {
    world: Option<WorldBlock<'state>>,
    transactions: Option<TransactionsBlock<'state>>,
    cells: CellPhase<'state>,
    block_hashes: Option<BlockHashesBlock<'state>>,
    membership: Option<storage_transactions::PreparedMembershipStart>,
    target: &'state State,
    started: bool,
    complete: bool,
}

impl<'state> RuntimeBlockAcquisition<'state> {
    /// Inert custody of the original detached hash and membership successors.
    /// Initialization admits every Cell token before entering any physical writer.
    pub(super) fn new(
        target: &'state State,
        block_hashes: BlockHashesBlock<'state>,
        membership: storage_transactions::PreparedMembershipStart,
    ) -> Self {
        Self {
            world: None,
            transactions: None,
            cells: CellPhase::Empty,
            block_hashes: Some(block_hashes),
            membership: Some(membership),
            target,
            started: false,
            complete: false,
        }
    }

    pub(super) fn initialize(&mut self, replacement: bool) -> Result<(), StateAdmissionError> {
        assert!(!self.started, "original State acquisition is one-shot");
        self.started = true;
        let budget = self.target.ivm_execution_budget();
        self.cells = CellPhase::admit(self.target, &budget)?;
        self.world = Some(if replacement {
            self.target
                .world
                .try_block_and_revert(&budget)
                .map_err(StateStorageAdmissionError::World)?
        } else {
            self.target
                .world
                .try_block(&budget)
                .map_err(StateStorageAdmissionError::World)?
        });
        self.transactions = Some(
            self.target
                .transactions
                .attach_prepared(&mut self.membership)?,
        );
        self.cells.initialize(if replacement {
            BlockMode::Replace
        } else {
            BlockMode::Ordinary
        })?;
        self.complete = true;
        Ok(())
    }

    pub(super) fn retain_refused_membership(&mut self) {
        self.release();
        if let Some(original) = self.membership.take() {
            self.target.transactions.retain_preparation(original);
        }
    }

    pub(super) fn world(&self) -> &WorldBlock<'state> {
        self.world.as_ref().expect("original acquired World")
    }

    pub(super) fn world_mut(&mut self) -> &mut WorldBlock<'state> {
        self.world.as_mut().expect("original acquired World")
    }

    pub(super) fn canonical_runtime(&self) -> &CellBlock<'state, SnapshotNexusRuntime> {
        let CellPhase::Acquired(cells) = &self.cells else {
            panic!("original acquired runtime Cell");
        };
        cells
            .canonical_runtime
            .as_ref()
            .expect("original canonical runtime")
    }

    fn release(&mut self) {
        self.complete = false;
        if let Some(world) = self.world.as_mut() {
            world.release_writers();
        }
        if let Some(transactions) = self.transactions.as_mut() {
            transactions.release_writers();
        }
        self.cells.release();
    }
}

impl Drop for RuntimeBlockAcquisition<'_> {
    fn drop(&mut self) {
        self.release();
    }
}
