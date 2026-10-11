//! Original finite credits for the fixed-width canonical hash journal.

use super::*;
#[cfg(test)]
#[path = "block_hashes_admission_tests.rs"]
mod tests;
use concread::bptree::{
    AllocationDemand, ClonePlanning, MapAdmissionError, NodeCloning, NodeFunding, PlanningError,
};

/// Local admission for original State storage and committed-history owners.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateAdmissionError {
    /// Original refusal from a World field, prepaid shell or successor inventory.
    #[error(transparent)]
    Storage(#[from] StateStorageAdmissionError),
    /// Original block-hash history admission.
    #[error(transparent)]
    History(#[from] BlockHashAdmissionError),
    /// Original replay-membership history admission.
    #[error(transparent)]
    Membership(#[from] storage_transactions::MembershipAdmissionError),
}
impl StateAdmissionError {
    /// Original resource release, when releasing retained custody can help.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::Storage(e) => e.release_wait(),
            Self::History(e) => e.release_wait(),
            Self::Membership(e) => e.release_wait(),
        }
    }
}
impl From<StateAdmissionError> for MergeLedgerCommitError {
    fn from(error: StateAdmissionError) -> Self {
        match error {
            StateAdmissionError::Storage(e) => Self::StateStorageAdmission(e),
            StateAdmissionError::History(e) => Self::BlockHashAdmission(e),
            StateAdmissionError::Membership(e) => Self::MembershipAdmission(e),
        }
    }
}

/// Separate local acquisition refusal from the caller's deterministic start stage.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateBlockStartError<E: std::fmt::Debug> {
    /// The original committed scheduling policy is malformed.
    #[error("invalid committed block-start policy: {0}")]
    Policy(String),
    /// No World owner or start effect was acquired before this local refusal.
    #[error(transparent)]
    Storage(#[from] StateStorageAdmissionError),
    /// No World owner or start effect was acquired before this local refusal.
    #[error(transparent)]
    History(#[from] BlockHashAdmissionError),
    /// No World owner or start effect was acquired before this local refusal.
    #[error(transparent)]
    Membership(#[from] storage_transactions::MembershipAdmissionError),
    /// Original source-route backing or a pre-effect routing read could not complete locally.
    #[error(transparent)]
    ExecutionDeferred(crate::execution_attempt::ExecutionDeferred),
    /// The caller's original pristine/after-start failure.
    #[error("block start stage failed: {0:?}")]
    Stage(E),
}
impl From<StateBlockStartError<MergeLedgerCommitError>> for MergeLedgerCommitError {
    fn from(error: StateBlockStartError<MergeLedgerCommitError>) -> Self {
        match error {
            StateBlockStartError::Storage(error) => Self::StateStorageAdmission(error),
            StateBlockStartError::History(error) => Self::BlockHashAdmission(error),
            StateBlockStartError::Membership(error) => Self::MembershipAdmission(error),
            StateBlockStartError::ExecutionDeferred(error) => Self::ExecutionDeferred(error),
            StateBlockStartError::Stage(error) => error,
            StateBlockStartError::Policy(error) => Self::ExecutionStatePublication(error),
        }
    }
}

/// Fixed local categories retained by the JSON execution-root decoder.
/// JSON exposes these categories without the binary decoder's numeric counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RootScopeDecodeRefusal {
    /// The inherited decode scope refused allocation or structural work.
    #[error("execution-root metadata decode budget refused")]
    Budget,
    /// The physical allocator refused the decoder's requested storage.
    #[error("execution-root metadata allocation refused")]
    Allocator,
}

/// Local State storage or protocol decoder refusal; never a verdict on consensus data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateStorageAdmissionError {
    /// Original finite-credit refusal from an admitted World storage owner.
    #[error(transparent)]
    World(#[from] mv::storage::AdmittedStorageError),
    /// The original decoder scope or allocator refused while executing an AMX instruction.
    #[error("local AMX decoder resource refusal: {0}")]
    AmxDecode(norito::core::DecodeResourceError),
    /// The original native participant graph or allocator refused before monetary execution.
    #[error("local native AMX graph refusal: {0}")]
    NativeAmx(crate::sumeragi::amx::NativeAmxAdmissionError),
    /// The original execution-root metadata decoder refused before instruction authority existed.
    #[error(transparent)]
    RootScopeDecode(RootScopeDecodeRefusal),
}

impl StateStorageAdmissionError {
    /// The original release observation, only when releasing another owner can help.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::World(error) => error.release_wait(),
            Self::NativeAmx(crate::sumeragi::amx::NativeAmxAdmissionError::Admission(
                iroha_allocation::AllocationRefusal::Capacity { release, .. },
            )) => Some(release),
            Self::NativeAmx(_) => None,
            Self::AmxDecode(_) | Self::RootScopeDecode(_) => None,
        }
    }
}

/// Local canonical hash-history acquisition failure; never a verdict on consensus data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockHashAdmissionError {
    /// Another physical owner must release the original history lock.
    #[error("canonical hash history is busy")]
    Busy(iroha_allocation::release::ReleaseWait),
    /// The configured finite pool refused the complete operation.
    #[error("canonical hash history capacity: {0}")]
    Capacity(iroha_allocation::AllocationRefusal),
    /// A checked layout or generation cannot be represented.
    #[error("canonical hash history planning failed: {0:?}")]
    Planning(PlanningError),
    /// An earlier failed edit requires Strict restart/recovery.
    #[error("canonical hash history is poisoned")]
    Poisoned,
    /// The observed original generation was replaced before acquisition.
    #[error("canonical hash history predecessor changed")]
    Changed(iroha_allocation::release::ReleaseWait),
    /// Emergency Fast startup does not permit a successor.
    #[error("emergency Fast history is read-only; restart in Strict mode")]
    ReadOnly,
}

impl BlockHashAdmissionError {
    /// The original release observation, only when releasing another owner can help.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::Busy(wait) | Self::Changed(wait) => Some(wait),
            Self::Capacity(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
                Some(release)
            }
            _ => None,
        }
    }
}
impl<E: std::fmt::Debug> From<StateAdmissionError> for StateBlockStartError<E> {
    fn from(error: StateAdmissionError) -> Self {
        match error {
            StateAdmissionError::Storage(e) => Self::Storage(e),
            StateAdmissionError::History(e) => Self::History(e),
            StateAdmissionError::Membership(e) => Self::Membership(e),
        }
    }
}
impl<E: std::fmt::Debug> StateBlockStartError<E> {
    /// Preserve the original storage release without retrying a deterministic stage failure.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::Storage(error) => error.release_wait(),
            Self::History(error) => error.release_wait(),
            Self::Membership(error) => error.release_wait(),
            Self::ExecutionDeferred(error) => match error.allocation_refusal() {
                Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
                    Some(release)
                }
                _ => None,
            },
            Self::Stage(_) | Self::Policy(_) => None,
        }
    }
}

/// Concrete payloads contain no nested allocation or destructor-owned storage.
pub(super) struct BlockHashPolicy(iroha_allocation::AllocationReservation);
impl NodeFunding for BlockHashPolicy {
    type Charge = iroha_allocation::AllocationCharge;
    fn take_node_charge(&mut self, layout: std::alloc::Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("complete concrete hash edit plan")
    }
}
impl NodeCloning<usize, HashOf<BlockHeader>> for BlockHashPolicy {
    fn clone_key(&mut self, key: &usize) -> usize {
        *key
    }
    fn clone_value(&mut self, value: &HashOf<BlockHeader>) -> HashOf<BlockHeader> {
        *value
    }
}
impl ClonePlanning<usize, HashOf<BlockHeader>> for BlockHashPolicy {
    fn plan_key(_: &usize, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
    fn plan_value(_: &HashOf<BlockHeader>, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
}
impl BlockHashes {
    fn admit_successor(
        &self,
        existing: AllocationDemand,
        additional: AllocationDemand,
    ) -> Result<BlockHashPolicy, iroha_allocation::AllocationRefusal> {
        let required = existing
            .bytes()
            .checked_add(additional.bytes())
            // The shared map owner cannot be refunded while this history lives.
            // Include its original charge in the permanent capacity bound.
            .and_then(|bytes| bytes.checked_add(ChargedBlockHashMap::layout().size()))
            .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)?;
        if required > self.budget.limit_bytes() {
            return Err(iroha_allocation::AllocationRefusal::ExceedsLimit {
                requested_bytes: required,
                limit_bytes: self.budget.limit_bytes(),
            });
        }
        self.admit(additional)
    }
    pub(super) fn admit(
        &self,
        demand: AllocationDemand,
    ) -> Result<BlockHashPolicy, iroha_allocation::AllocationRefusal> {
        self.budget
            .try_reserve_bytes(demand.bytes())
            .map(BlockHashPolicy)
    }
    fn admission_error(
        &self,
        error: MapAdmissionError<iroha_allocation::AllocationRefusal>,
        wait: iroha_allocation::release::ReleaseWait,
    ) -> BlockHashAdmissionError {
        match error {
            MapAdmissionError::Busy => BlockHashAdmissionError::Busy(wait),
            MapAdmissionError::Poisoned => BlockHashAdmissionError::Poisoned,
            MapAdmissionError::Changed => BlockHashAdmissionError::Changed(wait),
            MapAdmissionError::Planning(error) => BlockHashAdmissionError::Planning(error),
            MapAdmissionError::Refused(error) => BlockHashAdmissionError::Capacity(error),
        }
    }
    /// Restore exact ordered history with every tree allocation charged to this pool.
    /// The input sequence is owned by the caller's authenticated snapshot/replay scope.
    pub(crate) fn try_new(
        initial: impl IntoIterator<Item = HashOf<BlockHeader>>,
        budget: iroha_allocation::AllocationBudget,
    ) -> Result<Self, BlockHashAdmissionError> {
        budget.with_deferred_refund_notifications(|_| {
            let control_layout = ChargedBlockHashMap::layout();
            let mut control_reservation = budget
                .try_reserve(control_layout)
                .map_err(BlockHashAdmissionError::Capacity)?;
            let control_charge = control_reservation
                .try_split(control_layout)
                .expect("exact prepaid history owner layout");
            let map = BlockHashMap::try_new_with_node_custody(|demand| {
                budget
                    .try_reserve_bytes(demand.bytes())
                    .map(BlockHashPolicy)
            })
            .map_err(BlockHashAdmissionError::Capacity)?;
            let owner = Self {
                inner: BlockHashStorage::Owned(ChargedBlockHashMap::new(map, control_charge)),
                budget: budget.clone(),
                released: iroha_allocation::release::ReleaseNotification::default(),
                committed_height: AtomicUsize::new(0),
            };
            for (index, hash) in initial.into_iter().enumerate() {
                let map = owner.map().expect("new mutable history");
                let wait = owner.released.observe();
                let (work, old) = map
                    .try_insert_admitted_with_footprint(index, hash, |existing, additional| {
                        owner.admit_successor(existing, additional)
                    })
                    .map_err(|(_, error)| owner.admission_error(error, wait))?;
                debug_assert!(old.is_none());
                let writer = map
                    .try_write_owned(work)
                    .unwrap_or_else(|_| unreachable!("exclusive cold history"));
                drop(writer.prepare_commit().publish().release());
                owner.committed_height.store(index + 1, Ordering::Release);
            }
            Ok(owner)
        })
    }

    /// Prepay and create the entire successor before any World execution begins.
    /// The private tip remains hidden until `push` installs the exact final hash.
    pub(crate) fn try_next_block(
        &self,
        replacement: bool,
    ) -> Result<BlockHashesBlock<'_>, BlockHashAdmissionError> {
        self.budget.with_deferred_refund_notifications(|_| {
            let map = self.map().ok_or(BlockHashAdmissionError::ReadOnly)?;
            let wait = map.observe_reader_release();
            let view = self.try_view().map_err(|error| match error {
                concread::bptree::OwnedWriteError::Busy => {
                    BlockHashAdmissionError::Busy(wait.clone())
                }
                concread::bptree::OwnedWriteError::Poisoned => BlockHashAdmissionError::Poisoned,
                concread::bptree::OwnedWriteError::Changed => {
                    BlockHashAdmissionError::Changed(wait.clone())
                }
            })?;
            let prefix = if replacement {
                view.len().saturating_sub(1)
            } else {
                view.len()
            };
            let predecessor = match &view.inner {
                BlockHashesViewInner::Owned(view) => view.predecessor().retain(),
                BlockHashesViewInner::Mapped(_) => unreachable!("mutable map checked above"),
            };
            drop(view);
            let wait = self.released.observe();
            let acquired = map
                .try_acquire_writer()
                .ok_or_else(|| BlockHashAdmissionError::Busy(wait.clone()))?;
            let writer = match self
                .released
                .poisoning_guard(acquired)
                .try_map_preserving_release(|acquired| {
                    acquired
                        .try_insert_admitted_with_footprint(
                            prefix,
                            HashOf::from_untyped_unchecked(Hash::prehashed([0; 32])),
                            |existing, additional| self.admit_successor(existing, additional),
                        )
                        .map_err(|(acquired, input, error)| (acquired, (input, error)))
                }) {
                Ok(writer) => writer,
                Err((acquired, (_, error))) => {
                    drop(acquired);
                    return Err(self.admission_error(error, wait));
                }
            };
            let (work, _) = writer.release_with(|(writer, previous)| (writer.detach(), previous));
            if !predecessor.matches(&work.predecessor()) {
                return Err(BlockHashAdmissionError::Changed(wait));
            }
            Ok(BlockHashesBlock {
                inner: self,
                work,
                visible_len: prefix,
                reserved_tip: Some(prefix),
                fixture_edits: false,
                mode: if replacement {
                    mv::BlockMode::Replace
                } else {
                    mv::BlockMode::Ordinary
                },
            })
        })
    }
}
