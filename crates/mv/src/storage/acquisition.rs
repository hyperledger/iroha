//! Caller-owned original map-pair acquisition before any constructor work.

use super::*;
use concread::bptree::{BptreeMapAbandonment, BptreeMapWriterAcquisition};
use iroha_allocation::release::DeferredReleaseBatch;

/// Original mode-specific storage slot, owning partial construction through unwind.
/// Construct every slot of an aggregate before initializing any of them.
#[must_use = "initialize or abandon the original acquisition slot"]
pub struct BlockAcquisitionSlot<'a, K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
    target: &'a Storage<K, V, M>,
    phase: AcquisitionPhase<'a, K, V, M>,
    started: bool,
    complete: bool,
    custody: M::AcquisitionCustody,
    // Last: recorded native notifications survive payload/charge destruction.
    undo_release: DeferredReleaseBatch,
    current_release: DeferredReleaseBatch,
}

// A role owns only its current physical phase. Raw, converted and retired
// handles must not occupy simultaneous stack slots in every World field.
enum WriterPhase<'a, K: Key, V: Value, M: MapMode + NodeCloning<K, V>> {
    Empty,
    Raw(ReleaseGuard<'a, BptreeMapWriterAcquisition<'a, K, V, M>>),
    Writer(MapWriter<'a, K, V, M>),
    Retired(BptreeMapAbandonment<K, V, M>),
}

impl<'a, K: Key, V: Value, M: MapMode + NodeCloning<K, V>> WriterPhase<'a, K, V, M> {
    fn is_poisoned(&self) -> bool {
        match self {
            Self::Raw(raw) => raw.is_poisoned(),
            _ => panic!("original raw writer"),
        }
    }

    fn take_raw(&mut self) -> ReleaseGuard<'a, BptreeMapWriterAcquisition<'a, K, V, M>> {
        match std::mem::replace(self, Self::Empty) {
            Self::Raw(raw) => raw,
            other => {
                *self = other;
                panic!("original raw writer")
            }
        }
    }

    fn take_writer(&mut self) -> MapWriter<'a, K, V, M> {
        match std::mem::replace(self, Self::Empty) {
            Self::Writer(writer) => writer,
            other => {
                *self = other;
                panic!("original converted writer")
            }
        }
    }

    fn release(&mut self, target: &BptreeMap<K, V, M>, releases: &mut DeferredReleaseBatch) {
        match std::mem::replace(self, Self::Empty) {
            Self::Empty => {}
            Self::Raw(raw) => {
                raw.try_release_into_observed(releases, drop, || target.is_poisoned())
                    .unwrap_or_else(|_| unreachable!("original raw release source"));
            }
            Self::Writer(writer) => {
                let retirement = writer
                    .try_release_into_observed(
                        releases,
                        |writer| writer.abort_retaining(),
                        || target.is_poisoned(),
                    )
                    .unwrap_or_else(|_| unreachable!("original converted release source"));
                *self = Self::Retired(retirement);
            }
            Self::Retired(retirement) => *self = Self::Retired(retirement),
        }
    }
}

// Once both converted writers move into Block, the earlier phase storage is
// reused. The block is installed here before any reset/replacement payload code.
#[expect(
    clippy::large_enum_variant,
    reason = "caller-owned inline phase storage retains partial writers through constructor unwind without a fallible allocation while sibling writers are held"
)]
enum AcquisitionPhase<'a, K: Key, V: Value, M: StorageMode<K, V>> {
    Empty,
    Pending {
        undo: WriterPhase<'a, K, Option<V>, M>,
        current: WriterPhase<'a, K, V, M>,
    },
    Block(Block<'a, K, V, M>),
}

impl<'a, K: Key, V: Value> BlockAcquisitionSlot<'a, K, V> {
    pub(super) fn new(target: &'a Storage<K, V>) -> Self {
        Self {
            target,
            phase: AcquisitionPhase::Pending {
                undo: WriterPhase::Empty,
                current: WriterPhase::Empty,
            },
            started: false,
            complete: false,
            custody: (),
            undo_release: target.revert_released.deferred_batch(),
            current_release: target.blocks_released.deferred_batch(),
        }
    }
}

impl<'a, K: Key, V: Value> crate::BlockAcquisition for BlockAcquisitionSlot<'a, K, V> {
    type Block = Block<'a, K, V>;

    fn initialize(&mut self, mode: BlockMode) {
        assert!(!self.started, "original storage acquisition is one-shot");
        self.started = true;
        let target = self.target;
        let AcquisitionPhase::Pending { undo, current } = &mut self.phase else {
            panic!("original pending acquisition");
        };
        *undo = WriterPhase::Raw(
            target
                .revert_released
                .poisoning_guard(target.revert.acquire_writer()),
        );
        assert!(!undo.is_poisoned(), "original undo writer is poisoned");
        *current = WriterPhase::Raw(
            target
                .blocks_released
                .poisoning_guard(target.blocks.acquire_writer()),
        );
        assert!(
            !current.is_poisoned(),
            "original storage writer is poisoned"
        );
        let raw = undo.take_raw();
        *undo = WriterPhase::Writer(
            match raw
                .try_map_preserving_release_into(
                    &mut self.undo_release,
                    |undo| Ok::<_, (_, std::convert::Infallible)>(undo.write()),
                    || target.revert.is_poisoned(),
                )
                .unwrap_or_else(|_| unreachable!("original undo release source"))
            {
                Ok(writer) => writer,
                Err((_, never)) => match never {},
            },
        );
        let raw = current.take_raw();
        *current = WriterPhase::Writer(
            match raw
                .try_map_preserving_release_into(
                    &mut self.current_release,
                    |current| Ok::<_, (_, std::convert::Infallible)>(current.write()),
                    || target.blocks.is_poisoned(),
                )
                .unwrap_or_else(|_| unreachable!("original current release source"))
            {
                Ok(writer) => writer,
                Err((_, never)) => match never {},
            },
        );
        // The caller slot owns completed writers before identity lookup and all
        // reset/replacement operations that may invoke arbitrary payload code.
        let predecessor = target.publication.capture();
        let writers = StorageWriters::new(target, undo.take_writer(), current.take_writer());
        self.phase = AcquisitionPhase::Block(Block::new(
            writers,
            mode == BlockMode::Replace,
            predecessor,
            mode,
        ));
        let AcquisitionPhase::Block(block) = &mut self.phase else {
            unreachable!("original storage block");
        };
        block.failed = true;
        let OriginalWriters { revert, blocks } = block.writers.as_mut();
        if mode == BlockMode::Replace {
            for (key, value) in revert.iter() {
                match value {
                    None => blocks.remove(key),
                    Some(value) => blocks.insert(key.clone(), value.clone()),
                };
            }
        }
        revert.clear();
        block.failed = false;
        self.complete = true;
    }

    fn release(&mut self) {
        BlockAcquisitionSlot::release(self);
    }

    fn is_initialized(&self) -> bool {
        BlockAcquisitionSlot::is_initialized(self)
    }

    fn take_block(&mut self) -> Self::Block {
        BlockAcquisitionSlot::take_block(self)
    }

    fn into_block(self) -> Self::Block {
        BlockAcquisitionSlot::into_block(self)
    }
}

impl<'a, K: Key, V: Value, M: StorageMode<K, V>> BlockAcquisitionSlot<'a, K, V, M> {
    /// Unlock every original writer while retaining private payloads and wakes.
    /// Aggregates release all sibling slots before dropping any of them.
    pub fn release(&mut self) {
        self.complete = false;
        self.started = true;
        match &mut self.phase {
            AcquisitionPhase::Empty => {}
            AcquisitionPhase::Block(block) => crate::BlockRetirement::release_writers(block),
            AcquisitionPhase::Pending { undo, current } => {
                current.release(&self.target.blocks, &mut self.current_release);
                undo.release(&self.target.revert, &mut self.undo_release);
            }
        }
    }

    /// Transfer only a fully initialized original block without allocation.
    /// A prepaid block retains this slot's original scope and cannot outlive it.
    pub fn into_block(mut self) -> Block<'a, K, V, M> {
        self.take_block()
    }

    /// Whether this original slot can transfer without allocation or payload work.
    pub fn is_initialized(&self) -> bool {
        self.complete && matches!(self.phase, AcquisitionPhase::Block(_))
    }

    /// Move the original completed Block while retaining this slot on refusal.
    /// This performs no payload callback, allocation or physical acquisition.
    pub fn take_block(&mut self) -> Block<'a, K, V, M> {
        assert!(
            self.complete,
            "original storage initialization did not complete"
        );
        match std::mem::replace(&mut self.phase, AcquisitionPhase::Empty) {
            AcquisitionPhase::Block(block) => block,
            other => {
                self.phase = other;
                panic!("original completed storage block")
            }
        }
    }
}

impl<K: Key, V: Value, M: StorageMode<K, V>> Drop for BlockAcquisitionSlot<'_, K, V, M> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<K, V, P> Storage<K, V, concread::bptree::Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy
        + concread::bptree::ClonePlanning<K, V>
        + concread::bptree::ClonePlanning<K, Option<V>>,
{
    /// Create an inert prepaid slot under this storage's original refund scope.
    ///
    /// No lock, cursor, identity or payload is constructed here. A foreign scope
    /// refuses first. Construct all sibling slots before initializing any; keep
    /// them alive and release every sibling before destroying private owners.
    /// Neither the slot nor its returned block can escape the scope:
    /// ```compile_fail
    /// use concread::bptree::{ClonePlanning, Prepaid};
    /// use iroha_allocation::{AllocationBudget};
    /// use mv::{storage::{AdmittedStoragePolicy, Block, Storage},BlockMode};
    /// fn escape<'a, P>(budget: &'a AllocationBudget, storage: &'a Storage<u64,u64,Prepaid<P>>)
    ///     -> Block<'a,u64,u64,Prepaid<P>>
    /// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
    ///     budget.with_deferred_refund_notifications(|scope| {
    ///         let mut slot = storage.try_block_acquisition_admitted(scope).unwrap();
    ///         slot.try_initialize(BlockMode::Ordinary).unwrap();
    ///         slot.into_block()
    ///     })
    /// }
    /// ```
    /// The acquisition slot itself is confined to the same borrow:
    /// ```compile_fail
    /// use concread::bptree::{ClonePlanning, Prepaid};
    /// use iroha_allocation::{AllocationBudget};
    /// use mv::{storage::{AdmittedStoragePolicy, BlockAcquisitionSlot, Storage}};
    /// fn escape<'a, P>(budget: &'a AllocationBudget, storage: &'a Storage<u64,u64,Prepaid<P>>)
    ///     -> BlockAcquisitionSlot<'a,u64,u64,Prepaid<P>>
    /// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
    ///     budget.with_deferred_refund_notifications(|scope| {
    ///         storage.try_block_acquisition_admitted(scope).unwrap()
    ///     })
    /// }
    /// ```
    /// Transferring publication ownership preserves that physical lifetime:
    /// ```compile_fail
    /// use concread::bptree::{ClonePlanning, Prepaid};
    /// use iroha_allocation::{AllocationBudget};
    /// use mv::{storage::{AdmittedStoragePolicy, BlockPublicationSlot, Storage},BlockMode};
    /// fn escape<'a, P>(budget: &'a AllocationBudget, storage: &'a Storage<u64,u64,Prepaid<P>>)
    ///     -> BlockPublicationSlot<'a,u64,u64,Prepaid<P>>
    /// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
    ///     budget.with_deferred_refund_notifications(|scope| {
    ///         let mut slot = storage.try_block_acquisition_admitted(scope).unwrap();
    ///         slot.try_initialize(BlockMode::Ordinary).unwrap();
    ///         slot.into_block().publication_slot()
    ///     })
    /// }
    /// ```
    /// A scoped thread cannot take the original executing physical owner:
    /// ```compile_fail
    /// use concread::bptree::{ClonePlanning, Prepaid};
    /// use iroha_allocation::{AllocationBudget};
    /// use mv::{storage::{AdmittedStoragePolicy, Storage},BlockMode};
    /// fn send<P>(budget: &AllocationBudget, storage: &Storage<u64,u64,Prepaid<P>>)
    /// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
    ///     budget.with_deferred_refund_notifications(|scope| {
    ///         let mut slot = storage.try_block_acquisition_admitted(scope).unwrap();
    ///         slot.try_initialize(BlockMode::Ordinary).unwrap();
    ///         let block = slot.into_block();
    ///         std::thread::scope(|threads| { threads.spawn(move || drop(block)); });
    ///     })
    /// }
    /// ```
    /// The mode's custody itself cannot be shared or transferred to a thread;
    /// this is independent of a platform's native mutex guard traits:
    /// ```compile_fail
    /// use concread::bptree::{ClonePlanning, Prepaid};
    /// use mv::storage::{AdmittedStoragePolicy, StorageMode};
    /// fn require_thread_custody<P>()
    /// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
    ///     fn send_sync<T: Send + Sync>() {}
    ///     send_sync::<<Prepaid<P> as StorageMode<u64,u64>>::AcquisitionCustody>();
    /// }
    /// ```
    pub fn try_block_acquisition_admitted<'a>(
        &'a self,
        scope: &'a iroha_allocation::AllocationScope<'a>,
    ) -> Result<BlockAcquisitionSlot<'a, K, V, concread::bptree::Prepaid<P>>, AdmittedStorageError>
    {
        let budget = self
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        if !scope.belongs_to(budget) {
            return Err(AdmittedStorageError::ScopeIdentity);
        }
        Ok(BlockAcquisitionSlot {
            target: self,
            phase: AcquisitionPhase::Pending {
                undo: WriterPhase::Empty,
                current: WriterPhase::Empty,
            },
            started: false,
            complete: false,
            custody: AdmittedAcquisitionCustody {
                _owned: None,
                _thread: std::marker::PhantomData,
            },
            undo_release: self.revert_released.deferred_batch(),
            current_release: self.blocks_released.deferred_batch(),
        })
    }

    /// Create an inert slot retaining the same original prepaid refund scope.
    ///
    /// Unlike the borrowed callback API, this slot may return to its caller:
    /// both it and the resulting block keep a clone of the original thread-bound
    /// scope until after physical writer release. A foreign pool refuses before
    /// taking a lock or allocating a cursor. Aggregate callers retain a scope
    /// clone until every sibling writer has released, including untracked fields.
    pub fn try_block_acquisition_owned(
        &self,
        scope: &iroha_allocation::OwnedAllocationScope,
    ) -> Result<BlockAcquisitionSlot<'_, K, V, concread::bptree::Prepaid<P>>, AdmittedStorageError>
    {
        let budget = self.allocation.as_ref().expect("original admitted pool");
        if !scope.belongs_to(budget) {
            return Err(AdmittedStorageError::ScopeIdentity);
        }
        Ok(BlockAcquisitionSlot {
            target: self,
            phase: AcquisitionPhase::Pending {
                undo: WriterPhase::Empty,
                current: WriterPhase::Empty,
            },
            started: false,
            complete: false,
            custody: AdmittedAcquisitionCustody {
                _owned: Some(scope.clone()),
                _thread: std::marker::PhantomData,
            },
            undo_release: self.revert_released.deferred_batch(),
            current_release: self.blocks_released.deferred_batch(),
        })
    }
}

impl<'a, K, V, P> BlockAcquisitionSlot<'a, K, V, concread::bptree::Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy
        + concread::bptree::ClonePlanning<K, V>
        + concread::bptree::ClonePlanning<K, Option<V>>,
{
    /// Admit and initialize both original writers, retaining every partial phase.
    ///
    /// A normal refusal or caught panic leaves this one-shot slot for terminal
    /// release only. It never returns a partially restored block. Current/undo
    /// cursor and identity demand is reserved together before the first lock;
    /// both raw locks precede either policy callback. Reset and replacement run
    /// only after the completed pair belongs to this caller-owned slot.
    pub fn try_initialize(&mut self, mode: BlockMode) -> Result<(), AdmittedStorageError> {
        use super::admitted::{policy, reserve_owners, writer_error};
        use concread::bptree::{MapAdmissionError, Prepaid};

        assert!(!self.started, "original storage acquisition is one-shot");
        self.started = true;
        let target = self.target;
        let budget = target
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        let custody = self.custody.clone();
        let current_demand = BptreeMap::<K, V, Prepaid<P>>::writer_start_allocation_demand()
            .map_err(AdmittedStorageError::Planning)?;
        let undo_demand = BptreeMap::<K, Option<V>, Prepaid<P>>::writer_start_allocation_demand()
            .map_err(AdmittedStorageError::Planning)?;
        let identity_demand =
            NextPublication::allocation_demand().map_err(AdmittedStorageError::Planning)?;
        let (current_reservation, undo_reservation, identity_reservation) =
            reserve_owners(budget, current_demand, undo_demand, identity_demand)?;
        let AcquisitionPhase::Pending { undo, current } = &mut self.phase else {
            panic!("original pending acquisition");
        };
        let undo_wait = target.revert_released.observe();
        let raw = target.revert.try_acquire_writer().ok_or_else(|| {
            writer_error(
                MapAdmissionError::Busy,
                StorageRole::Undo,
                undo_wait.clone(),
            )
        })?;
        *undo = WriterPhase::Raw(target.revert_released.poisoning_guard(raw));
        if undo.is_poisoned() {
            return Err(AdmittedStorageError::Poisoned {
                role: StorageRole::Undo,
            });
        }
        let current_wait = target.blocks_released.observe();
        let raw = target.blocks.try_acquire_writer().ok_or_else(|| {
            writer_error(
                MapAdmissionError::Busy,
                StorageRole::Current,
                current_wait.clone(),
            )
        })?;
        *current = WriterPhase::Raw(target.blocks_released.poisoning_guard(raw));
        if current.is_poisoned() {
            return Err(AdmittedStorageError::Poisoned {
                role: StorageRole::Current,
            });
        }
        let converted = undo
            .take_raw()
            .try_map_preserving_release_into(
                &mut self.undo_release,
                |raw| {
                    raw.try_write_admitted(|demand| policy::<P>(budget, undo_reservation, demand))
                },
                || target.revert.is_poisoned(),
            )
            .unwrap_or_else(|_| unreachable!("original undo release source"));
        match converted {
            Ok(writer) => *undo = WriterPhase::Writer(writer),
            Err((raw, error)) => {
                *undo = WriterPhase::Raw(raw);
                return Err(writer_error(error, StorageRole::Undo, undo_wait));
            }
        }
        let converted = current
            .take_raw()
            .try_map_preserving_release_into(
                &mut self.current_release,
                |raw| {
                    raw.try_write_admitted(|demand| {
                        policy::<P>(budget, current_reservation, demand)
                    })
                },
                || target.blocks.is_poisoned(),
            )
            .unwrap_or_else(|_| unreachable!("original current release source"));
        match converted {
            Ok(writer) => *current = WriterPhase::Writer(writer),
            Err((raw, error)) => {
                *current = WriterPhase::Raw(raw);
                return Err(writer_error(error, StorageRole::Current, current_wait));
            }
        }
        let predecessor = target.publication.capture();
        let writers = StorageWriters::new(target, undo.take_writer(), current.take_writer());
        self.phase = AcquisitionPhase::Block(Block {
            writers,
            dirty: mode == BlockMode::Replace,
            direct_write: false,
            applied_transactions: 0,
            failed: true,
            predecessor,
            next: None,
            mode,
            _acquisition_custody: custody,
        });
        let AcquisitionPhase::Block(block) = &mut self.phase else {
            unreachable!("original admitted block");
        };
        // Even identity allocation runs only after the slot owns both writers.
        let mut identity_reservation = identity_reservation;
        block.next = Some(
            NextPublication::try_from_charge(
                identity_reservation
                    .try_split(NextPublication::allocation_layout())
                    .expect("original successor identity admission"),
            )
            .map_err(|(charge, error)| {
                drop(charge);
                AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?,
        );
        debug_assert_eq!(identity_reservation.remaining_bytes(), 0);
        block.initialize_admitted_contents()?;
        self.complete = true;
        Ok(())
    }
}
