//! Joined admitted insertion and removal through the original MV child checkpoints.
//!
//! Ordered local touches and both map edits share one original finite admission.
//! These child owners never detach or reacquire the physical writers. Publication
//! still belongs to the enclosing ordinary block's synchronous refund scope.

use super::{
    admitted::admit,
    block::TransactionTouches,
    touches::{PreparedTouch, SortedTouches},
    *,
};
use concread::bptree::{
    AllocationDemand, ClonePlanning, PairInsertError, PairRemoveError, Prepaid,
};
use iroha_allocation::AllocationBudget;

// Keep this as the LAST Transaction field, after both checkpoints and touches.
// Transaction::drop records whether unwinding began before field cleanup. The
// original checkpoints can still roll back a failed ordinary child. A new cleanup
// panic poisons the parent; an already armed edit/apply failure stays sticky.
pub(super) struct ParentFailure<'block> {
    failed: &'block mut bool,
    unwind_before_cleanup: bool,
}
impl<'block> ParentFailure<'block> {
    pub(super) fn new(failed: &'block mut bool) -> Self {
        Self {
            failed,
            unwind_before_cleanup: false,
        }
    }
    pub(super) fn begin_cleanup(&mut self) {
        self.unwind_before_cleanup = std::thread::panicking();
    }
    pub(super) fn arm(&mut self) {
        *self.failed = true;
    }
    pub(super) fn resolve(&mut self) {
        *self.failed = false;
    }
    pub(super) fn is_failed(&self) -> bool {
        *self.failed
    }
}
impl Drop for ParentFailure<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() && !self.unwind_before_cleanup {
            *self.failed = true;
        }
    }
}

impl<K, V, P> Block<'_, K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Borrow the original pool retained by this admitted block.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        self.writers
            .target
            .allocation
            .as_ref()
            .expect("original admitted block pool")
    }

    /// Begin a private admitted transaction under these same physical writers.
    ///
    /// Checked generation refusal is returned before any user admission or copy.
    /// If the second checkpoint refuses, the first original checkpoint is dropped
    /// before returning. Empty ordered touch storage allocates nothing. Applying
    /// the transaction keeps its edits in this block; dropping it restores both
    /// original parent roots and preserves the parent's previous dirty state.
    pub fn try_transaction_admitted(
        &mut self,
    ) -> Result<Transaction<'_, K, V, Prepaid<P>>, AdmittedStorageError> {
        self.assert_admitted_operable();
        let allocation = self
            .writers
            .target
            .allocation
            .as_ref()
            .expect("original admitted block pool");
        self.failed = true;
        let OriginalWriters { revert, blocks } = self.writers.as_mut();
        let blocks = match blocks.checkpoint() {
            Ok(blocks) => blocks,
            Err(error) => {
                self.failed = false;
                return Err(AdmittedStorageError::Planning(error));
            }
        };
        let revert = match revert.checkpoint() {
            Ok(revert) => revert,
            Err(error) => {
                drop(blocks);
                self.failed = false;
                return Err(AdmittedStorageError::Planning(error));
            }
        };
        self.failed = false;
        let dirty = self.dirty;
        Ok(Transaction {
            blocks: Some(blocks),
            revert: Some(revert),
            touched: TransactionTouches::Admitted(SortedTouches::new()),
            parent_dirty: &mut self.dirty,
            parent_applied_transactions: &mut self.applied_transactions,
            dirty,
            failed: false,
            allocation: Some(allocation),
            parent_failure: Some(ParentFailure::new(&mut self.failed)),
        })
    }
}

// Move the exclusive touch-set borrow into the pair's FnOnce callback. The
// prepared owner erases its temporary input-key borrow while retaining exclusive
// custody of that unchanged set until the original pair has succeeded.
fn prepare_touch<'set, K, V, P>(
    touches: &'set mut SortedTouches<K>,
    prepared: &mut Option<PreparedTouch<'set, K>>,
    budget: &AllocationBudget,
    pair: AllocationDemand,
    key: &K,
) -> Result<P, AdmittedStorageError>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    let plan = touches
        .plan::<V, P>(key, pair)
        .map_err(AdmittedStorageError::Planning)?;
    let mut provider = admit::<P>(budget, plan.demand())?;
    let ready = plan.prepare::<V, P>(&mut provider);
    // A conservative key-copy bound may leave slack. It must never consume the
    // map pair's reserved portion or replace the original pool during preparation.
    if !provider.admission().belongs_to(budget) {
        return Err(AdmittedStorageError::PolicyIdentity);
    }
    if provider.admission().remaining_bytes() < pair.bytes() {
        return Err(AdmittedStorageError::PolicyDemand {
            expected_bytes: pair.bytes(),
            remaining_bytes: provider.admission().remaining_bytes(),
        });
    }
    *prepared = Some(ready);
    Ok(provider)
}

impl<K, V, P> Transaction<'_, K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    fn assert_admitted_operable(&self) {
        assert!(
            !self.failed,
            "admitted transaction edit unwound; abandon the parent block"
        );
        assert!(
            !self
                .parent_failure
                .as_ref()
                .expect("original admitted parent")
                .is_failed(),
            "admitted parent block is unusable"
        );
        self.blocks
            .as_ref()
            .expect("original current checkpoint")
            .len();
        self.revert
            .as_ref()
            .expect("original undo checkpoint")
            .len();
    }

    pub(super) fn arm(&mut self) {
        self.failed = true;
        self.parent_failure
            .as_mut()
            .expect("original admitted parent")
            .arm();
    }

    pub(super) fn resolve(&mut self) {
        self.failed = false;
        self.parent_failure
            .as_mut()
            .expect("original admitted parent")
            .resolve();
    }

    /// Insert through both original checkpoints and retain one ordered touch.
    ///
    /// Before any allocation or copy, one admission includes the exact pair plan
    /// and the new touch key/buffer plan. Already touched keys add no copy or
    /// storage demand. The exact incoming key is borrowed from the canonical pair
    /// callback; no unfunded pre-clone is made. Ordinary refusal returns original
    /// inputs and leaves both parent checkpoints and touch metadata reusable.
    /// A caught preparation, map edit or cleanup panic makes this transaction and
    /// original parent block unusable; neither may publish a partial successor.
    pub fn try_insert_admitted(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<V>, ((K, V), AdmittedStorageError)> {
        self.assert_admitted_operable();
        self.arm();
        let budget = self.allocation.expect("original admitted transaction pool");
        let mut prepared = None;
        let current = self.blocks.as_mut().expect("original current checkpoint");
        let undo = self.revert.as_mut().expect("original undo checkpoint");
        let touches = self.touched.admitted_mut();
        let prepared_slot = &mut prepared;
        let result = current
            .try_insert_with_undo_admitted(undo, key, value, move |pair, key| {
                prepare_touch::<K, V, P>(touches, prepared_slot, budget, pair, key)
            })
            .map_err(|(input, error)| {
                let error = match error {
                    PairInsertError::Planning(error) => AdmittedStorageError::Planning(error),
                    PairInsertError::Refused(error) => error,
                    PairInsertError::Current(_) | PairInsertError::Undo(_) => {
                        unreachable!("original borrowed checkpoints never reacquire writers")
                    }
                };
                (input, error)
            });
        if result.is_ok() {
            let retired = prepared
                .take()
                .expect("same successful pair admission prepared its touch")
                .install();
            // The original empty old buffer must be physically freed before its
            // credits return and before either aggregate failure flag is cleared.
            drop(retired);
            self.dirty = true;
        }
        drop(prepared);
        self.resolve();
        result
    }

    /// Remove through both original checkpoints and retain one ordered touch.
    ///
    /// One original reservation funds the pair and first touch before any copy.
    /// An absent removal retains an explicit absent-to-absent touch and first
    /// None preimage without setting dirty. Repeated touches preserve their key
    /// owner and first preimages. Refusal returns the exact query and leaves all
    /// three owners reusable. Copy, query-drop and touch-cleanup panics leave the
    /// transaction and its original parent armed against partial publication.
    pub fn try_remove_admitted(&mut self, key: K) -> Result<Option<V>, (K, AdmittedStorageError)> {
        self.assert_admitted_operable();
        self.arm();
        let budget = self.allocation.expect("original admitted transaction pool");
        let mut prepared = None;
        let current = self.blocks.as_mut().expect("original current checkpoint");
        let undo = self.revert.as_mut().expect("original undo checkpoint");
        let touches = self.touched.admitted_mut();
        let prepared_slot = &mut prepared;
        let result = current
            .try_remove_with_undo_admitted(undo, key, move |pair, key| {
                prepare_touch::<K, V, P>(touches, prepared_slot, budget, pair, key)
            })
            .map_err(|(key, error)| {
                let error = match error {
                    PairRemoveError::Planning(error) => AdmittedStorageError::Planning(error),
                    PairRemoveError::Refused(error) => error,
                };
                (key, error)
            });
        if let Ok(previous) = &result {
            let retired = prepared
                .take()
                .expect("same successful pair admission prepared its touch")
                .install();
            drop(retired);
            self.dirty |= previous.is_some();
        }
        drop(prepared);
        self.resolve();
        result
    }

    /// Borrow a value in this transaction's private current generation.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.assert_admitted_operable();
        self.blocks
            .as_ref()
            .expect("original current checkpoint")
            .get(key)
    }

    /// Borrow the first preimage of the original enclosing block.
    pub fn get_before_block(&self, key: &K) -> Option<&V> {
        self.assert_admitted_operable();
        match self
            .revert
            .as_ref()
            .expect("original undo checkpoint")
            .get(key)
        {
            Some(previous) => previous.as_ref(),
            None => self
                .blocks
                .as_ref()
                .expect("original current checkpoint")
                .get(key),
        }
    }

    /// Borrow the preimage at this transaction's original parent cut.
    pub fn get_before_transaction(&self, key: &K) -> Option<&V> {
        self.assert_admitted_operable();
        self.blocks
            .as_ref()
            .expect("original current checkpoint")
            .get_before(key)
    }

    /// Visit unique ordered touches with original/current values, without allocation.
    /// No-op insertions and absent removals remain explicit; aborted siblings add no rows.
    pub fn touched_entries(
        &self,
    ) -> impl DoubleEndedIterator<Item = TouchedEntry<'_, K, V>> + ExactSizeIterator {
        self.assert_admitted_operable();
        let current = self.blocks.as_ref().expect("original current checkpoint");
        self.touched.admitted().iter().map(move |key| TouchedEntry {
            key,
            before: current.get_before(key),
            after: current.get(key),
        })
    }

    /// Number of entries in this private current generation.
    pub fn len(&self) -> usize {
        self.assert_admitted_operable();
        self.blocks
            .as_ref()
            .expect("original current checkpoint")
            .len()
    }
    /// Whether this private current generation contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Whether this transaction or an earlier applied sibling changed the block.
    pub fn is_dirty(&self) -> bool {
        self.assert_admitted_operable();
        self.dirty
    }

    /// Keep both original private successors in the enclosing block.
    ///
    /// Release transaction-local touch keys while both rollback guards are still
    /// armed. Only after both checkpoint applies and their cleanup succeed does
    /// the original parent become usable. This publishes no storage generation.
    pub fn apply(mut self) {
        self.assert_admitted_operable();
        self.arm();
        drop(core::mem::replace(
            &mut self.touched,
            TransactionTouches::Admitted(SortedTouches::new()),
        ));
        let current_retirement = self
            .blocks
            .take()
            .expect("original current checkpoint")
            .apply_retaining();
        let undo_retirement = self
            .revert
            .take()
            .expect("original undo checkpoint")
            .apply_retaining();
        *self.parent_dirty = self.dirty;
        drop(current_retirement);
        drop(undo_retirement);
        *self.parent_applied_transactions = self
            .parent_applied_transactions
            .checked_add(1)
            .expect("applied transaction count exceeds the finite block domain");
        self.resolve();
    }
}

impl<K, V, P> Transaction<'_, K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Borrow this child's original map pool, never a newly constructed budget.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        self.allocation.expect("original admitted transaction pool")
    }
}
