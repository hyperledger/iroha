//! Names for unchanged map custody and inline results; these add no allocation or wrapper.

use super::*;

pub(super) type MapCell<K, V, M> = LinCowCell<
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;
pub(super) type MapRead<'a, K, V, M> = LinCowCellReadTxn<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;
pub(super) type MapWrite<'a, K, V, M> = LinCowCellWriteTxn<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellFamily specialization; field and destruction order are unchanged.
pub(super) type MapFamily<K, V, M> =
    LinCowCellFamily<SuperBlock<K, V, M>, CursorRead<K, V, M>, <M as NodeFunding>::Charge>;

/// Original LinCowCellPredecessor specialization; field and destruction order are unchanged.
pub(super) type MapPredecessor<'a, K, V, M> =
    LinCowCellPredecessor<'a, SuperBlock<K, V, M>, CursorRead<K, V, M>, <M as NodeFunding>::Charge>;

/// Original LinCowCellRetainedPredecessor specialization; field and destruction order are unchanged.
pub(super) type MapRetainedPredecessor<K, V, M> = LinCowCellRetainedPredecessor<
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellWriterAcquisition specialization; field and destruction order are unchanged.
pub(super) type MapWriterAcquisition<'a, K, V, M> = LinCowCellWriterAcquisition<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellOwnedAcquisition specialization; field and destruction order are unchanged.
pub(super) type MapOwnedAcquisition<'a, K, V, M> = LinCowCellOwnedAcquisition<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellOwned specialization; field and destruction order are unchanged.
pub(super) type MapOwned<K, V, M> = LinCowCellOwned<
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original immutable work/base/root handles; no allocation or payload copy.
pub(super) type MapRetainedWork<K, V, M> = LinCowCellRetainedWork<
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellPreparedCommit specialization; field and destruction order are unchanged.
pub(super) type MapPreparedCommit<'a, K, V, M> = LinCowCellPreparedCommit<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellCommitSlot specialization; field and destruction order are unchanged.
pub(super) type MapCommitSlot<'a, K, V, M> = LinCowCellCommitSlot<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellPublished specialization; field and destruction order are unchanged.
pub(super) type MapPublished<'a, K, V, M> = LinCowCellPublished<
    'a,
    SuperBlock<K, V, M>,
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Original LinCowCellCommitRetirement specialization; field and destruction order are unchanged.
pub(super) type MapCommitRetirement<K, V, M> = LinCowCellCommitRetirement<
    CursorRead<K, V, M>,
    CursorWrite<K, V, M>,
    <M as NodeFunding>::Charge,
>;

/// Refused reattachment retains the exact original private map owner.
pub(super) type MapOwnedAcquireResult<'a, K, V, M> =
    Result<BptreeMapOwnedAcquisition<'a, K, V, M>, (BptreeMapOwned<K, V, M>, OwnedWriteError)>;
/// Failed single-map adoption returns the exact owner after unlocking.
pub(super) type MapOwnedWriteResult<'a, K, V, M> =
    Result<BptreeMapWriteTxn<'a, K, V, M>, (BptreeMapOwned<K, V, M>, OwnedWriteError)>;
/// Refusal preserves the original incoming key and value before admission.
pub(super) type AdmittedInsertResult<K, V, P, E> =
    Result<(BptreeMapOwned<K, V, Prepaid<P>>, Option<V>), ((K, V), MapAdmissionError<E>)>;
/// Refusal retains the exact unpublished map and the unchanged incoming input.
pub(super) type OwnedInsertResult<K, V, P, E> = Result<
    (BptreeMapOwned<K, V, Prepaid<P>>, Option<V>),
    (
        (BptreeMapOwned<K, V, Prepaid<P>>, (K, V)),
        MapAdmissionError<E>,
    ),
>;
/// Closed edit refusal returns input without boxing or releasing caller custody.
pub(super) type EditResult<K, V, E> = Result<Option<V>, ((K, V), MapAdmissionError<E>)>;
/// Planning refusal preserves the original input without admitting an allocation.
pub(super) type PreparedInsertResult<'a, K, V, P> =
    Result<BptreeMapPreparedInsert<'a, K, V, P>, ((K, V), PlanningError)>;
/// Insertion refusal retains the actual acquired writer and untouched input.
pub(super) type AcquiredInsertResult<'a, K, V, P, E> = Result<
    (BptreeMapWriteTxn<'a, K, V, Prepaid<P>>, Option<V>),
    (
        BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>,
        (K, V),
        MapAdmissionError<E>,
    ),
>;
/// Writer admission refusal retains its actual original physical guard.
pub(super) type AcquiredWriteResult<'a, K, V, P, E> = Result<
    BptreeMapWriteTxn<'a, K, V, Prepaid<P>>,
    (
        BptreeMapWriterAcquisition<'a, K, V, Prepaid<P>>,
        MapAdmissionError<E>,
    ),
>;
/// Pair edit refusal returns the exact input while both writers remain borrowed.
pub(super) type PairEditResult<K, V, E> = Result<Option<V>, ((K, V), PairInsertError<E>)>;
/// Pair insertion retains both original owners in the existing tuple/drop order.
pub(super) type OwnedPairInsertResult<K, V, P, E> = Result<
    (
        (
            BptreeMapOwned<K, V, Prepaid<P>>,
            BptreeMapOwned<K, Option<V>, Prepaid<P>>,
        ),
        Option<V>,
    ),
    (
        (
            BptreeMapOwned<K, V, Prepaid<P>>,
            BptreeMapOwned<K, Option<V>, Prepaid<P>>,
            K,
            V,
        ),
        PairInsertError<E>,
    ),
>;
