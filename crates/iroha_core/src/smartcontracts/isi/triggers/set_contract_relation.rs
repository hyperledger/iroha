//! One trigger-contract semantic engine with an explicit conservative L1 work proxy.
//! L1 counts source events and full byte footprints; it is not CPU, gas or physical funding.

use super::*;
use crate::state::authority_registry::original_images::RawStorageImages;
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use mv::PublicationPreparationError;
use std::{cmp::Ordering, convert::Infallible};

/// Original semantic failures, in the original phase order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SemanticFailure {
    Overflow,
    Lookup,
    Code,
    Count,
    Missing,
    ActionDuplicate,
    ActionIdMissing,
    ActionKind,
    ActionOrphan,
    ActionActiveMissing,
    ActionActiveUnexpected,
}
impl SemanticFailure {
    fn message(self) -> &'static str {
        match self {
            Self::Overflow => "trigger contract reference count exceeds u64",
            Self::Lookup => "trigger contract lookup hash does not match its original bytecode",
            Self::Code => "trigger contract code hash does not match its original bytecode",
            Self::Count => "trigger contract reference count does not match its actions",
            Self::Missing => "trigger action references a missing original contract",
            Self::ActionDuplicate => {
                "trigger action id belongs to more than one typed action stream"
            }
            Self::ActionIdMissing => "trigger action has no original id index row",
            Self::ActionKind => "trigger id index kind does not match its original typed action",
            Self::ActionOrphan => "trigger id index row has no original typed action",
            Self::ActionActiveMissing => {
                "enabled non-depleted trigger action has no original active index row"
            }
            Self::ActionActiveUnexpected => {
                "trigger active index row has no eligible original typed action"
            }
        }
    }
    pub(crate) fn original_message(self) -> String {
        self.message().to_owned()
    }
}
/// Bounded equality descriptor; equality does not assert original cause identity.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HashFailureDescriptor {
    category: std::mem::Discriminant<norito::Error>,
    resource: Option<norito::core::DecodeResourceError>,
    io: Option<std::io::ErrorKind>,
    exact: [u64; 3],
    context: Option<&'static str>,
}
/// Moves the exact codec cause without boxing, copying or rendering its diagnostic.
#[derive(Debug, thiserror::Error)]
#[error("original trigger typed-hash encoding failed")]
pub(crate) struct HashFailure {
    descriptor: HashFailureDescriptor,
    #[source]
    original: norito::Error,
}
impl PartialEq for HashFailure {
    fn eq(&self, rhs: &Self) -> bool {
        self.descriptor == rhs.descriptor
    }
}
impl Eq for HashFailure {}
impl HashFailure {
    fn new(original: norito::Error) -> Self {
        let mut descriptor = HashFailureDescriptor {
            category: std::mem::discriminant(&original),
            resource: original.decode_resource_error(),
            io: None,
            exact: [0; 3],
            context: None,
        };
        match &original {
            norito::Error::Io(error) => descriptor.io = Some(error.kind()),
            norito::Error::AllocationFailed { bytes } => descriptor.exact[0] = *bytes,
            norito::Error::NestingDepthExceeded {
                depth,
                limit,
                context,
            } => {
                descriptor.exact = [*depth as u64, *limit as u64, 0];
                descriptor.context = Some(context);
            }
            norito::Error::InvalidValue { context }
            | norito::Error::DecodePanic { context }
            | norito::Error::UnsupportedFeature(context) => descriptor.context = Some(context),
            norito::Error::Misaligned { align, addr } => {
                descriptor.exact = [*align as u64, *addr as u64, 0]
            }
            _ => {} // resource variants retain all exact copyable fields above
        }
        Self {
            descriptor,
            original,
        }
    }
    /// Inspect the same original owned codec cause, including private scope provenance.
    #[cfg(test)]
    pub(crate) fn original(&self) -> &norito::Error {
        &self.original
    }
}
/// Exact local refusal categories; semantic failures retain their existing String boundary.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TriggerContractError {
    /// The original Set predicate failed.
    #[error("{0:?}")]
    Semantic(SemanticFailure),
    /// Original publication custody refused this cut.
    #[error(transparent)]
    Publication(#[from] PublicationPreparationError<Infallible>),
    /// Conservative local admission units were exhausted before source access.
    #[error("trigger contract source work admission exhausted")]
    WorkLimit,
    /// Fixed counter capacity arithmetic overflowed.
    #[error("trigger contract counter geometry exceeds addressable storage")]
    CounterGeometry,
    /// Original pool refusal before allocating the fixed counter backing.
    #[error(transparent)]
    Admission(iroha_allocation::AllocationRefusal),
    /// The allocator refused the exact previously admitted fixed backing layout.
    #[error("trigger contract counter allocator refused {requested_bytes} bytes")]
    Allocator { requested_bytes: usize },
    /// Preserve the real inherited codec cause.
    #[error(transparent)]
    Hash(HashFailure),
}
impl From<ChargedBufferError> for TriggerContractError {
    fn from(error: ChargedBufferError) -> Self {
        match error {
            ChargedBufferError::Admission(error) => Self::Admission(error),
            ChargedBufferError::Allocator { requested_bytes } => {
                Self::Allocator { requested_bytes }
            }
        }
    }
}
/// Native B+tree height is bounded by address width, not by a new accepted row limit.
const CURSOR_SETUP: u64 = 29 * usize::BITS as u64 + 44;
const CURSOR_NEXT: u64 = 17 * usize::BITS as u64 + 26;
const HASH_COMPARE: u64 = 67; // two operand borrows, comparison and 64 full operand bytes
const COUNTER_CELL: u64 = 79; // full tail: step, read, compare, branch, optional index write, count8
const INCREMENT: u64 = 19;
const APPEND: u64 = 43;
const COUNT_OUTCOME: u64 = 28;
const EMPTY_CELL: u64 = 11;

#[cfg(test)]
#[derive(Default, Debug, PartialEq, Eq)]
struct Observed {
    setup: usize,
    next: usize,
    compare: usize,
    typed: usize,
    deploy: usize,
    reset: usize,
}
pub(super) struct Work {
    remaining: u64,
    #[cfg(test)]
    observed: Observed,
}
impl Work {
    fn new(remaining: u64) -> Self {
        Self {
            remaining,
            #[cfg(test)]
            observed: Observed::default(),
        }
    }
    fn prepay(&mut self, amount: u64) -> Result<(), TriggerContractError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(TriggerContractError::WorkLimit)?;
        Ok(())
    }
    fn bytes(&mut self, amount: usize) -> Result<(), TriggerContractError> {
        self.prepay(u64::try_from(amount).map_err(|_| TriggerContractError::WorkLimit)?)
    }
    fn setup(&mut self) -> Result<(), TriggerContractError> {
        self.prepay(CURSOR_SETUP)?;
        #[cfg(test)]
        {
            self.observed.setup += 1;
        }
        Ok(())
    }
    fn next<I: Iterator>(&mut self, rows: &mut I) -> Result<Option<I::Item>, TriggerContractError> {
        self.prepay(CURSOR_NEXT)?;
        #[cfg(test)]
        {
            self.observed.next += 1;
        }
        Ok(rows.next())
    }
    fn hash_equal<T: PartialEq>(
        &mut self,
        left: &T,
        right: &T,
    ) -> Result<bool, TriggerContractError> {
        self.prepay(HASH_COMPARE)?;
        #[cfg(test)]
        {
            self.observed.compare += 1;
        }
        Ok(left == right)
    }
}
#[derive(Clone, Copy)]
struct CounterCell {
    hash: HashOf<IvmBytecode>,
    count: u64,
}
/// Real fixed original-pool backing. No clone, growth, replacement pool or row bank.
pub(super) struct CheckedStrategy {
    work: Work,
    counts: ChargedBuffer<CounterCell>,
}
trait Strategy {
    type Error;
    fn control(&mut self, units: u64) -> Result<(), Self::Error>;
    fn failure(&self, failure: SemanticFailure) -> Self::Error;
    fn increment(&mut self, hash: &HashOf<IvmBytecode>) -> Result<(), Self::Error>;
    fn lookup_hash(&mut self, bytecode: &IvmBytecode) -> Result<HashOf<IvmBytecode>, Self::Error>;
    fn code_hash(&mut self, bytecode: &IvmBytecode) -> Result<Hash, Self::Error>;
    fn equal<T: PartialEq>(&mut self, left: &T, right: &T) -> Result<bool, Self::Error>;
    fn count_matches(
        &mut self,
        hash: &HashOf<IvmBytecode>,
        expected: NonZeroU64,
    ) -> Result<bool, Self::Error>;
    fn empty(&mut self) -> Result<bool, Self::Error>;
}
struct OrdinaryStrategy(BTreeMap<HashOf<IvmBytecode>, u64>);
impl Strategy for OrdinaryStrategy {
    type Error = String;
    fn control(&mut self, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn failure(&self, failure: SemanticFailure) -> String {
        failure.original_message()
    }
    fn increment(&mut self, hash: &HashOf<IvmBytecode>) -> Result<(), String> {
        let count = self.0.entry(*hash).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| SemanticFailure::Overflow.original_message())?;
        Ok(())
    }
    fn lookup_hash(&mut self, bytecode: &IvmBytecode) -> Result<HashOf<IvmBytecode>, String> {
        Ok(HashOf::new(bytecode))
    }
    fn code_hash(&mut self, bytecode: &IvmBytecode) -> Result<Hash, String> {
        Ok(ivm::contract_code_hash(bytecode.as_ref()))
    }
    fn equal<T: PartialEq>(&mut self, left: &T, right: &T) -> Result<bool, String> {
        Ok(left == right)
    }
    fn count_matches(
        &mut self,
        hash: &HashOf<IvmBytecode>,
        expected: NonZeroU64,
    ) -> Result<bool, String> {
        Ok(self.0.remove(hash) == Some(expected.get()))
    }
    fn empty(&mut self) -> Result<bool, String> {
        Ok(self.0.is_empty())
    }
}
impl Strategy for CheckedStrategy {
    type Error = TriggerContractError;
    fn control(&mut self, units: u64) -> Result<(), Self::Error> {
        self.work.prepay(units)
    }
    fn failure(&self, failure: SemanticFailure) -> Self::Error {
        TriggerContractError::Semantic(failure)
    }
    fn increment(&mut self, hash: &HashOf<IvmBytecode>) -> Result<(), Self::Error> {
        self.work.prepay(3)?; // helper, fixed iterator construction and prepaid terminal next
        let mut found = None;
        for (index, cell) in self.counts.as_slice().iter().enumerate() {
            self.work.prepay(COUNTER_CELL)?;
            #[cfg(test)]
            {
                self.work.observed.compare += 1;
            }
            if cell.hash == *hash {
                found = Some(index);
            }
        }
        self.work.prepay(1)?;
        if let Some(index) = found {
            self.work.prepay(INCREMENT)?;
            let cell = &mut self.counts.as_mut_slice()[index];
            cell.count = cell
                .count
                .checked_add(1)
                .ok_or(TriggerContractError::Semantic(SemanticFailure::Overflow))?;
        } else {
            self.work.prepay(APPEND + INCREMENT)?;
            let count = 0u64
                .checked_add(1)
                .ok_or(TriggerContractError::Semantic(SemanticFailure::Overflow))?;
            self.counts
                .try_push(CounterCell { hash: *hash, count })
                .map_err(|_| TriggerContractError::CounterGeometry)?;
        }
        Ok(())
    }
    fn lookup_hash(&mut self, bytecode: &IvmBytecode) -> Result<HashOf<IvmBytecode>, Self::Error> {
        self.work.prepay(3)?; // helper entry, AsRef and length metadata
        let length = bytecode.as_ref().len();
        let payload = length
            .checked_add(8)
            .ok_or(TriggerContractError::WorkLimit)?;
        let prefix = compact_prefix(payload);
        let units = 42u64
            .checked_add(2 * prefix)
            .and_then(|v| v.checked_add((length as u64).checked_mul(2)?))
            .ok_or(TriggerContractError::WorkLimit)?;
        self.work.prepay(units)?;
        #[cfg(test)]
        {
            self.work.observed.typed += 1;
        }
        HashOf::try_new(bytecode)
            .map_err(|cause| TriggerContractError::Hash(HashFailure::new(cause)))
    }
    fn code_hash(&mut self, bytecode: &IvmBytecode) -> Result<Hash, Self::Error> {
        self.work.prepay(3)?;
        let length = bytecode.as_ref().len();
        self.work.prepay(
            36u64
                .checked_add(length as u64)
                .ok_or(TriggerContractError::WorkLimit)?,
        )?;
        #[cfg(test)]
        {
            self.work.observed.deploy += 1;
        }
        Ok(ivm::contract_code_hash(bytecode.as_ref()))
    }
    fn equal<T: PartialEq>(&mut self, left: &T, right: &T) -> Result<bool, Self::Error> {
        self.work.hash_equal(left, right)
    }
    fn count_matches(
        &mut self,
        hash: &HashOf<IvmBytecode>,
        expected: NonZeroU64,
    ) -> Result<bool, Self::Error> {
        self.work.prepay(3)?; // helper, fixed iterator construction and prepaid terminal next
        let mut found = None;
        for (index, cell) in self.counts.as_slice().iter().enumerate() {
            self.work.prepay(COUNTER_CELL)?;
            #[cfg(test)]
            {
                self.work.observed.compare += 1;
            }
            if cell.hash == *hash {
                found = Some(index);
            }
        }
        self.work.prepay(COUNT_OUTCOME)?;
        let actual = found.map(|index| {
            let cell = &mut self.counts.as_mut_slice()[index];
            let count = cell.count;
            cell.count = 0;
            count
        });
        Ok(actual == Some(expected.get()))
    }
    fn empty(&mut self) -> Result<bool, Self::Error> {
        self.work.prepay(3)?; // helper, fixed iterator and terminal next
        let mut empty = true;
        for cell in self.counts.as_slice() {
            self.work.prepay(EMPTY_CELL)?;
            empty &= cell.count == 0;
        }
        Ok(empty)
    }
}
fn compact_prefix(value: usize) -> u64 {
    ((usize::BITS - value.leading_zeros()).max(1) as u64).div_ceil(7)
}
#[derive(Clone, Copy)]
enum Phase {
    Data,
    Pipeline,
    Time,
    ByCall,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Image {
    Current,
    Predecessor,
}
trait Sources<S: Strategy> {
    fn actions(&self, phase: Phase, image: Image, strategy: &mut S) -> Result<(), S::Error>;
    fn contracts(&self, image: Image, strategy: &mut S) -> Result<(), S::Error>;
}
fn reference<S: Strategy>(action: &ExecutableRef, strategy: &mut S) -> Result<(), S::Error> {
    strategy.control(35)?; // callback dispatch, variant inspection/copy occurrence and full hash32
    if let ExecutableRef::Ivm(hash) = action {
        strategy.increment(hash)?;
    }
    Ok(())
}
fn contract<S: Strategy>(
    key: &HashOf<IvmBytecode>,
    entry: &IvmBytecodeEntry,
    strategy: &mut S,
) -> Result<(), S::Error> {
    strategy.control(1)?;
    let lookup = strategy.lookup_hash(&entry.original_contract)?;
    let matches = strategy.equal(&lookup, key)?;
    strategy.control(1)?;
    if !matches {
        return Err(strategy.failure(SemanticFailure::Lookup));
    }
    let code = strategy.code_hash(&entry.original_contract)?;
    let matches = strategy.equal(&code, &entry.code_hash)?;
    strategy.control(1)?;
    if !matches {
        return Err(strategy.failure(SemanticFailure::Code));
    }
    let matches = strategy.count_matches(key, entry.count)?;
    strategy.control(1)?;
    if !matches {
        return Err(strategy.failure(SemanticFailure::Count));
    }
    Ok(())
}
/// The only semantic phase engine used by current public validation and both checked images.
fn validate_image<S: Strategy>(
    sources: &impl Sources<S>,
    image: Image,
    strategy: &mut S,
) -> Result<(), S::Error> {
    strategy.control(1)?;
    for phase in [Phase::Data, Phase::Pipeline, Phase::Time, Phase::ByCall] {
        strategy.control(1)?;
        sources.actions(phase, image, strategy)?;
    }
    strategy.control(1)?;
    sources.contracts(image, strategy)?;
    let empty = strategy.empty()?;
    strategy.control(1)?;
    if !empty {
        return Err(strategy.failure(SemanticFailure::Missing));
    }
    Ok(())
}
struct OrdinarySources<'a, W: ?Sized>(&'a W);
impl<W: SetReadOnly + ?Sized> Sources<OrdinaryStrategy> for OrdinarySources<'_, W> {
    fn actions(
        &self,
        phase: Phase,
        _: Image,
        strategy: &mut OrdinaryStrategy,
    ) -> Result<(), String> {
        macro_rules! visit {
            ($field:ident) => {
                for (_, action) in self.0.$field().iter() {
                    reference(&action.executable, strategy)?;
                }
            };
        }
        match phase {
            Phase::Data => visit!(data_triggers),
            Phase::Pipeline => visit!(pipeline_triggers),
            Phase::Time => visit!(time_triggers),
            Phase::ByCall => visit!(by_call_triggers),
        }
        Ok(())
    }
    fn contracts(&self, _: Image, strategy: &mut OrdinaryStrategy) -> Result<(), String> {
        for (key, entry) in self.0.contracts().iter() {
            contract(key, entry, strategy)?;
        }
        Ok(())
    }
}
pub(super) fn validate_current(world: &(impl SetReadOnly + ?Sized)) -> Result<(), String> {
    validate_image(
        &OrdinarySources(world),
        Image::Current,
        &mut OrdinaryStrategy(BTreeMap::new()),
    )
}
pub(super) trait MergeKey: mv::Key {
    fn compare(&self, other: &Self, work: &mut Work) -> Result<Ordering, TriggerContractError>;
}
impl MergeKey for TriggerId {
    fn compare(&self, other: &Self, work: &mut Work) -> Result<Ordering, TriggerContractError> {
        work.prepay(7)?; // getters2, string borrows2, lengths2 and cmp1, before bytes
        let left: &str = self.name().as_ref();
        let right: &str = other.name().as_ref();
        work.bytes(left.len())?;
        work.bytes(right.len())?;
        #[cfg(test)]
        {
            work.observed.compare += 1;
        }
        Ok(self.cmp(other))
    }
}
impl MergeKey for HashOf<IvmBytecode> {
    fn compare(&self, other: &Self, work: &mut Work) -> Result<Ordering, TriggerContractError> {
        work.prepay(HASH_COMPARE)?;
        #[cfg(test)]
        {
            work.observed.compare += 1;
        }
        Ok(self.cmp(other))
    }
}
pub(super) fn visit_original<'a, K: MergeKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: Image,
    strategy: &mut CheckedStrategy,
    mut inspect: impl FnMut(&'a K, &'a V, &mut CheckedStrategy) -> Result<(), TriggerContractError>,
) -> Result<(), TriggerContractError> {
    strategy.work.setup()?;
    let mut current = rows.current_entries();
    if image == Image::Current {
        loop {
            strategy.work.prepay(2)?; // loop and result branch before original call
            let Some((key, value)) = strategy.work.next(&mut current)? else {
                break;
            };
            inspect(key, value, strategy)?;
        }
        return Ok(());
    }
    strategy.work.setup()?;
    let mut undo = rows.undo_entries();
    let mut current_head = strategy.work.next(&mut current)?;
    let mut undo_head = strategy.work.next(&mut undo)?;
    loop {
        strategy.work.prepay(4)?; // head state, match dispatch, consume/refill, loop
        match (current_head, undo_head) {
            (None, None) => break,
            (Some((key, value)), None) => {
                inspect(key, value, strategy)?;
                current_head = strategy.work.next(&mut current)?;
            }
            (None, Some((key, prior))) => {
                strategy.work.prepay(1)?;
                if let Some(value) = prior {
                    inspect(key, value, strategy)?;
                }
                undo_head = strategy.work.next(&mut undo)?;
            }
            (Some((current_key, current_value)), Some((undo_key, prior))) => {
                match current_key.compare(undo_key, &mut strategy.work)? {
                    Ordering::Less => {
                        inspect(current_key, current_value, strategy)?;
                        current_head = strategy.work.next(&mut current)?;
                    }
                    Ordering::Equal => {
                        strategy.work.prepay(1)?;
                        if let Some(value) = prior {
                            inspect(undo_key, value, strategy)?;
                        }
                        current_head = strategy.work.next(&mut current)?;
                        undo_head = strategy.work.next(&mut undo)?;
                    }
                    Ordering::Greater => {
                        strategy.work.prepay(1)?;
                        if let Some(value) = prior {
                            inspect(undo_key, value, strategy)?;
                        }
                        undo_head = strategy.work.next(&mut undo)?;
                    }
                }
            }
        }
    }
    Ok(())
}
pub(super) struct NativeSources<'a, D, P, T, C, R> {
    pub(super) data: &'a D,
    pub(super) pipeline: &'a P,
    pub(super) time: &'a T,
    pub(super) by_call: &'a C,
    pub(super) contracts: &'a R,
}
impl<D, P, T, C, R> Sources<CheckedStrategy> for NativeSources<'_, D, P, T, C, R>
where
    D: RawStorageImages<TriggerId, LoadedAction<DataEventFilter>>,
    P: RawStorageImages<TriggerId, LoadedAction<PipelineEventFilterBox>>,
    T: RawStorageImages<TriggerId, LoadedAction<TimeEventFilter>>,
    C: RawStorageImages<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
    R: RawStorageImages<HashOf<IvmBytecode>, IvmBytecodeEntry>,
{
    fn actions(
        &self,
        phase: Phase,
        image: Image,
        strategy: &mut CheckedStrategy,
    ) -> Result<(), TriggerContractError> {
        macro_rules! visit {
            ($field:ident) => {
                visit_original(self.$field, image, strategy, |_, action, strategy| {
                    reference(&action.executable, strategy)
                })
            };
        }
        match phase {
            Phase::Data => visit!(data),
            Phase::Pipeline => visit!(pipeline),
            Phase::Time => visit!(time),
            Phase::ByCall => visit!(by_call),
        }
    }
    fn contracts(
        &self,
        image: Image,
        strategy: &mut CheckedStrategy,
    ) -> Result<(), TriggerContractError> {
        visit_original(self.contracts, image, strategy, contract)
    }
}
fn capacity<K: mv::Key, V: mv::Value>(
    rows: &impl RawStorageImages<K, V>,
    work: &mut Work,
) -> Result<usize, TriggerContractError> {
    work.setup()?;
    let current = rows.current_entries();
    work.prepay(2)?;
    let current = current.len();
    work.setup()?;
    let undo = rows.undo_entries();
    work.prepay(2)?;
    let undo = undo.len();
    work.prepay(1)?;
    current
        .checked_add(undo)
        .ok_or(TriggerContractError::CounterGeometry)
}
impl CheckedStrategy {
    pub(super) fn prepare<D, P, T, C, R>(
        sources: &NativeSources<'_, D, P, T, C, R>,
        max_work: u64,
        budget: &AllocationBudget,
    ) -> Result<Self, TriggerContractError>
    where
        D: RawStorageImages<TriggerId, LoadedAction<DataEventFilter>>,
        P: RawStorageImages<TriggerId, LoadedAction<PipelineEventFilterBox>>,
        T: RawStorageImages<TriggerId, LoadedAction<TimeEventFilter>>,
        C: RawStorageImages<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
        R: RawStorageImages<HashOf<IvmBytecode>, IvmBytecodeEntry>,
    {
        let mut work = Work::new(max_work);
        let mut size = capacity(sources.data, &mut work)?;
        for count in [
            capacity(sources.pipeline, &mut work)?,
            capacity(sources.time, &mut work)?,
            capacity(sources.by_call, &mut work)?,
        ] {
            work.prepay(1)?;
            size = size
                .checked_add(count)
                .ok_or(TriggerContractError::CounterGeometry)?;
        }
        work.prepay(6)?; // layout/capacity/admission/construction/initialization and strategy return
        let counts = ChargedBuffer::new(size, budget)?;
        Ok(Self { work, counts })
    }
    pub(super) fn encoding_rows<'a, K: mv::Key, V: mv::Value>(
        &mut self,
        source: &'a impl RawStorageImages<K, V>,
    ) -> Result<impl Iterator<Item = (&'a K, &'a V)> + 'a, TriggerContractError> {
        self.work.setup()?;
        let rows = source.current_entries();
        self.work.prepay(2)?;
        let attempts = rows
            .len()
            .checked_add(1)
            .ok_or(TriggerContractError::WorkLimit)?;
        let units = (attempts as u64)
            .checked_mul(CURSOR_NEXT)
            .ok_or(TriggerContractError::WorkLimit)?;
        self.work.prepay(units)?;
        Ok(rows)
    }
    fn reset(&mut self) -> Result<(), TriggerContractError> {
        self.work.prepay(2)?;
        self.work.bytes(self.counts.as_slice().len())?;
        #[cfg(test)]
        {
            self.work.observed.reset += 1;
        }
        self.counts.truncate(0);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn action_test_work(amount: u64, budget: &AllocationBudget) -> Self {
        Self {
            work: Work::new(amount),
            counts: ChargedBuffer::new(0, budget).unwrap(),
        }
    }
    #[cfg(test)]
    pub(super) fn action_remaining(&self) -> u64 {
        self.work.remaining
    }
    /// Admit action-local source-event/byte capsules on the same remaining allowance.
    pub(super) fn admit_action_work(&mut self, units: u64) -> Result<(), TriggerContractError> {
        self.work.prepay(units)
    }
    /// Compare complete original TriggerIds through the one prepaid key primitive.
    pub(super) fn compare_action_ids(
        &mut self,
        left: &TriggerId,
        right: &TriggerId,
    ) -> Result<bool, TriggerContractError> {
        left.compare(right, &mut self.work)
            .map(|order| order == Ordering::Equal)
    }
    /// Invoke the original contract engine for one image, without another predicate.
    pub(super) fn validate_action_contract_image<D, P, T, C, R>(
        &mut self,
        sources: &NativeSources<'_, D, P, T, C, R>,
        image: Image,
    ) -> Result<(), TriggerContractError>
    where
        D: RawStorageImages<TriggerId, LoadedAction<DataEventFilter>>,
        P: RawStorageImages<TriggerId, LoadedAction<PipelineEventFilterBox>>,
        T: RawStorageImages<TriggerId, LoadedAction<TimeEventFilter>>,
        C: RawStorageImages<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
        R: RawStorageImages<HashOf<IvmBytecode>, IvmBytecodeEntry>,
    {
        validate_image(sources, image, self)
    }
    /// Retire only the initialized fixed counter prefix before the next image.
    pub(super) fn reset_action_contract_counts(&mut self) -> Result<(), TriggerContractError> {
        self.reset()
    }
    pub(super) fn validate<D, P, T, C, R>(
        &mut self,
        sources: &NativeSources<'_, D, P, T, C, R>,
    ) -> Result<(), TriggerContractError>
    where
        D: RawStorageImages<TriggerId, LoadedAction<DataEventFilter>>,
        P: RawStorageImages<TriggerId, LoadedAction<PipelineEventFilterBox>>,
        T: RawStorageImages<TriggerId, LoadedAction<TimeEventFilter>>,
        C: RawStorageImages<TriggerId, LoadedAction<ExecuteTriggerEventFilter>>,
        R: RawStorageImages<HashOf<IvmBytecode>, IvmBytecodeEntry>,
    {
        validate_image(sources, Image::Current, self)?;
        self.reset()?;
        validate_image(sources, Image::Predecessor, self)
    }
}
/// Empty capture control baseline; the incremental reference is one L3 no-undo singleton.
/// These are scheduling references, never validity, bytecode length or row-count rules.
pub(crate) const TRIGGER_CONTRACT_BASE_WORK: u64 = 24 * CURSOR_SETUP + 16 * CURSOR_NEXT + 83;
pub(crate) const TRIGGER_CONTRACT_ROW_WORK: u64 = 5 * CURSOR_NEXT + 923;
pub(crate) fn scheduled_work(limits: crate::state::authority_registry::leaf::LeafLimits) -> u64 {
    TRIGGER_CONTRACT_BASE_WORK
        .saturating_add(limits.max_rows.saturating_mul(TRIGGER_CONTRACT_ROW_WORK))
        .saturating_add(limits.max_streamed_value_bytes.saturating_mul(3))
}

#[cfg(test)]
#[path = "set_contract_relation/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "set_contract_relation/work_tests.rs"]
mod work_tests;
