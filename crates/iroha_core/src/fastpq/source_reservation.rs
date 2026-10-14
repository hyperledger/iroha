//! Journaled reservations for exact FASTPQ source contributions.
//!
//! The complete-entry adapter keeps one whole ordered entry bundle in one replaceable
//! contribution. Its M/S are one public frame; independently measured occurrence
//! frames must never be summed for production entry accounting. The occurrence API
//! remains a lower-level accounting test surface.
//!
//! State supplies logical invocation ownership, authenticated frozen policy and
//! exact before-movement measurement. Physical State transactions borrow both
//! quota journals and publish or discard them with State and witness overlays;
//! final source inventory reconciliation checks every retained entry and dimension.

use std::{collections::BTreeMap, sync::Arc};

/// Fixed accounting order, matching source construction's E/T/D/I/M/S dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceDimension {
    /// Logical executed entries, including entries with no transfers.
    ExecutedEntries,
    /// Complete original transcript occurrences.
    Transcripts,
    /// Original deltas across all occurrences.
    Deltas,
    /// Sum of canonical original private-input frame lengths.
    InputTranscriptBytes,
    /// Maximum complete public-statement frame length.
    IndividualStatementBytes,
    /// Sum of complete public-statement frame lengths.
    TotalStatementBytes,
}

const DIMENSIONS: [SourceDimension; 6] = [
    SourceDimension::ExecutedEntries,
    SourceDimension::Transcripts,
    SourceDimension::Deltas,
    SourceDimension::InputTranscriptBytes,
    SourceDimension::IndividualStatementBytes,
    SourceDimension::TotalStatementBytes,
];

/// Fixed-width exact usage, also used for caller-supplied inclusive ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceUsage {
    /// Logical entry count E.
    pub(crate) executed_entries: u64,
    /// Whole occurrence count T.
    pub(crate) transcripts: u64,
    /// Original delta count D.
    pub(crate) deltas: u64,
    /// Original canonical input bytes I.
    pub(crate) input_transcript_bytes: u64,
    /// Largest canonical public statement M.
    pub(crate) max_statement_bytes: u64,
    /// Total canonical public statement bytes S.
    pub(crate) total_statement_bytes: u64,
}

impl SourceUsage {
    /// Empty accounting value; a zero ceiling means zero, never unlimited.
    pub(crate) const ZERO: Self = Self {
        executed_entries: 0,
        transcripts: 0,
        deltas: 0,
        input_transcript_bytes: 0,
        max_statement_bytes: 0,
        total_statement_bytes: 0,
    };

    fn get(self, dimension: SourceDimension) -> u64 {
        match dimension {
            SourceDimension::ExecutedEntries => self.executed_entries,
            SourceDimension::Transcripts => self.transcripts,
            SourceDimension::Deltas => self.deltas,
            SourceDimension::InputTranscriptBytes => self.input_transcript_bytes,
            SourceDimension::IndividualStatementBytes => self.max_statement_bytes,
            SourceDimension::TotalStatementBytes => self.total_statement_bytes,
        }
    }

    fn set(&mut self, dimension: SourceDimension, value: u64) {
        match dimension {
            SourceDimension::ExecutedEntries => self.executed_entries = value,
            SourceDimension::Transcripts => self.transcripts = value,
            SourceDimension::Deltas => self.deltas = value,
            SourceDimension::InputTranscriptBytes => self.input_transcript_bytes = value,
            SourceDimension::IndividualStatementBytes => self.max_statement_bytes = value,
            SourceDimension::TotalStatementBytes => self.total_statement_bytes = value,
        }
    }

    fn replaced(self, old: Self, new: Self, maximum: u64) -> Result<Self, ReservationError> {
        let mut total = Self::ZERO;
        for dimension in DIMENSIONS {
            let value = if dimension == SourceDimension::IndividualStatementBytes {
                maximum
            } else {
                self.get(dimension)
                    .checked_sub(old.get(dimension))
                    .ok_or(ReservationError::Invariant(
                        ReservationInvariant::UsageUnderflow { dimension },
                    ))?
                    .checked_add(new.get(dimension))
                    .ok_or(ReservationError::Invariant(
                        ReservationInvariant::UsageOverflow { dimension },
                    ))?
            };
            total.set(dimension, value);
        }
        Ok(total)
    }
}

/// Explicit limits; this type supplies no production defaults or policy authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservationPolicy {
    /// Ceiling on the complete cumulative logical entry, across physical fragments.
    pub(crate) intrinsic: SourceUsage,
    /// Ceiling on all entries committed or staged in this block ledger.
    pub(crate) block: SourceUsage,
}

/// Frozen adapter-supplied scope; equality checks do not authenticate these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservationContext {
    /// Source height selected by the State owner.
    pub(crate) height: u64,
    /// Authenticated policy commitment to be supplied by the future State adapter.
    pub(crate) policy_digest: [u8; 32],
    /// Stable accounting scope across business, penalty and fee fragments.
    /// Phase-specific allocation rules belong to the future authenticated owner policy.
    pub(crate) scope_tag: u64,
}

/// Exact replacement contribution, with one complete statement frame M=S.
/// The occurrence constructor fixes T=1; the entry-bundle adapter measures its
/// complete ordered occurrence slice. This is not a measurement certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OccurrenceUsage {
    transcripts: u64,
    deltas: u64,
    input_bytes: u64,
    statement_bytes: u64,
}

impl OccurrenceUsage {
    #[cfg(test)]
    /// Accept exact caller-measured counts after checked conversion into u64.
    ///
    /// The adapter must verify one transcript and M=S in its measurement result.
    /// This constructor does not inspect, finalize or authenticate a transcript.
    pub(crate) fn new(
        deltas: u64,
        input_bytes: u64,
        statement_bytes: u64,
    ) -> Result<Self, ReservationError> {
        if deltas == 0 || input_bytes == 0 || statement_bytes == 0 {
            return Err(ReservationError::Invariant(
                ReservationInvariant::EmptyOccurrence,
            ));
        }
        Ok(Self {
            transcripts: 1,
            deltas,
            input_bytes,
            statement_bytes,
        })
    }

    fn usage(self) -> SourceUsage {
        SourceUsage {
            executed_entries: 0,
            transcripts: self.transcripts,
            deltas: self.deltas,
            input_transcript_bytes: self.input_bytes,
            max_statement_bytes: self.statement_bytes,
            total_statement_bytes: self.statement_bytes,
        }
    }
}

/// Malformed capability/lifetime/accounting state; never capacity deferral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationInvariant {
    /// A token belongs to another block ledger instance.
    ForeignLedger,
    /// A requested or token context differs from this ledger's frozen scope.
    ContextMismatch,
    /// An owner was rolled back or its generation is no longer live.
    StaleOwner,
    /// A slot belongs to a different logical owner.
    ForeignSlotOwner,
    /// A slot was replaced/rolled back or its generation is no longer live.
    StaleSlot,
    /// A checkpoint belongs to a different physical transaction.
    #[cfg(test)]
    ForeignTransaction,
    /// This checkpoint's journal prefix was discarded or replaced.
    #[cfg(test)]
    StaleCheckpoint,
    /// A nonempty occurrence must have positive delta and canonical frame counts.
    #[cfg(test)]
    EmptyOccurrence,
    /// A complete-entry measurement is inconsistent with its one-frame shape.
    InvalidEntryBundleMeasurement,
    /// A sum cannot be represented in the fixed accounting integer.
    UsageOverflow {
        /// First overflowing E/T/D/I/M/S dimension.
        dimension: SourceDimension,
    },
    /// Removing an owned contribution contradicts the cached accounting state.
    UsageUnderflow {
        /// First inconsistent dimension.
        dimension: SourceDimension,
    },
    /// Maximum multiplicities contradict the live entries/slots.
    InvalidMaximumIndex,
    /// An intrinsic ceiling exceeds the corresponding whole-block ceiling.
    InvalidPolicy {
        /// First incoherent dimension.
        dimension: SourceDimension,
    },
    /// Private identity/generation allocation exhausted; identifiers never wrap.
    GenerationOverflow,
    /// An existing non-owner contribution already violates the block invariant.
    ExistingUsageExceedsBlock {
        /// First inconsistent dimension.
        dimension: SourceDimension,
    },
}

/// Typed owner outcome; intrinsic is checked for the whole entry before capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationError {
    /// Prospective complete entry usage exceeds its intrinsic inclusive profile.
    Intrinsic {
        /// First exceeded dimension in E/T/D/I/M/S order.
        dimension: SourceDimension,
        /// Complete prospective owner usage, not just the changed occurrence.
        actual: u64,
        /// Caller-supplied inclusive intrinsic ceiling.
        maximum: u64,
    },
    /// The entry fits intrinsically but other block work leaves insufficient room.
    RemainingBlock {
        /// First exceeded dimension in E/T/D/I/M/S order.
        dimension: SourceDimension,
        /// Complete prospective owner usage in this dimension.
        required: u64,
        /// Ceiling after excluding this owner's old contribution; M is not subtracted.
        available: u64,
    },
    /// A capability, context, source shape or arithmetic invariant failed.
    Invariant(ReservationInvariant),
}

impl std::fmt::Display for ReservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FASTPQ source reservation: {self:?}")
    }
}

impl std::error::Error for ReservationError {}

#[derive(Clone, Debug)]
struct OwnerBinding {
    ledger: Arc<()>,
    context: ReservationContext,
    id: u64,
    generation: u64,
}

/// Opaque logical-entry capability, reusable across committed physical fragments.
/// It grants no execution identity beyond this ledger's internal bookkeeping.
#[derive(Clone, Debug)]
pub(crate) struct EntryOwner {
    binding: OwnerBinding,
}

/// Opaque replaceable occurrence capability; successful replacement supersedes it.
#[derive(Clone, Debug)]
pub(crate) struct OccurrenceSlot {
    owner: OwnerBinding,
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy)]
struct SlotState {
    generation: u64,
    usage: OccurrenceUsage,
}

struct OwnerState {
    generation: u64,
    next_slot: u64,
    slots: BTreeMap<u64, SlotState>,
    maxima: BTreeMap<u64, u64>,
    usage: SourceUsage,
}

fn maximum_after(index: &BTreeMap<u64, u64>, old: Option<u64>, new: Option<u64>) -> u64 {
    // Removing one occurrence can expose at most the immediately preceding key.
    index
        .iter()
        .rev()
        .find(|(value, count)| old != Some(**value) || **count > 1)
        .map_or(0, |(&value, _)| value)
        .max(new.unwrap_or(0))
}

fn check_maximum_change(
    index: &BTreeMap<u64, u64>,
    old: Option<u64>,
    new: Option<u64>,
) -> Result<(), ReservationError> {
    if old.is_some_and(|value| index.get(&value).copied().unwrap_or(0) == 0) {
        return Err(ReservationError::Invariant(
            ReservationInvariant::InvalidMaximumIndex,
        ));
    }
    if old != new && new.is_some_and(|value| index.get(&value).copied() == Some(u64::MAX)) {
        return Err(ReservationError::Invariant(
            ReservationInvariant::InvalidMaximumIndex,
        ));
    }
    Ok(())
}

fn change_maximum(index: &mut BTreeMap<u64, u64>, old: Option<u64>, new: Option<u64>) {
    if old == new {
        return;
    }
    if let Some(value) = old {
        let count = index.get_mut(&value).expect("prechecked maximum removal");
        *count -= 1;
        if *count == 0 {
            index.remove(&value);
        }
    }
    if let Some(value) = new {
        *index.entry(value).or_default() += 1;
    }
}

fn check_budget(
    owner: SourceUsage,
    others: SourceUsage,
    block: SourceUsage,
    policy: ReservationPolicy,
) -> Result<(), ReservationError> {
    for dimension in DIMENSIONS {
        if others.get(dimension) > policy.block.get(dimension) {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ExistingUsageExceedsBlock { dimension },
            ));
        }
    }
    for dimension in DIMENSIONS {
        if owner.get(dimension) > policy.intrinsic.get(dimension) {
            return Err(ReservationError::Intrinsic {
                dimension,
                actual: owner.get(dimension),
                maximum: policy.intrinsic.get(dimension),
            });
        }
    }
    for dimension in DIMENSIONS {
        if block.get(dimension) > policy.block.get(dimension) {
            let available = if dimension == SourceDimension::IndividualStatementBytes {
                policy.block.get(dimension)
            } else {
                policy.block.get(dimension) - others.get(dimension)
            };
            return Err(ReservationError::RemainingBlock {
                dimension,
                required: owner.get(dimension),
                available,
            });
        }
    }
    Ok(())
}

/// Immutable original-ledger publication receipt; public counters cannot recreate it.
/// Retaining the existing Arc prevents address reuse from acquiring this identity.
#[derive(Debug)]
pub(super) struct ReservationCommitSeal {
    identity: Arc<()>,
    context: ReservationContext,
    policy: ReservationPolicy,
    applied_generation: u64,
    usage: SourceUsage,
}

/// Block-owned reservations with exclusive, journaled physical transactions.
/// Private IDs/generations never enter canonical ordering, serialization or hashes.
pub(crate) struct ReservationLedger {
    identity: Arc<()>,
    context: ReservationContext,
    policy: ReservationPolicy,
    next_generation: u64,
    /// Original transaction generation of the most recent nonempty publication.
    applied_generation: u64,
    owners: BTreeMap<u64, OwnerState>,
    maxima: BTreeMap<u64, u64>,
    usage: SourceUsage,
}

impl ReservationLedger {
    /// Create an empty ledger under explicit scope and inclusive coherent ceilings.
    /// A larger intrinsic ceiling would permit perpetual deferral in an empty block.
    pub(crate) fn new(
        context: ReservationContext,
        policy: ReservationPolicy,
    ) -> Result<Self, ReservationError> {
        for dimension in DIMENSIONS {
            if policy.intrinsic.get(dimension) > policy.block.get(dimension) {
                return Err(ReservationError::Invariant(
                    ReservationInvariant::InvalidPolicy { dimension },
                ));
            }
        }
        Ok(Self {
            identity: Arc::new(()),
            context,
            policy,
            next_generation: 1,
            applied_generation: 0,
            owners: BTreeMap::new(),
            maxima: BTreeMap::new(),
            usage: SourceUsage::ZERO,
        })
    }

    fn take_generation(&mut self) -> Result<u64, ReservationError> {
        let next = self
            .next_generation
            .checked_add(1)
            .ok_or(ReservationError::Invariant(
                ReservationInvariant::GenerationOverflow,
            ))?;
        let allocated = self.next_generation;
        self.next_generation = next;
        Ok(allocated)
    }

    /// Start an exclusive physical scope; Drop undoes every uncommitted change.
    /// Generations stay consumed after abort, so provisional handles cannot revive.
    pub(crate) fn transaction(
        &mut self,
        context: ReservationContext,
    ) -> Result<ReservationTransaction<'_>, ReservationError> {
        if context != self.context {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ContextMismatch,
            ));
        }
        let generation = self.take_generation()?;
        Ok(ReservationTransaction {
            ledger: self,
            journal: Vec::new(),
            generation,
            committed: false,
        })
    }

    /// Retain the original allocation and last applied transaction without new backing.
    fn retain_commit_seal(&self) -> ReservationCommitSeal {
        ReservationCommitSeal {
            identity: Arc::clone(&self.identity),
            context: self.context,
            policy: self.policy,
            applied_generation: self.applied_generation,
            usage: self.usage,
        }
    }

    /// Validate original custody, frozen limits and exact applied journal lineage.
    fn matches_commit_seal(&self, seal: &ReservationCommitSeal) -> bool {
        Arc::ptr_eq(&self.identity, &seal.identity)
            && self.context == seal.context
            && self.policy == seal.policy
            && self.applied_generation == seal.applied_generation
            && self.usage == seal.usage
    }

    /// Exact committed usage when no physical transaction holds the exclusive borrow.
    pub(crate) const fn usage(&self) -> SourceUsage {
        self.usage
    }
}

enum Undo {
    Owner {
        id: u64,
        block_before: SourceUsage,
    },
    Slot {
        #[cfg(test)]
        generation: u64,
        owner: u64,
        id: u64,
        previous: Option<SlotState>,
        next_slot_before: u64,
        owner_before: SourceUsage,
        block_before: SourceUsage,
    },
}

impl Undo {
    #[cfg(test)]
    fn generation(&self) -> u64 {
        match self {
            Self::Owner { id, .. } => *id,
            Self::Slot { generation, .. } => *generation,
        }
    }
}

/// Non-cloneable identity of one original quota transaction, including aborted generations.
/// Public block coordinates and equal journal contents cannot reconstruct this token.
pub(crate) struct SourceTransactionIdentity {
    ledger: Arc<()>,
    context: ReservationContext,
    generation: u64,
}

/// Exclusive physical scope with O(changes) undo storage, without block-map snapshots.
/// State must pair accounting commit/rollback with its WSV and source side effects.
pub(crate) struct ReservationTransaction<'a> {
    ledger: &'a mut ReservationLedger,
    journal: Vec<Undo>,
    generation: u64,
    committed: bool,
}

#[cfg(test)]
/// Constant-size checkpoint bound to a retained prefix of one physical transaction.
/// Ancestor savepoints survive inner rollback; discarded journal branches do not revive.
pub(crate) struct ReservationCheckpoint {
    identity: Arc<()>,
    context: ReservationContext,
    transaction: u64,
    boundary_generation: u64,
    journal_len: usize,
}

impl ReservationTransaction<'_> {
    fn retain_identity(&self) -> SourceTransactionIdentity {
        SourceTransactionIdentity {
            ledger: Arc::clone(&self.ledger.identity),
            context: self.ledger.context,
            generation: self.generation,
        }
    }
    fn matches_identity(&self, identity: &SourceTransactionIdentity) -> bool {
        Arc::ptr_eq(&self.ledger.identity, &identity.ledger)
            && self.ledger.context == identity.context
            && self.generation == identity.generation
    }

    fn validate_binding(&self, binding: &OwnerBinding) -> Result<(), ReservationError> {
        if !Arc::ptr_eq(&binding.ledger, &self.ledger.identity) {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ForeignLedger,
            ));
        }
        if binding.context != self.ledger.context {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ContextMismatch,
            ));
        }
        Ok(())
    }

    fn validate_owner(&self, owner: &EntryOwner) -> Result<&OwnerState, ReservationError> {
        self.validate_binding(&owner.binding)?;
        self.ledger
            .owners
            .get(&owner.binding.id)
            .filter(|state| state.generation == owner.binding.generation)
            .ok_or(ReservationError::Invariant(
                ReservationInvariant::StaleOwner,
            ))
    }

    fn validate_slot(
        &self,
        owner: &EntryOwner,
        slot: &OccurrenceSlot,
    ) -> Result<&OwnerState, ReservationError> {
        let state = self.validate_owner(owner)?;
        self.validate_binding(&slot.owner)?;
        if slot.owner.id != owner.binding.id || slot.owner.generation != owner.binding.generation {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ForeignSlotOwner,
            ));
        }
        if state.slots.get(&slot.id).map(|live| live.generation) != Some(slot.generation) {
            return Err(ReservationError::Invariant(ReservationInvariant::StaleSlot));
        }
        Ok(state)
    }

    fn proposed_block(
        &self,
        old: Option<SourceUsage>,
        new: SourceUsage,
    ) -> Result<SourceUsage, ReservationError> {
        let old_max = old.map(|usage| usage.max_statement_bytes);
        check_maximum_change(&self.ledger.maxima, old_max, Some(new.max_statement_bytes))?;
        let others = self.ledger.usage.replaced(
            old.unwrap_or(SourceUsage::ZERO),
            SourceUsage::ZERO,
            maximum_after(&self.ledger.maxima, old_max, None),
        )?;
        let block = others.replaced(
            SourceUsage::ZERO,
            new,
            others.max_statement_bytes.max(new.max_statement_bytes),
        )?;
        check_budget(new, others, block, self.ledger.policy)?;
        Ok(block)
    }

    /// Reserve E=1 for one logical entry, including entries without occurrences.
    /// Only the State owner decides when to mint and retain this capability.
    pub(crate) fn open_owner(&mut self) -> Result<EntryOwner, ReservationError> {
        let usage = SourceUsage {
            executed_entries: 1,
            ..SourceUsage::ZERO
        };
        let block = self.proposed_block(None, usage)?;
        let generation = self.ledger.take_generation()?;
        self.journal.push(Undo::Owner {
            id: generation,
            block_before: self.ledger.usage,
        });
        self.ledger.owners.insert(
            generation,
            OwnerState {
                generation,
                next_slot: 0,
                slots: BTreeMap::new(),
                maxima: BTreeMap::new(),
                usage,
            },
        );
        change_maximum(&mut self.ledger.maxima, None, Some(0));
        self.ledger.usage = block;
        Ok(EntryOwner {
            binding: OwnerBinding {
                ledger: Arc::clone(&self.ledger.identity),
                context: self.ledger.context,
                id: generation,
                generation,
            },
        })
    }

    /// Reserve one measured statement contribution under an existing logical entry.
    /// The complete-entry adapter may supply an empty contribution retaining E only.
    pub(crate) fn reserve(
        &mut self,
        owner: &EntryOwner,
        usage: OccurrenceUsage,
    ) -> Result<OccurrenceSlot, ReservationError> {
        let state = self.validate_owner(owner)?;
        let id = state.next_slot;
        id.checked_add(1).ok_or(ReservationError::Invariant(
            ReservationInvariant::GenerationOverflow,
        ))?;
        self.update_slot(owner, id, None, usage)
    }

    /// Replace the complete contribution atomically; T is measured and M can decrease.
    /// The old handle becomes stale only after a successful replacement.
    pub(crate) fn replace(
        &mut self,
        owner: &EntryOwner,
        slot: &OccurrenceSlot,
        usage: OccurrenceUsage,
    ) -> Result<OccurrenceSlot, ReservationError> {
        let state = self.validate_slot(owner, slot)?;
        let previous = *state.slots.get(&slot.id).expect("validated slot");
        self.update_slot(owner, slot.id, Some(previous), usage)
    }

    fn update_slot(
        &mut self,
        owner: &EntryOwner,
        id: u64,
        previous: Option<SlotState>,
        usage: OccurrenceUsage,
    ) -> Result<OccurrenceSlot, ReservationError> {
        let state = self.validate_owner(owner)?;
        let old_max = previous.map(|slot| slot.usage.statement_bytes);
        check_maximum_change(&state.maxima, old_max, Some(usage.statement_bytes))?;
        let prospective = state.usage.replaced(
            previous.map_or(SourceUsage::ZERO, |slot| slot.usage.usage()),
            usage.usage(),
            maximum_after(&state.maxima, old_max, Some(usage.statement_bytes)),
        )?;
        let block = self.proposed_block(Some(state.usage), prospective)?;
        let owner_before = state.usage;
        let next_slot_before = state.next_slot;
        let generation = self.ledger.take_generation()?;
        self.journal.push(Undo::Slot {
            #[cfg(test)]
            generation,
            owner: owner.binding.id,
            id,
            previous,
            next_slot_before,
            owner_before,
            block_before: self.ledger.usage,
        });
        let state = self
            .ledger
            .owners
            .get_mut(&owner.binding.id)
            .expect("validated owner");
        state.slots.insert(id, SlotState { generation, usage });
        if previous.is_none() {
            state.next_slot += 1; // reserve checked this before any mutation.
        }
        change_maximum(&mut state.maxima, old_max, Some(usage.statement_bytes));
        state.usage = prospective;
        change_maximum(
            &mut self.ledger.maxima,
            Some(owner_before.max_statement_bytes),
            Some(prospective.max_statement_bytes),
        );
        self.ledger.usage = block;
        Ok(OccurrenceSlot {
            owner: owner.binding.clone(),
            id,
            generation,
        })
    }

    /// Exact complete owner usage across committed and currently staged fragments.
    pub(crate) fn owner_usage(&self, owner: &EntryOwner) -> Result<SourceUsage, ReservationError> {
        Ok(self.validate_owner(owner)?.usage)
    }

    /// Exact block usage visible inside this physical scope.
    pub(crate) fn usage(&self) -> SourceUsage {
        self.ledger.usage
    }

    #[cfg(test)]
    /// Save an undo offset; the corresponding WSV checkpoint remains adapter-owned.
    pub(crate) fn checkpoint(&self) -> ReservationCheckpoint {
        ReservationCheckpoint {
            identity: Arc::clone(&self.ledger.identity),
            context: self.ledger.context,
            transaction: self.generation,
            boundary_generation: self
                .journal
                .last()
                .map_or(self.generation, Undo::generation),
            journal_len: self.journal.len(),
        }
    }

    #[cfg(test)]
    /// Restore a retained checkpoint, preserving ancestors and invalidating discarded branches.
    /// Old live slots revive; undo needs no new generation and works even at exhaustion.
    pub(crate) fn rollback(
        &mut self,
        checkpoint: ReservationCheckpoint,
    ) -> Result<SourceUsage, ReservationError> {
        if !Arc::ptr_eq(&checkpoint.identity, &self.ledger.identity) {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ForeignLedger,
            ));
        }
        if checkpoint.context != self.ledger.context {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ContextMismatch,
            ));
        }
        if checkpoint.transaction != self.generation {
            return Err(ReservationError::Invariant(
                ReservationInvariant::ForeignTransaction,
            ));
        }
        let boundary = if checkpoint.journal_len == 0 {
            Some(self.generation)
        } else {
            self.journal
                .get(checkpoint.journal_len - 1)
                .map(Undo::generation)
        };
        if boundary != Some(checkpoint.boundary_generation) {
            return Err(ReservationError::Invariant(
                ReservationInvariant::StaleCheckpoint,
            ));
        }
        self.rollback_to(checkpoint.journal_len);
        Ok(self.ledger.usage)
    }

    fn rollback_to(&mut self, offset: usize) {
        while self.journal.len() > offset {
            match self.journal.pop().expect("journal suffix") {
                Undo::Owner { id, block_before } => {
                    let owner = self.ledger.owners.remove(&id).expect("journal-owned entry");
                    debug_assert!(owner.slots.is_empty());
                    change_maximum(
                        &mut self.ledger.maxima,
                        Some(owner.usage.max_statement_bytes),
                        None,
                    );
                    self.ledger.usage = block_before;
                }
                Undo::Slot {
                    #[cfg(test)]
                        generation: _,
                    owner,
                    id,
                    previous,
                    next_slot_before,
                    owner_before,
                    block_before,
                } => {
                    let state = self
                        .ledger
                        .owners
                        .get_mut(&owner)
                        .expect("journal-owned entry");
                    let current = state.slots.remove(&id).expect("journal-owned slot");
                    if let Some(previous) = previous {
                        state.slots.insert(id, previous);
                    }
                    change_maximum(
                        &mut state.maxima,
                        Some(current.usage.statement_bytes),
                        previous.map(|slot| slot.usage.statement_bytes),
                    );
                    change_maximum(
                        &mut self.ledger.maxima,
                        Some(state.usage.max_statement_bytes),
                        Some(owner_before.max_statement_bytes),
                    );
                    state.next_slot = next_slot_before;
                    state.usage = owner_before;
                    self.ledger.usage = block_before;
                }
            }
        }
    }

    /// Retain all changes; State must commit the matching WSV/transcript fragment too.
    pub(crate) fn commit(mut self) -> SourceUsage {
        if !self.journal.is_empty() {
            // This original token was allocated with checked_add before the scope
            // opened. It never wraps, and rollback never restores its allocator.
            // Equal final usage cannot conceal an applied replacement. Empty and
            // fully rolled-back scopes retain the previous publication identity.
            self.ledger.applied_generation = self.generation;
        }
        self.committed = true;
        self.ledger.usage
    }
}

impl Drop for ReservationTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback_to(0);
        }
    }
}

#[cfg(test)]
#[path = "source_reservation/tests.rs"]
mod tests;

/// Exact complete-entry reservation adapter; occurrence accounting stays internal.
pub(crate) mod entry_bundle;

/// Frozen ordinary/mandatory source admission and physical transaction scopes.
pub(crate) mod admission;
