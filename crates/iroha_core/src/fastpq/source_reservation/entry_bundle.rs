//! Logical-entry reservations over complete ordered transcript bundles.
//!
//! Every entry hash owns E=1 across physical execution and fee fragments. Its
//! transcript counts and sole public statement are replaced from the complete
//! bundle framing, never summed from independently prepared occurrences.
//! Framing does not validate transfer arithmetic or inter-occurrence chronology;
//! those belong to the execution/proof relation, independently of resource usage.
//! State owns authenticated entry creation, WSV/source publication and matching
//! rollback. This framing adapter does not grant finality or execution authority.

use iroha_crypto::Hash;
use iroha_data_model::fastpq::TransferTranscript;

#[cfg(test)]
use super::ReservationCheckpoint;
use super::{
    BTreeMap, EntryOwner, OccurrenceSlot, OccurrenceUsage, ReservationContext, ReservationError,
    ReservationInvariant, ReservationLedger, ReservationPolicy, ReservationTransaction,
    SourceDimension, SourceUsage,
};
use crate::fastpq::source_capture::{
    FastpqSourceStatementBuildLimits, FastpqSourceTranscriptUsage,
};

use crate::fastpq::source_prefix_lengths::entry::measure_fastpq_source_entry_frame_usage;

/// Failure before complete-entry replacement; every variant leaves usage intact.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EntryBundleReservationError {
    /// Canonical framing, input shape, or its explicit local bound failed.
    /// This must not be interpreted as ordinary transaction rejection or deferral.
    Preparation(String),
    /// An explicit framing capacity was exceeded; the authenticated caller selects its meaning.
    Capacity(String),
    /// The complete measured entry violates capacity or capability invariants.
    Reservation(ReservationError),
}

impl From<ReservationError> for EntryBundleReservationError {
    fn from(error: ReservationError) -> Self {
        Self::Reservation(error)
    }
}

impl std::fmt::Display for EntryBundleReservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparation(error) => {
                write!(formatter, "FASTPQ complete-entry preparation: {error}")
            }
            Self::Capacity(error) => {
                write!(formatter, "FASTPQ complete-entry framing capacity: {error}")
            }
            Self::Reservation(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for EntryBundleReservationError {}

/// Opaque capability binding one logical execution identity to this block ledger.
#[derive(Clone, Debug)]
pub(crate) struct EntryBundleOwner {
    entry_hash: Hash,
    inner: EntryOwner,
}

/// Block accounting with one public-statement contribution per logical entry.
/// Explicit construction bounds limit preparation and do not select runtime policy.
pub(crate) struct EntryBundleReservationLedger {
    inner: ReservationLedger,
    entries: BTreeMap<Hash, EntryOwner>,
    construction_limits: FastpqSourceStatementBuildLimits,
}

impl EntryBundleReservationLedger {
    /// Create an empty ledger under explicit frozen context, ceilings and scratch bounds.
    pub(crate) fn new(
        context: ReservationContext,
        policy: ReservationPolicy,
        construction_limits: FastpqSourceStatementBuildLimits,
    ) -> Result<Self, ReservationError> {
        Ok(Self {
            inner: ReservationLedger::new(context, policy)?,
            entries: BTreeMap::new(),
            construction_limits,
        })
    }

    /// Start a physical scope; dropping it restores accounting and identity bindings.
    pub(crate) fn transaction(
        &mut self,
        context: ReservationContext,
    ) -> Result<EntryBundleReservationTransaction<'_>, ReservationError> {
        Ok(EntryBundleReservationTransaction {
            inner: self.inner.transaction(context)?,
            bindings: PendingBindings {
                entries: &mut self.entries,
                created: Vec::new(),
                committed: false,
            },
            construction_limits: self.construction_limits,
        })
    }

    /// Identities already owned by this pool, in canonical hash order.
    pub(crate) fn entry_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
        self.entries.keys().copied()
    }

    /// Preserve the original quota journal allocation and applied lineage.
    pub(super) fn retain_commit_seal(&self) -> super::ReservationCommitSeal {
        self.inner.retain_commit_seal()
    }

    /// Public entry/counter reconstruction never replaces original journal custody.
    pub(super) fn matches_commit_seal(&self, seal: &super::ReservationCommitSeal) -> bool {
        self.inner.matches_commit_seal(seal)
    }

    /// Exact committed E/T/D/I/M/S usage.
    pub(crate) fn usage(&self) -> SourceUsage {
        self.inner.usage()
    }
}

struct PendingBindings<'a> {
    entries: &'a mut BTreeMap<Hash, EntryOwner>,
    created: Vec<Hash>,
    committed: bool,
}

impl PendingBindings<'_> {
    fn rollback_to(&mut self, offset: usize) {
        while self.created.len() > offset {
            if let Some(hash) = self.created.pop() {
                self.entries.remove(&hash);
            }
        }
    }
}

impl Drop for PendingBindings<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback_to(0);
        }
    }
}

/// Exclusive physical fragment using the journaled reservation ledger.
pub(crate) struct EntryBundleReservationTransaction<'a> {
    inner: ReservationTransaction<'a>,
    bindings: PendingBindings<'a>,
    construction_limits: FastpqSourceStatementBuildLimits,
}

#[cfg(test)]
/// Journal checkpoint covering both usage and newly owned entry identities.
pub(crate) struct EntryBundleReservationCheckpoint {
    inner: ReservationCheckpoint,
    created_entries: usize,
}

fn occurrence_usage(
    measured: FastpqSourceTranscriptUsage,
) -> Result<OccurrenceUsage, ReservationError> {
    let empty = measured.transcripts == 0;
    if measured.max_statement_bytes != measured.total_statement_bytes
        || (empty
            && (measured.deltas != 0
                || measured.input_transcript_bytes != 0
                || measured.total_statement_bytes != 0))
        || (!empty
            && (measured.deltas < measured.transcripts
                || measured.input_transcript_bytes == 0
                || measured.total_statement_bytes == 0))
    {
        return Err(ReservationError::Invariant(
            ReservationInvariant::InvalidEntryBundleMeasurement,
        ));
    }
    let checked = |count: usize, dimension| {
        u64::try_from(count).map_err(|_| {
            ReservationError::Invariant(ReservationInvariant::UsageOverflow { dimension })
        })
    };
    Ok(OccurrenceUsage {
        transcripts: checked(measured.transcripts, SourceDimension::Transcripts)?,
        deltas: checked(measured.deltas, SourceDimension::Deltas)?,
        input_bytes: checked(
            measured.input_transcript_bytes,
            SourceDimension::InputTranscriptBytes,
        )?,
        statement_bytes: checked(
            measured.total_statement_bytes,
            SourceDimension::TotalStatementBytes,
        )?,
    })
}

impl EntryBundleReservationTransaction<'_> {
    /// Retain the existing ledger allocation and this exact checked physical generation.
    pub(crate) fn retain_identity(&self) -> super::SourceTransactionIdentity {
        self.inner.retain_identity()
    }
    /// Require the exact original journal allocation, context and checked generation.
    pub(crate) fn matches_identity(&self, identity: &super::SourceTransactionIdentity) -> bool {
        self.inner.matches_identity(identity)
    }
    /// Only identities first staged by this original physical journal, never older siblings.
    pub(crate) fn has_staged_entry(&self, hash: Hash) -> bool {
        self.bindings.created.contains(&hash)
    }

    /// Retain E=1 for this identity, including transcript-free/rejected entries.
    /// Reopening it in a fee or later physical fragment reuses the same owner.
    /// State must choose the identity from its owned complete execution archive.
    pub(crate) fn open_entry(
        &mut self,
        entry_hash: Hash,
    ) -> Result<EntryBundleOwner, ReservationError> {
        let inner = if let Some(owner) = self.bindings.entries.get(&entry_hash) {
            self.inner.validate_owner(owner)?;
            owner.clone()
        } else {
            let owner = self.inner.open_owner()?;
            self.bindings.entries.insert(entry_hash, owner.clone());
            self.bindings.created.push(entry_hash);
            owner
        };
        Ok(EntryBundleOwner { entry_hash, inner })
    }

    /// Look up an already-retained invocation without minting execution authority.
    pub(crate) fn existing_entry(
        &self,
        entry_hash: Hash,
    ) -> Result<Option<EntryBundleOwner>, ReservationError> {
        let Some(inner) = self.bindings.entries.get(&entry_hash) else {
            return Ok(None);
        };
        self.inner.validate_owner(inner)?;
        Ok(Some(EntryBundleOwner {
            entry_hash,
            inner: inner.clone(),
        }))
    }

    /// Atomically replace T/D/I and M=S from the complete entry bundle framing.
    ///
    /// Empty input clears its source contribution while retaining E=1. This measures
    /// every original occurrence together, including repeated keys and original quantities.
    /// This checks framing and entry identity, not arithmetic, digest values or chronology.
    /// The caller must publish this exact bundle and matching WSV changes atomically.
    /// Borrowed committed, pending and candidate slices may be chained without copying.
    /// No input is mutated, no private tree is built, and failure changes no accounting.
    pub(crate) fn replace_bundle<'a, I>(
        &mut self,
        owner: &EntryBundleOwner,
        bundle: I,
    ) -> Result<SourceUsage, EntryBundleReservationError>
    where
        I: IntoIterator<Item = &'a TransferTranscript>,
    {
        self.inner.validate_owner(&owner.inner)?;
        let measured = measure_fastpq_source_entry_frame_usage(
            owner.entry_hash,
            bundle,
            self.construction_limits,
        )
        .map_err(|error| {
            use crate::fastpq::source_prefix_lengths::{
                PrefixLengthError, entry::EntryFrameLengthError,
            };
            match &error {
                EntryFrameLengthError::Bound(_)
                | EntryFrameLengthError::Prefix(
                    PrefixLengthError::Deltas { .. }
                    | PrefixLengthError::Input { .. }
                    | PrefixLengthError::Public { .. },
                ) => EntryBundleReservationError::Capacity(error.to_string()),
                _ => EntryBundleReservationError::Preparation(error.to_string()),
            }
        })?;
        let usage = occurrence_usage(measured)?;
        let state = self.inner.validate_owner(&owner.inner)?;
        // Only this wrapper can mint its owners. It keeps one replaceable slot;
        // slots and the raw occurrence API are never exposed by the wrapper.
        if let Some((&id, slot)) = state.slots.first_key_value() {
            let previous = OccurrenceSlot {
                owner: owner.inner.binding.clone(),
                id,
                generation: slot.generation,
            };
            self.inner.replace(&owner.inner, &previous, usage)?;
        } else {
            self.inner.reserve(&owner.inner, usage)?;
        }
        self.inner.owner_usage(&owner.inner).map_err(Into::into)
    }

    /// Validate an already retained entry against this exact original binding and
    /// generation. Equal public hashes in a foreign journal never substitute.
    pub(crate) fn matches_existing_entry(&self, hash: Hash, owner: &EntryBundleOwner) -> bool {
        let Some(actual) = self.bindings.entries.get(&hash) else {
            return false;
        };
        owner.entry_hash == hash
            && std::sync::Arc::ptr_eq(&actual.binding.ledger, &owner.inner.binding.ledger)
            && actual.binding.context == owner.inner.binding.context
            && actual.binding.id == owner.inner.binding.id
            && actual.binding.generation == owner.inner.binding.generation
            && self.inner.validate_owner(&owner.inner).is_ok()
    }

    /// Exact usage for the complete logical entry across committed/staged fragments.
    pub(crate) fn owner_usage(
        &self,
        owner: &EntryBundleOwner,
    ) -> Result<SourceUsage, ReservationError> {
        self.inner.owner_usage(&owner.inner)
    }

    /// Exact block usage including this physical fragment's pending replacements.
    pub(crate) fn usage(&self) -> SourceUsage {
        self.inner.usage()
    }

    #[cfg(test)]
    /// Save an ancestor-safe accounting and identity-binding boundary.
    pub(crate) fn checkpoint(&self) -> EntryBundleReservationCheckpoint {
        EntryBundleReservationCheckpoint {
            inner: self.inner.checkpoint(),
            created_entries: self.bindings.created.len(),
        }
    }

    #[cfg(test)]
    /// Undo a retained boundary; invalid checkpoints leave both ledgers intact.
    pub(crate) fn rollback(
        &mut self,
        checkpoint: EntryBundleReservationCheckpoint,
    ) -> Result<SourceUsage, ReservationError> {
        let usage = self.inner.rollback(checkpoint.inner)?;
        self.bindings.rollback_to(checkpoint.created_entries);
        Ok(usage)
    }

    /// Retain usage and entry bindings with the matching State/source commit.
    pub(crate) fn commit(mut self) -> SourceUsage {
        self.bindings.committed = true;
        self.inner.commit()
    }
}

#[cfg(test)]
mod tests;
