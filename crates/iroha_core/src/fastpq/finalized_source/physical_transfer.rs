//! Borrowed native/D7 physical transfers without a WG receipt or remote spend authority.
//!
//! The private `FinalizedFastpqSource` constructor already joined the immutable
//! original execution witness, D7 source and authenticated native result. Selection
//! below borrows those originals; it does not repeat whole-witness hashing, decode
//! another owner, materialize the optional quantity archive or accept a supplied root.
//! TODO(P.1): integrate an actual consumer and join a State-owned per-entry keyed
//! WG receipt core before constructing an AXT success receipt. No root exposed here is a complete post-transaction State root.

use super::FinalizedFastpqSource;
use iroha_crypto::Hash;
use iroha_data_model::{
    block::execution_output::NetworkExecutionOutputV1,
    fastpq::{
        FastpqOrdinarySourceStatementLeafV1, FastpqSourceEffectCoverageV1,
        FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1, TransferDeltaTranscript,
        TransferTranscript,
    },
    transaction::signed::TransactionEntrypoint,
};

/// Caller-selected physical occurrence, with no unverified receipt or remote claim digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalTransferLocation {
    /// Expected exact execution-call identity, not the outer sealed-reveal identity.
    pub(crate) source_call: Hash,
    /// Position in the authenticated Network inputs, not a generic output position.
    pub(crate) network_index: u32,
    /// Position in the full execution-owned source projection, independent of D7 leaves.
    pub(crate) entry_index: u32,
    /// Position among the original nonempty D7 statements.
    pub(crate) statement_index: u32,
    /// Position in this source call's ordered transfer transcript bundle.
    pub(crate) transcript_index: u32,
    /// Position in the selected transcript's ordered transfer deltas.
    pub(crate) delta_index: u32,
    /// Position across every delta in this call's ordered transcript bundle.
    pub(crate) pair_ordinal: u32,
}

/// Finite local scan limits for one selection, not consensus or proof admission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalTransferScan {
    /// Bound on the complete source inventory scanned for unique call identity.
    pub(crate) max_source_entries: u32,
    /// Bound on the selected call's transcript count, checked before traversal.
    pub(crate) max_transcripts: u32,
    /// Bound on its cumulative delta count, checked by lengths without visiting deltas.
    pub(crate) max_deltas: u32,
}

/// Exact scan whose caller allowance was insufficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalTransferWork {
    /// Complete original source entries, including rejected and internal entries.
    SourceEntries,
    /// Selected source's transfer transcripts.
    Transcripts,
    /// Selected source's cumulative transfer deltas.
    Deltas,
}

/// Original local work refusal; the borrowed owner and all backing remain unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalTransferRefusal {
    /// Work dimension that exceeded its finite caller allowance.
    pub(crate) work: PhysicalTransferWork,
    /// Caller allowance used by this attempt.
    pub(crate) limit: u32,
    /// Exact observed count, or the first cumulative count crossing the allowance.
    pub(crate) observed: usize,
}

/// Completed source/location disagreement, separate from local work refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalTransferMismatch {
    /// The selected source is not an actual Network input/output join.
    NonNetworkSource,
    /// Selected call identity differs from its original execution-owned entry.
    SourceCall,
    /// More than one original execution entry has the selected call identity.
    DuplicateSourceCall,
    /// The actual authenticated Network output was rejected.
    RejectedExecution,
    /// No complete nonempty original quantity statement matches this Network entry.
    Statement,
    /// Original quantity capture reported an unowned mutation.
    IncompleteQuantityCoverage,
    /// The selected original source has no transfer transcripts.
    MissingTranscripts,
    /// Original transcript identity or nonempty shape is inconsistent.
    Transcript,
    /// Transcript, delta and flattened pair positions do not name the same occurrence.
    Coordinate,
}

/// Selection never turns a finite serving limit into invalid execution or source finality.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PhysicalTransferError {
    /// The exact local scan allowance was insufficient; retry keeps the same source.
    #[error("finalized physical transfer work refused: {0:?}")]
    Refused(PhysicalTransferRefusal),
    /// Actual cumulative work cannot be represented without overflow.
    #[error("finalized physical transfer work count overflow: {0:?}")]
    WorkOverflow(PhysicalTransferWork),
    /// The requested physical source or occurrence does not satisfy the contract.
    #[error("finalized physical transfer rejected: {0:?}")]
    Rejected(PhysicalTransferMismatch),
}

/// One physical transfer observation from a successful original Network call.
///
/// The D7 leaf names that call's complete effect tape. This observation does not
/// prove that the selected delta is a particular complete-effect member.
///
/// No Clone, wire decoder or independent constructor exists. This borrow keeps the
/// original source, native body, D7 backing and funding alive together. The quantity
/// digest covers Transfer/Mint/Burn/Retire with source/lifecycle/authorization facts;
/// it does not claim all non-quantity State mutations, a proof or a WG State root.
/// A caller still needs actual per-entry WG receipt authority and current issuer checks
/// before any remote-spend admission. This value performs no reservation or mutation.
pub(crate) struct PhysicalTransfer<'a> {
    original: &'a FinalizedFastpqSource,
    location: PhysicalTransferLocation,
    input: &'a TransactionEntrypoint,
    entry: &'a FastpqSourceExecutionEntryV1,
    leaf: &'a FastpqOrdinarySourceStatementLeafV1,
    output: &'a NetworkExecutionOutputV1,
    transcript: &'a TransferTranscript,
    delta: &'a TransferDeltaTranscript,
}

impl PhysicalTransfer<'_> {
    /// Same immutable authenticated source owner; no decoded authority is reconstructed.
    pub(crate) fn original(&self) -> &FinalizedFastpqSource {
        self.original
    }
    /// Exact positions checked against the original Network entry and transcript bundle.
    pub(crate) fn location(&self) -> PhysicalTransferLocation {
        self.location
    }
    /// Original source inventory entry joined to this actual Network output.
    pub(crate) fn source_entry(&self) -> &FastpqSourceExecutionEntryV1 {
        self.entry
    }
    /// Original complete quantity leaf, including source route, dataspace and wire-set digest.
    pub(crate) fn statement(&self) -> &FastpqOrdinarySourceStatementLeafV1 {
        self.leaf
    }
    /// Actual original Network input; sealed identity is never replaced by an outer hash.
    pub(crate) fn input(&self) -> &TransactionEntrypoint {
        self.input
    }
    /// Actual successful Network output from the same authenticated original body.
    pub(crate) fn output(&self) -> &NetworkExecutionOutputV1 {
        self.output
    }
    /// Original selected transcript; private path material is borrowed, never copied.
    pub(crate) fn transcript(&self) -> &TransferTranscript {
        self.transcript
    }
    /// Original physical delta at all three checked occurrence locations.
    pub(crate) fn delta(&self) -> &TransferDeltaTranscript {
        self.delta
    }
}

fn reject(error: PhysicalTransferMismatch) -> PhysicalTransferError {
    PhysicalTransferError::Rejected(error)
}

fn bounded(
    work: PhysicalTransferWork,
    observed: usize,
    limit: u32,
) -> Result<(), PhysicalTransferError> {
    if observed > limit as usize {
        return Err(PhysicalTransferError::Refused(PhysicalTransferRefusal {
            work,
            limit,
            observed,
        }));
    }
    Ok(())
}

impl FinalizedFastpqSource {
    /// Resolve one exact successful Network transfer without manufacturing receipt authority.
    ///
    /// `bind` already authenticated this immutable original graph. The original producer
    /// derives the Network prefix from actual execution-call identities and checks it
    /// against the applied output owner; the native join authenticates that exact body.
    /// Reuse those fixed identities instead of re-encoding transaction bodies or hashing
    /// a caller-supplied archive. Only fixed-size inventory rows and transcript lengths
    /// are scanned here; no allocation, codec or optional archive admission is attempted.
    /// The entry allowance also bounds the authenticated transcript-map cardinality;
    /// each applied transcript key has an original entry. Constructor authentication
    /// is deliberately not repeated under this per-request work allowance.
    ///
    /// # Errors
    /// Returns the exact local work refusal or a completed selection disagreement. Neither
    /// consumes, rebinds or mutates the source. D7 presence alone cannot prove success:
    /// rejected calls can retain independently applied fee or penalty quantity effects.
    pub(crate) fn physical_transfer(
        &self,
        location: PhysicalTransferLocation,
        limits: PhysicalTransferScan,
    ) -> Result<PhysicalTransfer<'_>, PhysicalTransferError> {
        use PhysicalTransferMismatch as Rejection;
        use PhysicalTransferWork as Work;
        bounded(
            Work::SourceEntries,
            self.entries().len(),
            limits.max_source_entries,
        )?;
        let block = self.native().block();
        let index = location.network_index as usize;
        // An internal source can have ExecutionCall kind too. Only this actual
        // Network prefix and the typed Network output join establish its namespace.
        if index >= block.network_entrypoint_count() {
            return Err(reject(Rejection::NonNetworkSource));
        }
        let input = block
            .network_entrypoint_at(index)
            .ok_or_else(|| reject(Rejection::NonNetworkSource))?;
        let (output_index, output) = block
            .network_output_at(location.network_index)
            .ok_or_else(|| reject(Rejection::NonNetworkSource))?;
        // The constructor-authenticated producer retains one source record per
        // actual output, with the Network prefix in input order. Validate this
        // explicit join; a statement position or pair ordinal cannot supply it.
        if location.entry_index != output_index {
            return Err(reject(Rejection::SourceCall));
        }
        let entry = self
            .entries()
            .get(location.entry_index as usize)
            .ok_or_else(|| reject(Rejection::SourceCall))?;
        if entry.execution_kind != FastpqSourceExecutionKindV1::ExecutionCall
            || entry.entry_hash != location.source_call
        {
            return Err(reject(Rejection::SourceCall));
        }
        if self
            .entries()
            .iter()
            .filter(|entry| entry.entry_hash == location.source_call)
            .take(2)
            .count()
            != 1
        {
            return Err(reject(Rejection::DuplicateSourceCall));
        }
        if !output.result.is_ok() {
            return Err(reject(Rejection::RejectedExecution));
        }
        if self.manifest().coverage != FastpqSourceEffectCoverageV1::Complete {
            return Err(reject(Rejection::IncompleteQuantityCoverage));
        }
        let leaf = self
            .leaves()
            .get(location.statement_index as usize)
            .ok_or_else(|| reject(Rejection::Statement))?;
        if leaf.statement_index != location.statement_index
            || leaf.entry_index != location.entry_index
            || leaf.effect_count == 0
            || leaf.source != self.manifest().source
            || leaf.entry_hash != entry.entry_hash
            || leaf.execution_kind != entry.execution_kind
            || leaf.route != entry.route
            || leaf.dataspace_id != entry.dataspace_id
        {
            return Err(reject(Rejection::Statement));
        }
        let transcripts = block
            .fastpq_transcripts()
            .get(&location.source_call)
            .ok_or_else(|| reject(Rejection::MissingTranscripts))?;
        bounded(Work::Transcripts, transcripts.len(), limits.max_transcripts)?;
        let mut count = 0usize;
        let mut selected = None;
        for (index, transcript) in transcripts.iter().enumerate() {
            if transcript.batch_hash != location.source_call || transcript.deltas.is_empty() {
                return Err(reject(Rejection::Transcript));
            }
            // `count <= u32::MAX` after each pass; adding an actual slice length
            // uses checked arithmetic and an overflow is necessarily above this limit.
            let observed = count
                .checked_add(transcript.deltas.len())
                .ok_or(PhysicalTransferError::WorkOverflow(Work::Deltas))?;
            bounded(Work::Deltas, observed, limits.max_deltas)?;
            if index == location.transcript_index as usize {
                let delta = transcript
                    .deltas
                    .get(location.delta_index as usize)
                    .ok_or_else(|| reject(Rejection::Coordinate))?;
                if count + location.delta_index as usize != location.pair_ordinal as usize {
                    return Err(reject(Rejection::Coordinate));
                }
                selected = Some((transcript, delta));
            }
            count = observed;
        }
        let (transcript, delta) = selected.ok_or_else(|| reject(Rejection::Coordinate))?;
        Ok(PhysicalTransfer {
            original: self,
            location,
            input,
            entry,
            leaf,
            output,
            transcript,
            delta,
        })
    }
}

#[cfg(test)]
mod tests;
