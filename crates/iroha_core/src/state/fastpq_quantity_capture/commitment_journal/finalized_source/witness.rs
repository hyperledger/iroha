//! Original D7 witness allocation custody through native result and job ownership.
//!
//! Only the actual completed State source can construct this local owner. The
//! canonical wire remains `ExecWitness`; borrowing it grants no source finality.

use super::*;
use crate::state::fastpq_quantity_archive::FrozenQuantityArchive;
use iroha_allocation::{AllocationCharge, RetainedPayload};
use iroha_data_model::{
    block::consensus::{ExecKv, ExecWitness},
    execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1 as KEY,
};
use std::mem::ManuallyDrop;

/// One original captured canonical witness with inseparable new allocation custody.
///
/// The retained ledger covers the exact new write-vector backing and D7 key/value
/// allocations. Existing moved read/transcript/nested ordinary-write allocations
/// retain their original ownership; this does not claim they were newly admitted.
/// No raw extraction, Clone or mutable original-wire projection exists.
pub(crate) struct CapturedExecWitness {
    wire: RetainedPayload<ExecWitness>,
    source: ChargedShared<FinalizedQuantitySource>,
    /// Fixed identity calculated from this exact original during native R preparation.
    /// No public setter or caller-supplied root is accepted.
    native: Option<(
        iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
        iroha_data_model::sumeragi_finality::ExecutionCommitment,
    )>,
    archive:
        Result<ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>, QuantityCaptureIssue>,
    // Explicit tests may offer reconstructed tampered bytes to the unchanged
    // production checks. They never obtain a mutable funded original allocation.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    offered_wire_for_test: Option<ExecWitness>,
}

impl std::fmt::Debug for CapturedExecWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapturedExecWitness")
            .field("wire", self.wire())
            .field("source", &self.source.manifest)
            .field("original_tape_available", &self.archive.is_ok())
            .finish()
    }
}
impl std::ops::Deref for CapturedExecWitness {
    type Target = ExecWitness;
    fn deref(&self) -> &Self::Target {
        self.wire()
    }
}

/// Borrowed exact original entry; no caller-supplied leaf, digest or pool is admitted.
pub(crate) struct CapturedQuantityEntry<'a> {
    effects: &'a FastpqExecutionEffectsV1,
    leaf: &'a FastpqOrdinarySourceStatementLeafV1,
    pool: &'a AllocationBudget,
}
impl<'a> CapturedQuantityEntry<'a> {
    pub(crate) fn effects(&self) -> &'a FastpqExecutionEffectsV1 {
        self.effects
    }
    pub(crate) fn leaf(&self) -> &'a FastpqOrdinarySourceStatementLeafV1 {
        self.leaf
    }
    pub(crate) fn pool(&self) -> &'a AllocationBudget {
        self.pool
    }
}

impl CapturedExecWitness {
    /// Read the exact canonical original; explicitly offered test wire is separate.
    pub(crate) fn wire(&self) -> &ExecWitness {
        #[cfg(any(test, feature = "iroha-core-tests"))]
        if let Some(offered) = self.offered_wire_for_test.as_ref() {
            return offered;
        }
        self.wire.get()
    }

    /// Original finite execution pool; this creates no capacity or work reservation.
    pub(crate) fn pool(&self) -> &AllocationBudget {
        &self.source.pool
    }
    pub(crate) fn manifest(&self) -> &FastpqOrdinarySourceStatementManifestV1 {
        &self.source.manifest
    }
    pub(crate) fn source_entries(&self) -> &[FastpqSourceExecutionEntryV1] {
        self.source.inventory.entries()
    }
    pub(crate) fn leaves(&self) -> &[FastpqOrdinarySourceStatementLeafV1] {
        self.source.leaves.as_slice()
    }

    /// Compare canonical offered bytes with the exact retained source, without finality claims.
    pub(crate) fn verify_source_binding(&self) -> Result<(), String> {
        #[cfg(test)]
        work_counts::wire();
        if !self.wire.belongs_to(&self.source.pool)
            || !self.source.belongs_to(&self.source.pool)
            || self
                .wire()
                .writes
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || !self.wire().fastpq_batches.is_empty()
        {
            return Err(
                "captured ordinary witness lost original custody or canonical ordering".into(),
            );
        }
        self.source
            .inventory
            .verify_ordinary_witness_bundles(&self.wire().fastpq_transcripts)?;
        let mut family = self
            .wire()
            .writes
            .iter()
            .filter(|write| write.key.first() == KEY.first());
        let Some(write) = family.next() else {
            return Err("captured witness omitted original D7 write".into());
        };
        if family.next().is_some()
            || write.key.as_slice() != KEY
            || write.value.as_slice() != self.source.manifest_bytes.as_slice()
        {
            return Err(
                "captured witness D7 bytes differ from the original completed source".into(),
            );
        }
        Ok(())
    }

    /// Standalone checked selection; production jobs use one admitted immutable archive.
    pub(crate) fn quantity_entry(
        &self,
        statement_index: usize,
    ) -> Result<CapturedQuantityEntry<'_>, QuantityCaptureIssue> {
        self.verify_source_binding()
            .map_err(|_| QuantityCaptureIssue::InvalidFacts)?;
        if self.source.manifest.coverage != FastpqSourceEffectCoverageV1::Complete {
            return Err(QuantityCaptureIssue::UnownedMutation);
        }
        let archive = self.archive.as_ref().map_err(|error| *error)?;
        checked_entry(&self.source, archive, statement_index)
    }
    #[cfg(test)]
    pub(crate) fn withhold_optional_archive_for_test(&mut self, issue: QuantityCaptureIssue) {
        self.archive = Err(issue);
    }
    /// Authenticate every retained original tape once, then share its immutable
    /// charged backing. No source, leaf, tape, census or allocation pool is rebuilt.
    pub(crate) fn admit_quantity_archive(
        &self,
    ) -> Result<AdmittedQuantityArchive, QuantityCaptureIssue> {
        self.verify_source_binding()
            .map_err(|_| QuantityCaptureIssue::InvalidFacts)?;
        if self.source.manifest.coverage != FastpqSourceEffectCoverageV1::Complete {
            return Err(QuantityCaptureIssue::UnownedMutation);
        }
        let archive = if self.source.leaves.as_slice().is_empty() {
            None
        } else {
            let archive = self.archive.as_ref().map_err(|error| *error)?;
            for index in 0..self.source.leaves.as_slice().len() {
                let _checked = checked_entry(&self.source, archive, index)?;
            }
            Some(archive.clone())
        };
        Ok(AdmittedQuantityArchive {
            source: self.source.clone(),
            archive,
        })
    }
    /// Calculate the existing native execution commitment over this exact protected
    /// witness and retain the same fixed result. This adds no second tree/hash pass.
    /// The native caller already owns the sealed output and its original World cut.
    pub(crate) fn prepare_native_execution(
        &mut self,
        executed: &iroha_data_model::block::SignedBlock,
        transition: &crate::sumeragi::commitment::WorldStateTransition,
    ) -> Result<
        iroha_data_model::sumeragi_finality::ExecutionCommitment,
        iroha_data_model::sumeragi_finality::CommitmentError,
    > {
        use iroha_data_model::sumeragi_finality::CommitmentError;
        self.verify_source_binding()
            .map_err(CommitmentError::InvalidOutputs)?;
        if self.wire() != self.wire.get()
            || executed.header().height().get() != self.manifest().source.height
        {
            return Err(CommitmentError::InvalidOutputs(
                "native commitment requires the exact original captured quantity source".into(),
            ));
        }
        let execution =
            crate::sumeragi::commitment::execution_commitment(self.wire(), executed, transition)?;
        let binding = (executed.hash(), execution);
        if self.native.is_some_and(|original| original != binding) {
            return Err(CommitmentError::InvalidOutputs(
                "original captured witness cannot change native execution identity".into(),
            ));
        }
        self.native = Some(binding);
        Ok(execution)
    }

    /// Match the same original native execution without decoding or copying its witness.
    /// This local binding does not authenticate a certificate or grant relay authority.
    pub(crate) fn matches_original_native_execution(
        &self,
        executed: &iroha_data_model::block::SignedBlock,
        execution: iroha_data_model::sumeragi_finality::ExecutionCommitment,
    ) -> bool {
        std::ptr::eq(self.wire(), self.wire.get())
            && self.native == Some((executed.hash(), execution))
            && self.wire.belongs_to(&self.source.pool)
    }

    /// Validate this protected original against the actual authenticated native result.
    /// No new root materialization, allocations or supplied expected digest are used.
    pub(crate) fn verify_finalized_source(
        &self,
        source: &crate::sumeragi::certified_chain::AuthenticatedExecutionBlock,
    ) -> Result<(), crate::fastpq::finalized_source::FinalizedFastpqSourceError> {
        #[cfg(test)]
        work_counts::native();
        use crate::fastpq::finalized_source::FinalizedFastpqSourceError as Error;
        self.verify_source_binding()
            .map_err(|_| Error::WitnessContent)?;
        let Some((block, execution)) = self.native else {
            return Err(Error::MissingNativeResult);
        };
        let committed = source.committed();
        if self.wire() != self.wire.get() {
            return Err(Error::WitnessContent);
        }
        if block != committed.block_hash()
            || self.manifest().source.height != committed.height()
            || self.manifest().source.network_id
                != committed.commitment().schedule.current.network_id
        {
            return Err(Error::BlockIdentity);
        }
        if execution != committed.commitment().execution {
            return Err(Error::ExecutionResult);
        }
        let certified = source.block().fastpq_transcripts();
        if self.wire().fastpq_transcripts.len() != certified.len() {
            return Err(Error::TranscriptInventory);
        }
        for (bundle, (entry, transcripts)) in self.wire().fastpq_transcripts.iter().zip(certified) {
            if &bundle.entry_hash != entry {
                return Err(Error::TranscriptInventory);
            }
            if &bundle.transcripts != transcripts {
                return Err(Error::TranscriptContent);
            }
        }
        Ok(())
    }

    pub(in crate::state) fn verify_current(&self, block: &StateBlock<'_>) -> Result<(), String> {
        self.source.verify_current(block)?;
        self.verify_source_binding()
    }

    /// Offer a deliberately reconstructed altered wire to existing production checks.
    /// The protected original graph and its credits stay unchanged and retained.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn offer_reconstructed_tamper_for_test(
        &mut self,
        alter: impl FnOnce(&mut ExecWitness),
    ) {
        let mut offered = self.wire.get().clone();
        alter(&mut offered);
        self.offered_wire_for_test = Some(offered);
    }
}

// During the one-shot canonical move, every initialized graph drops before its
// charge ledger. An unwind while graph destruction runs conservatively retains
// credit rather than claiming incomplete reclamation. This owner never escapes.
struct Assembly {
    wire: ManuallyDrop<ExecWitness>,
    charges: ManuallyDrop<ChargedBuffer<AllocationCharge>>,
}
impl Drop for Assembly {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Assembly uniquely owns both values and destroys payload first.
        unsafe { ManuallyDrop::drop(&mut self.wire) };
        // SAFETY: complete original payload destruction preceded its sole ledger.
        unsafe { ManuallyDrop::drop(&mut self.charges) };
    }
}
impl Assembly {
    #[allow(unsafe_code)]
    fn finish(self, pool: &AllocationBudget) -> SourceResult<RetainedPayload<ExecWitness>> {
        let mut original = ManuallyDrop::new(self);
        // SAFETY: one-time move prevents Assembly Drop and keeps the original
        // wire allocations and ledger paired through the canonical constructor.
        let wire = unsafe { ManuallyDrop::take(&mut original.wire) };
        let charges = unsafe { ManuallyDrop::take(&mut original.charges) };
        // SAFETY: exact fixed buffers were moved into writes/key/value below;
        // their capacities never grow or escape. Inherited fields move unchanged.
        match unsafe { RetainedPayload::try_new(wire, charges, pool) } {
            Ok(retained) => Ok(retained),
            Err((wire, charges, _)) => {
                let _original = Assembly {
                    wire: ManuallyDrop::new(wire),
                    charges: ManuallyDrop::new(charges),
                };
                Err(owner("D7 witness allocation custody changed pools"))
            }
        }
    }
}

impl StateBlock<'_> {
    /// Move canonical ordinary writes into exact original-pool backing with one D7 write.
    /// The native witness binder still authenticates the complete returned wire to R.
    #[allow(unsafe_code)]
    pub(in crate::state) fn retain_quantity_source_witness(
        &self,
        witness: ExecWitness,
    ) -> SourceResult<CapturedExecWitness> {
        let source = self
            .fastpq_quantity_candidate
            .commitments
            .sealed
            .as_ref()
            .ok_or_else(|| {
                owner("ordinary capture requires the completed original quantity source")
            })?;
        source.verify_current(self)?;
        source
            .inventory
            .verify_ordinary_witness_bundles(&witness.fastpq_transcripts)
            .map_err(ExecutionAttemptError::Rejected)?;
        if !witness.fastpq_batches.is_empty()
            || witness
                .writes
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || witness
                .writes
                .iter()
                .any(|write| write.key.first() == KEY.first())
        {
            return Err(owner(
                "ordinary capture requires canonical writes without an existing D7 family owner",
            ));
        }
        let write_capacity = witness.writes.len().checked_add(1).ok_or_else(overflow)?;
        let key_capacity = KEY.len();
        let value_capacity = source.manifest_bytes.as_slice().len();
        let demand = [
            Layout::array::<ExecKv>(write_capacity),
            Layout::array::<u8>(key_capacity),
            Layout::array::<u8>(value_capacity),
            Layout::array::<AllocationCharge>(3),
        ]
        .into_iter()
        .try_fold(0usize, |sum, layout| sum.checked_add(layout.ok()?.size()))
        .ok_or_else(overflow)?;
        let pool = &source.pool;
        let mut reservation = pool
            .try_reserve_bytes(demand)
            .map_err(|refusal| ExecutionAttemptError::Deferred(refusal.into()))?;
        let charges = ChargedBuffer::from_reservation(3, &mut reservation).map_err(buffer)?;
        let mut assembly = Assembly {
            wire: ManuallyDrop::new(witness),
            charges: ManuallyDrop::new(charges),
        };
        let mut writes =
            ChargedBuffer::from_reservation(write_capacity, &mut reservation).map_err(buffer)?;
        let mut key =
            ChargedBuffer::from_reservation(key_capacity, &mut reservation).map_err(buffer)?;
        let mut value =
            ChargedBuffer::from_reservation(value_capacity, &mut reservation).map_err(buffer)?;
        if reservation.remaining_bytes() != 0 {
            return Err(owner("D7 witness left unaccounted prepaid backing"));
        }
        for byte in KEY {
            key.push_reserved(*byte);
        }
        for byte in source.manifest_bytes.as_slice() {
            value.push_reserved(*byte);
        }
        // SAFETY: each exact allocation moves once into the new canonical write;
        // original credits enter Assembly before any graph can escape this scope.
        let (key, key_charge) = unsafe { key.into_allocation_parts() };
        let (value, value_charge) = unsafe { value.into_allocation_parts() };
        assembly.charges.push_reserved(key_charge);
        assembly.charges.push_reserved(value_charge);
        let mut original_d7 = Some(ExecKv { key, value });
        for write in std::mem::take(&mut assembly.wire.writes) {
            if original_d7.is_some() && write.key.as_slice() > KEY {
                writes.push_reserved(original_d7.take().expect("original new write retained"));
            }
            writes.push_reserved(write);
        }
        if let Some(write) = original_d7 {
            writes.push_reserved(write);
        }
        // SAFETY: replacement writes has one exact admitted allocation. Its
        // original nested values moved unchanged; no replacement/growth follows.
        let (writes, write_charge) = unsafe { writes.into_allocation_parts() };
        assembly.wire.writes = writes;
        assembly.charges.push_reserved(write_charge);
        let archive = match &self.fastpq_quantity_candidate.source_census {
            QuantitySourceCensusState::Sealed(census) => census.retained_archive_for_work(self),
            _ => Err(self
                .fastpq_quantity_candidate
                .issue
                .unwrap_or(QuantityCaptureIssue::InvalidFacts)),
        };
        let wire = assembly.finish(pool)?;
        let retained = CapturedExecWitness {
            wire,
            source: source.clone(),
            native: None,
            archive,
            #[cfg(any(test, feature = "iroha-core-tests"))]
            offered_wire_for_test: None,
        };
        // The immutable State borrow prevents changes after the initial source check.
        retained
            .verify_source_binding()
            .map_err(ExecutionAttemptError::Rejected)?;
        Ok(retained)
    }
}

/// Opaque complete-archive admission over original immutable charged owners.
/// Its private constructor validates every exact tape/leaf once. No Clone or mutable
/// projection exists; sharing the two original backing handles retains their charges.
pub(crate) struct AdmittedQuantityArchive {
    source: ChargedShared<FinalizedQuantitySource>,
    archive: Option<ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>>,
}
impl AdmittedQuantityArchive {
    /// Borrow one previously admitted original tape without another source scan/hash.
    pub(crate) fn entry(
        &self,
        index: usize,
    ) -> Result<CapturedQuantityEntry<'_>, QuantityCaptureIssue> {
        #[cfg(test)]
        work_counts::selection();
        let leaf = self
            .source
            .leaves
            .as_slice()
            .get(index)
            .ok_or(QuantityCaptureIssue::InvalidFacts)?;
        let archive = self
            .archive
            .as_ref()
            .ok_or(QuantityCaptureIssue::InvalidFacts)?;
        let row = archive
            .rows()
            .binary_search_by_key(&leaf.entry_hash, |(hash, _)| *hash)
            .map_err(|_| QuantityCaptureIssue::InvalidFacts)?;
        Ok(CapturedQuantityEntry {
            effects: archive.rows()[row].1.wire(),
            leaf,
            pool: &self.source.pool,
        })
    }
    #[cfg(test)]
    pub(crate) fn scan_counts_for_test() -> (usize, usize, usize, usize) {
        work_counts::counts()
    }
}
fn checked_entry<'a>(
    source: &'a FinalizedQuantitySource,
    archive: &'a ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>,
    statement_index: usize,
) -> Result<CapturedQuantityEntry<'a>, QuantityCaptureIssue> {
    let leaf = source
        .leaves
        .as_slice()
        .get(statement_index)
        .ok_or(QuantityCaptureIssue::InvalidFacts)?;
    if !archive.belongs_to(&source.pool) {
        return Err(QuantityCaptureIssue::InvalidFacts);
    }
    let index = archive
        .rows()
        .binary_search_by_key(&leaf.entry_hash, |(hash, _)| *hash)
        .map_err(|_| QuantityCaptureIssue::InvalidFacts)?;
    let effects = archive.rows()[index].1.wire();
    let entry = source
        .inventory
        .entries()
        .get(usize::try_from(leaf.entry_index).map_err(|_| QuantityCaptureIssue::InvalidFacts)?)
        .ok_or(QuantityCaptureIssue::InvalidFacts)?;
    if effects.context
        != (FastpqExecutionEffectContextV1 {
            source: leaf.source,
            entry: *entry,
        })
        || usize::try_from(leaf.effect_count).ok() != Some(effects.effects.len())
        || {
            #[cfg(test)]
            work_counts::digest();
            iroha_data_model::fastpq::execution_effects_digest_v1(effects)
                .map_err(|_| QuantityCaptureIssue::InvalidFacts)?
                .as_ref()
                != &leaf.effects_digest
        }
    {
        return Err(QuantityCaptureIssue::InvalidFacts);
    }
    Ok(CapturedQuantityEntry {
        effects,
        leaf,
        pool: &source.pool,
    })
}
#[cfg(test)]
mod work_counts {
    thread_local! { static COUNTS: std::cell::Cell<(usize,usize,usize,usize)> = const { std::cell::Cell::new((0,0,0,0)) }; }
    pub(super) fn native() {
        COUNTS.with(|c| {
            let (n, w, d, s) = c.get();
            c.set((n + 1, w, d, s));
        });
    }
    pub(super) fn wire() {
        COUNTS.with(|c| {
            let (n, w, d, s) = c.get();
            c.set((n, w + 1, d, s));
        });
    }
    pub(super) fn digest() {
        COUNTS.with(|c| {
            let (n, w, d, s) = c.get();
            c.set((n, w, d + 1, s));
        });
    }
    pub(super) fn selection() {
        COUNTS.with(|c| {
            let (n, w, d, s) = c.get();
            c.set((n, w, d, s + 1));
        });
    }
    pub(super) fn counts() -> (usize, usize, usize, usize) {
        COUNTS.with(std::cell::Cell::get)
    }
}
