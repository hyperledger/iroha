//! One original proof stream and atomic native clock, retaining local refusals.

use super::*;
use iroha_data_model::sumeragi::finality::PreparedNativeFinalityJournal;

/// Prepared source ranges and exact raw frame survive until the original cursor advances.
/// TODO: fund decoded nested SignedBlock/result graphs independently.
struct RestoredProofSource {
    address: usize,
    length: usize,
    digest: Hash,
    target: u64,
}
impl RestoredProofSource {
    fn of(frame: &[u8], target: u64) -> Self {
        Self {
            address: frame.as_ptr().addr(),
            length: frame.len(),
            digest: Hash::new(frame),
            target,
        }
    }
    fn matches(&self, frame: &[u8], target: u64) -> bool {
        self.address == frame.as_ptr().addr()
            && self.length == frame.len()
            && self.digest == Hash::new(frame)
            && self.target == target
    }
}

pub(super) struct FinalityInput {
    input: FrameInput,
    journal: PreparedNativeFinalityJournal,
    clock: NativeJournalCursor,
    height: u64,
    committed: bool,
    restored_source: Option<RestoredProofSource>,
}
impl FinalityInput {
    pub(super) fn new(
        input: FrameInput,
        clock: NativeJournalCursor,
        height: u64,
    ) -> std::result::Result<Self, AttemptError> {
        let journal =
            PreparedNativeFinalityJournal::new(clock.limits(), clock.allocation_budget())?;
        Ok(Self {
            input,
            journal,
            clock,
            height,
            committed: false,
            restored_source: None,
        })
    }
    pub(super) fn clock(&self) -> &NativeJournalCursor {
        &self.clock
    }
    pub(super) fn source_identity(&self) -> std::result::Result<[u64; 2], AttemptError> {
        Ok(self.input.source_identity()?)
    }
    pub(super) fn generation(&self) -> u64 {
        self.input.generation()
    }
    pub(super) fn restore_stream_generation(
        &mut self,
        generation: u64,
        original_source: [u64; 2],
    ) -> std::result::Result<(), AttemptError> {
        self.input.restore_empty_cursor(
            generation,
            self.clock.limits().journal_bytes,
            original_source,
        )?;
        Ok(())
    }
    pub(super) fn tighten_deadline(&mut self, deadline: Instant) {
        self.input.tighten_deadline(deadline);
    }

    pub(super) fn height(&self) -> u64 {
        self.height
    }
    fn finish_frame(&mut self) -> std::result::Result<(), AttemptError> {
        self.input.consume_verified_frame()?;
        self.journal.clear_consumed();
        self.committed = false;
        Ok(())
    }
    pub(super) fn advance_to(
        &mut self,
        target: u64,
        cutoff: u64,
        mut persist_original: impl FnMut(&[u8]) -> std::result::Result<(), AttemptError>,
    ) -> std::result::Result<(), AttemptError> {
        if self.committed {
            if self.height == target {
                self.persist_committed_target(&mut persist_original)?;
            }
            self.finish_frame()?;
        }
        while self.height < target {
            self.input.read_until_complete()?;
            let frame = self.input.charged_frame().ok_or(AttemptError::Phase)?;
            self.journal.decode(frame)?;
            let journal = self.journal.view(frame)?;
            let height = u64::try_from(journal.len()).map_err(|_| AttemptError::Height)?;
            check_rotation_phase_height(self.height, height, cutoff)
                .map_err(|_| AttemptError::Height)?;
            if height > target
                || self.clock.tip().map(|tip| tip.height()).unwrap_or(1) != self.height
            {
                return Err(AttemptError::Height);
            }
            let verified = self.clock.advance(journal)?;
            self.height = verified.height();
            self.committed = true;
            if self.height == target {
                self.persist_committed_target(&mut persist_original)?;
            }
            self.finish_frame()?;
        }
        if self.height != target {
            return Err(AttemptError::Height);
        }
        Ok(())
    }
    fn persist_committed_target(
        &self,
        persist: &mut impl FnMut(&[u8]) -> std::result::Result<(), AttemptError>,
    ) -> std::result::Result<(), AttemptError> {
        #[cfg(all(test, sumeragi_daemon_mutation = "HC110"))]
        return Ok(());
        let frame = self.input.frame().ok_or(AttemptError::Phase)?;
        persist(frame)
    }
    /// Rebuild actual native ancestry from the unchanged durable proof source.
    /// Raw recorded hashes never initialize the clock. Full canonical verification
    /// and the original chain/network certificate verifier run before its tip advances.
    /// TODO: decoded nested native block/result graphs still need retained funding.
    pub(super) fn restore_target_from_original_frame(
        &mut self,
        frame: &ChargedBuffer<u8>,
        target: u64,
        cutoff: u64,
    ) -> std::result::Result<(), AttemptError> {
        self.input.require_empty_cursor()?;
        if !cfg!(all(test, sumeragi_daemon_mutation = "HC119"))
            && !frame.belongs_to(self.clock.allocation_budget())
        {
            return Err(AttemptError::Binding);
        }
        if self.committed {
            return Err(AttemptError::Phase);
        }
        if target >= cutoff {
            return Err(AttemptError::Height);
        }
        if let Some(original) = &self.restored_source {
            if original.target == target {
                if !original.matches(frame.as_slice(), target) {
                    return Err(AttemptError::Binding);
                }
                if self.height == target {
                    return Ok(());
                }
            }
            if target < original.target {
                return Err(AttemptError::Height);
            }
            if target != original.target && self.height != original.target {
                return Err(AttemptError::Binding);
            }
        }
        // A restart can begin at genesis with an original H3 accepted checkpoint.
        // The complete journal below authenticates every intermediate block; only
        // the live FIFO path requires each submitted phase to be adjacent.
        #[cfg(all(test, sumeragi_daemon_mutation = "HC200"))]
        check_rotation_phase_height(self.height, target, cutoff)
            .map_err(|_| AttemptError::Height)?;
        if target <= self.height {
            return Err(AttemptError::Height);
        }
        if self.clock.tip().map(|tip| tip.height()).unwrap_or(1) != self.height {
            return Err(AttemptError::Height);
        }
        // Bind before decoder/native refusal so retry cannot substitute allocation
        // or changed bytes for this original source. The actual tip remains atomic.
        if self
            .restored_source
            .as_ref()
            .is_none_or(|old| old.target != target)
        {
            self.restored_source = Some(RestoredProofSource::of(frame.as_slice(), target));
        }
        self.journal.decode(frame)?;
        let journal = self.journal.view(frame)?;
        if u64::try_from(journal.len()).map_err(|_| AttemptError::Height)? != target {
            return Err(AttemptError::Height);
        }
        let verified = self.clock.advance(journal)?;
        self.height = verified.height();
        self.journal.clear_consumed();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
