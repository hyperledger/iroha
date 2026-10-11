//! Private lifecycle erasure uses the exclusive image owner, never guest write-log allocation.

use super::Memory;
use crate::{VMError, private_memory_ranges::PrivateMemoryRanges};

impl Memory {
    /// Validate every range and diagnostic row before the first private byte changes.
    /// Guest table permissions do not restrict this owner's terminal cleanup.
    pub(crate) fn scrub_private_ranges(
        &mut self,
        ranges: &PrivateMemoryRanges,
    ) -> Result<(), VMError> {
        let mut previous = None;
        while let Some((start, end)) = ranges.next_after(previous) {
            let heap = start >= Self::HEAP_START && end <= Self::HEAP_START + self.heap_limit;
            let stack = start >= Self::STACK_START && end <= self.stack_top();
            if start >= end || (!heap && !stack) || end > self.data.len() as u64 {
                return Err(VMError::ExecutionDeferred(
                    crate::error::ExecutionDeferral::LocalInvariantViolation,
                ));
            }
            previous = Some(start);
        }
        if ranges.is_empty() {
            return Ok(());
        }
        if let Some(recorder) = &self.diagnostic_access_recorder {
            // A single recorder lock makes preflight and publication atomic
            // even if another diagnostic Memory shares this recorder.
            recorder.record_private_scrub(&self.data, ranges)?;
        }
        let mut previous = None;
        while let Some((start, end)) = ranges.next_after(previous) {
            let start_index = start as usize;
            let end_index = end as usize;
            iroha_crypto::zeroize_value_for_confidential_discard(
                &mut self.data[start_index..end_index],
            );
            // Both bitmaps were prepaid with the image; roots and warm reset
            // continue to observe exactly the zeroed bytes, with no allocation.
            self.update_merkle(start_index, end_index - start_index);
            previous = Some(start);
        }
        Ok(())
    }
}
