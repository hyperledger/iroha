//! Atomic prepaid diagnostic publication for complete private-owner cleanup.

use super::{
    DiagnosticMemoryAccess, DiagnosticMemoryAccessKind, DiagnosticMemoryAccessRecorder,
    DiagnosticMemoryPrivacyTag, ExecutionDeferral, VMError,
};
use crate::private_memory_ranges::PrivateMemoryRanges;

impl DiagnosticMemoryAccessRecorder {
    pub(crate) fn record_private_scrub(
        &self,
        image: &[u8],
        ranges: &PrivateMemoryRanges,
    ) -> Result<(), VMError> {
        let mut inner = self.inner.lock();
        if !inner.started {
            return Err(VMError::HostUnavailable);
        }
        let mut bytes = 0_usize;
        let mut count = 0_u64;
        let mut previous = None;
        while let Some((start, end)) = ranges.next_after(previous) {
            let start_index = usize::try_from(start).map_err(|_| VMError::HostUnavailable)?;
            let end_index = usize::try_from(end).map_err(|_| VMError::HostUnavailable)?;
            let before = image
                .get(start_index..end_index)
                .ok_or(VMError::HostUnavailable)?;
            u32::try_from(before.len()).map_err(|_| VMError::HostUnavailable)?;
            bytes = bytes
                .checked_add(before.len())
                .ok_or(VMError::HostUnavailable)?;
            count = count.checked_add(1).ok_or(VMError::HostUnavailable)?;
            previous = Some(start);
        }
        if bytes > inner.capacity.saturating_sub(inner.rows.as_slice().len()) {
            return Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity,
            ));
        }
        let next_ordinal = inner
            .next_access_ordinal
            .checked_add(count)
            .ok_or(VMError::HostUnavailable)?;
        // Nothing below can allocate or fail: exact row capacity, every slice,
        // offset conversion and all ordinals have been checked under this lock.
        let mut previous = None;
        let mut ordinal = inner.next_access_ordinal;
        while let Some((start, end)) = ranges.next_after(previous) {
            for (offset, &before) in image[start as usize..end as usize].iter().enumerate() {
                let row = DiagnosticMemoryAccess {
                    step_ordinal: inner.step_ordinal,
                    access_ordinal: ordinal,
                    byte_offset: offset as u32,
                    address: start + offset as u64,
                    before,
                    after: 0,
                    kind: DiagnosticMemoryAccessKind::PrivateReset,
                    privacy_tag: DiagnosticMemoryPrivacyTag::Public,
                };
                inner
                    .rows
                    .append(&[row])
                    .expect("complete private scrub row preflight");
            }
            ordinal += 1;
            previous = Some(start);
        }
        inner.next_access_ordinal = next_ordinal;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;

    #[test]
    fn scrub_ordinal_overflow_refuses_before_publishing_any_row() {
        let budget = AllocationBudget::new(2 * std::mem::size_of::<DiagnosticMemoryAccess>());
        let recorder = DiagnosticMemoryAccessRecorder::try_new(2, &budget).unwrap();
        recorder.begin_run(true).unwrap();
        recorder.inner.lock().next_access_ordinal = u64::MAX;
        let mut ranges = PrivateMemoryRanges::default();
        ranges.try_insert(0..1).unwrap();
        assert!(matches!(
            recorder.record_private_scrub(&[9], &ranges),
            Err(VMError::HostUnavailable)
        ));
        assert_eq!(recorder.len(), 0);
        assert_eq!(recorder.inner.lock().next_access_ordinal, u64::MAX);
    }

    #[test]
    fn scrub_preflights_all_ranges_before_diagnostic_publication() {
        let budget = AllocationBudget::new(2 * std::mem::size_of::<DiagnosticMemoryAccess>());
        let recorder = DiagnosticMemoryAccessRecorder::try_new(2, &budget).unwrap();
        recorder.begin_run(true).unwrap();
        let mut ranges = PrivateMemoryRanges::default();
        ranges.try_insert(0..1).unwrap();
        ranges.try_insert(2..3).unwrap();
        assert!(matches!(
            recorder.record_private_scrub(&[9, 8], &ranges),
            Err(VMError::HostUnavailable)
        ));
        assert_eq!(recorder.len(), 0);
        assert_eq!(recorder.inner.lock().next_access_ordinal, 0);
    }
}
