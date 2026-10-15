//! Observation-only counts of key-admission work on the calling thread.
//!
//! Counted when started: canonical descriptor admission decodes
//! ([`super::DescriptorBinding::decode`] and [`super::DescriptorBinding::decode_v2`]) and
//! the original bytes hashed by compiled-profile admission. Counts are public, kept in
//! this thread's memory only and never persisted; no admission decision reads them.

use std::cell::Cell;

/// Key-admission work started on the current thread since the thread began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionWorkV1 {
    /// Canonical descriptor admission decodes.
    pub descriptor_decodes: u64,
    /// Profile and original bytes hashed by compiled-profile admission.
    pub builtin_bytes_hashed: u64,
}

impl AdmissionWorkV1 {
    /// This thread's cumulative counts.
    #[must_use]
    pub fn current_thread() -> Self {
        // Thread-local teardown loses only observation, never a verdict.
        WORK.try_with(Cell::get).unwrap_or_default()
    }

    /// The work counted in `self` and not in `earlier` (field by field, saturating).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            descriptor_decodes: self
                .descriptor_decodes
                .saturating_sub(earlier.descriptor_decodes),
            builtin_bytes_hashed: self
                .builtin_bytes_hashed
                .saturating_sub(earlier.builtin_bytes_hashed),
        }
    }
}

thread_local! {
    static WORK: Cell<AdmissionWorkV1> = const {
        Cell::new(AdmissionWorkV1 {
            descriptor_decodes: 0,
            builtin_bytes_hashed: 0,
        })
    };
}

fn record(add: impl FnOnce(&mut AdmissionWorkV1)) {
    let _ = WORK.try_with(|work| {
        let mut value = work.get();
        add(&mut value);
        work.set(value);
    });
}

/// Record one started canonical descriptor decode.
pub(super) fn record_descriptor_decode() {
    record(|work| work.descriptor_decodes = work.descriptor_decodes.saturating_add(1));
}

/// Record `bytes` hashed once by compiled-profile admission.
pub(super) fn record_builtin_hash(bytes: usize) {
    record(|work| {
        work.builtin_bytes_hashed = work
            .builtin_bytes_hashed
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DescriptorBinding;

    #[test]
    fn every_started_descriptor_decode_counts_once_on_its_own_thread() {
        let before = AdmissionWorkV1::current_thread();
        assert!(DescriptorBinding::decode(&[0, 1, 2]).is_err());
        assert!(DescriptorBinding::decode_v2(&[0, 1, 2]).is_err());
        let work = AdmissionWorkV1::current_thread().since(before);
        assert_eq!(work.descriptor_decodes, 2);
        assert_eq!(work.builtin_bytes_hashed, 0);
        std::thread::spawn(|| {
            let start = AdmissionWorkV1::current_thread();
            assert!(DescriptorBinding::decode_v2(&[3]).is_err());
            assert_eq!(
                AdmissionWorkV1::current_thread()
                    .since(start)
                    .descriptor_decodes,
                1
            );
        })
        .join()
        .unwrap();
        assert_eq!(
            AdmissionWorkV1::current_thread()
                .since(before)
                .descriptor_decodes,
            2
        );
    }

    #[test]
    fn builtin_digests_count_every_hashed_byte_and_differences_saturate() {
        let before = AdmissionWorkV1::current_thread();
        record_builtin_hash(4097);
        record_builtin_hash(0);
        assert_eq!(
            AdmissionWorkV1::current_thread()
                .since(before)
                .builtin_bytes_hashed,
            4097
        );
        assert_eq!(
            AdmissionWorkV1::default().since(AdmissionWorkV1 {
                descriptor_decodes: 1,
                builtin_bytes_hashed: 1,
            }),
            AdmissionWorkV1::default()
        );
    }
}
