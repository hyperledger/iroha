//! Process-shared, finite admission for private signer-journal inventory I/O.
//!
//! One original pool is injected into receipt purposes and pending Reserve. Credits are local
//! resources: refusal is retryable and never makes a signed operation consensus-invalid.
//! Exact portable filesystem accounting is recorded in `inventory_budget.md` beside this module.

use super::{
    MAX_JOURNAL_PATH_BYTES, MAX_JOURNAL_PATH_COMPONENTS, MAX_RECORDS, SignerReceiptJournalErrorV1,
};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_config::parameters::actual::SorafsSignerJournalInventory;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const NATIVE_BUFFER_ALLOWANCE: usize = 256 * 1024;
const PENDING_ID_SLOT_ALLOWANCE: usize = 128;
const TRANSIENT_HANDLES: u64 = 4;

/// One original finite pool injected into all receipt families and pending Reserve.
#[derive(Clone)]
pub struct SignerJournalInventoryPoolV1 {
    resident: AllocationBudget,
    metadata: Arc<Counter>,
    handles: Arc<Counter>,
}
impl SignerJournalInventoryPoolV1 {
    /// Construct the process pool from validated non-secret node configuration.
    ///
    /// # Errors
    /// Rejects limits unable to fund one full receipt scan and pinned maximum path.
    pub fn new(policy: SorafsSignerJournalInventory) -> Result<Self, SignerReceiptJournalErrorV1> {
        if policy.resident_bytes.0 < SorafsSignerJournalInventory::MIN_RESIDENT_BYTES
            || policy.metadata_probes < SorafsSignerJournalInventory::MIN_METADATA_PROBES
            || policy.open_handles < SorafsSignerJournalInventory::MIN_OPEN_HANDLES
        {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        let resident = usize::try_from(policy.resident_bytes.0)
            .map_err(|_| SignerReceiptJournalErrorV1::Unavailable)?;
        Ok(Self::from_limits(
            resident,
            policy.metadata_probes,
            u64::from(policy.open_handles),
        ))
    }

    fn from_limits(resident_bytes: usize, metadata_probes: u64, open_handles: u64) -> Self {
        Self {
            resident: AllocationBudget::new(resident_bytes),
            metadata: Arc::new(Counter::new(metadata_probes)),
            handles: Arc::new(Counter::new(open_handles)),
        }
    }

    pub(super) fn admit_open(
        &self,
        path_bytes: usize,
        components: usize,
    ) -> Result<(OpenLease, InspectionLease), SignerReceiptJournalErrorV1> {
        if path_bytes > MAX_JOURNAL_PATH_BYTES
            || components == 0
            || components > MAX_JOURNAL_PATH_COMPONENTS
        {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        let d = components + 1;
        // iroha_fs retains each complete prefix PathBuf, not just its component name.
        let resident_bytes = path_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_mul(d))
            .and_then(|n| n.checked_add(256 * d))
            .and_then(|n| n.checked_add(4096))
            .ok_or(SignerReceiptJournalErrorV1::Unavailable)?;
        let resident = self.reserve(resident_bytes)?;
        let handles = self.handles.try_acquire((d + 1) as u64)?; // ancestry plus control lock
        let inspection = self.admit_work(NATIVE_BUFFER_ALLOWANCE, 68 * d as u64 + 20)?;
        Ok((
            OpenLease {
                _resident: resident,
                _handles: handles,
            },
            inspection,
        ))
    }

    pub(super) fn admit_scan(
        &self,
        max_records: usize,
        pending_ids: bool,
        lineage_len: usize,
    ) -> Result<InspectionLease, SignerReceiptJournalErrorV1> {
        let d = bounded_lineage(lineage_len)?;
        if max_records > MAX_RECORDS || (pending_ids && max_records > 4096) {
            return Err(SignerReceiptJournalErrorV1::Unavailable);
        }
        let ids = if pending_ids {
            max_records * PENDING_ID_SLOT_ALLOWANCE
        } else {
            0
        };
        // One control entry and one overflow entry are included before an excessive scan stops.
        let entries = max_records as u64 + 2;
        self.admit_work(NATIVE_BUFFER_ALLOWANCE + ids, 8 * entries + 92 * d + 34)
    }

    pub(super) fn admit_file(
        &self,
        max_record_bytes: usize,
        lineage_len: usize,
    ) -> Result<FileLease, SignerReceiptJournalErrorV1> {
        bounded_lineage(lineage_len)?;
        let bytes = max_record_bytes
            .checked_add(16 * lineage_len + 2048)
            .ok_or(SignerReceiptJournalErrorV1::Unavailable)?;
        let resident = self.reserve(bytes)?;
        let handle = self.handles.try_acquire(1)?;
        Ok(FileLease {
            _resident: resident,
            _handle: handle,
        })
    }

    pub(super) fn admit_inspection(
        &self,
        lineage_len: usize,
        read_bytes: usize,
    ) -> Result<InspectionLease, SignerReceiptJournalErrorV1> {
        let d = bounded_lineage(lineage_len)?;
        let bytes = NATIVE_BUFFER_ALLOWANCE
            .checked_add(read_bytes)
            .ok_or(SignerReceiptJournalErrorV1::Unavailable)?;
        // The largest phase is durable pending creation, seal, exact read and no-replace rename.
        // Stage/recovery release this permit before their final independently budgeted recheck.
        self.admit_work(bytes, 198 * d + 128)
    }

    fn reserve(&self, bytes: usize) -> Result<AllocationReservation, SignerReceiptJournalErrorV1> {
        self.resident
            .try_reserve_bytes(bytes)
            .map_err(|_| SignerReceiptJournalErrorV1::Capacity)
    }

    fn admit_work(
        &self,
        bytes: usize,
        probes: u64,
    ) -> Result<InspectionLease, SignerReceiptJournalErrorV1> {
        let resident = self.reserve(bytes)?;
        let metadata = self.metadata.try_acquire(probes)?;
        let handles = self.handles.try_acquire(TRANSIENT_HANDLES)?;
        Ok(InspectionLease {
            _resident: resident,
            _metadata: metadata,
            _handles: handles,
        })
    }

    #[cfg(test)]
    pub(super) fn for_test(resident_bytes: usize, metadata_probes: u64, open_handles: u64) -> Self {
        Self::from_limits(resident_bytes, metadata_probes, open_handles)
    }
}

fn bounded_lineage(value: usize) -> Result<u64, SignerReceiptJournalErrorV1> {
    if !(2..=MAX_JOURNAL_PATH_COMPONENTS + 1).contains(&value) {
        return Err(SignerReceiptJournalErrorV1::Unavailable);
    }
    Ok(value as u64)
}

pub(super) struct OpenLease {
    _resident: AllocationReservation,
    _handles: CounterPermit,
}
pub(super) struct FileLease {
    _resident: AllocationReservation,
    _handle: CounterPermit,
}
pub(super) struct InspectionLease {
    _resident: AllocationReservation,
    _metadata: CounterPermit,
    _handles: CounterPermit,
}

struct Counter {
    limit: u64,
    held: AtomicU64,
}
impl Counter {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            held: AtomicU64::new(0),
        }
    }
    fn try_acquire(
        self: &Arc<Self>,
        amount: u64,
    ) -> Result<CounterPermit, SignerReceiptJournalErrorV1> {
        let mut held = self.held.load(Ordering::Acquire);
        loop {
            if amount > self.limit.saturating_sub(held) {
                return Err(SignerReceiptJournalErrorV1::Capacity);
            }
            match self.held.compare_exchange_weak(
                held,
                held + amount,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(CounterPermit {
                        pool: Arc::clone(self),
                        amount,
                    });
                }
                Err(current) => held = current,
            }
        }
    }
}

pub(super) struct CounterPermit {
    pool: Arc<Counter>,
    amount: u64,
}
impl Drop for CounterPermit {
    fn drop(&mut self) {
        self.pool.held.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_refusal_refunds_partial_acquisition_and_keeps_original_pool() {
        let pool = SignerJournalInventoryPoolV1::for_test(1024 * 1024, 1000, 7);
        let (open, probes) = pool.admit_open(10, 1).expect("first path");
        let resident = pool.resident.reserved_bytes();
        assert_eq!(pool.metadata.held.load(Ordering::Acquire), 156);
        assert_eq!(pool.handles.held.load(Ordering::Acquire), 7);
        assert!(matches!(
            pool.admit_scan(1, false, 2),
            Err(SignerReceiptJournalErrorV1::Capacity)
        ));
        assert_eq!(pool.metadata.held.load(Ordering::Acquire), 156);
        assert_eq!(pool.resident.reserved_bytes(), resident);
        drop(probes);
        assert_eq!(pool.metadata.held.load(Ordering::Acquire), 0);
        assert_eq!(pool.handles.held.load(Ordering::Acquire), 3);
        drop(open);
        assert_eq!(pool.resident.reserved_bytes(), 0);
        assert_eq!(pool.handles.held.load(Ordering::Acquire), 0);
    }

    #[test]
    fn distinct_purpose_handles_share_one_original_pool_and_refund_on_drop() {
        let pool = SignerJournalInventoryPoolV1::for_test(1024 * 1024, 1000, 7);
        let (first, probes) = pool.admit_open(10, 1).unwrap();
        drop(probes);
        let clone = pool.clone();
        assert!(matches!(
            clone.admit_open(10, 1),
            Err(SignerReceiptJournalErrorV1::Capacity)
        ));
        drop(first);
        assert!(clone.admit_open(10, 1).is_ok());
    }

    #[test]
    fn exact_scan_probe_boundary_and_one_below_are_distinct_from_invalid_content() {
        let probes = 8 * 3 + 92 * 2 + 34;
        let exact = SignerJournalInventoryPoolV1::for_test(NATIVE_BUFFER_ALLOWANCE, probes, 4);
        assert!(exact.admit_scan(1, false, 2).is_ok());
        let below = SignerJournalInventoryPoolV1::for_test(NATIVE_BUFFER_ALLOWANCE, probes - 1, 4);
        assert!(matches!(
            below.admit_scan(1, false, 2),
            Err(SignerReceiptJournalErrorV1::Capacity)
        ));
        assert_eq!(below.resident.reserved_bytes(), 0);
    }

    #[test]
    fn exact_open_resident_and_transient_handle_bounds_are_admitted() {
        let bytes = 2 * 10 * 2 + 256 * 2 + 4096 + NATIVE_BUFFER_ALLOWANCE;
        let exact = SignerJournalInventoryPoolV1::for_test(bytes, 156, 7);
        assert!(exact.admit_open(10, 1).is_ok());
        for pool in [
            SignerJournalInventoryPoolV1::for_test(bytes - 1, 156, 7),
            SignerJournalInventoryPoolV1::for_test(bytes, 155, 7),
            SignerJournalInventoryPoolV1::for_test(bytes, 156, 6),
        ] {
            assert!(matches!(
                pool.admit_open(10, 1),
                Err(SignerReceiptJournalErrorV1::Capacity)
            ));
            assert_eq!(pool.resident.reserved_bytes(), 0);
            assert_eq!(pool.metadata.held.load(Ordering::Acquire), 0);
            assert_eq!(pool.handles.held.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn pinned_bytes_and_recheck_bytes_hold_separate_refundable_credits() {
        let file_bytes = 64 * 1024 + 16 * 2 + 2048;
        let read_bytes = NATIVE_BUFFER_ALLOWANCE + 64 * 1024;
        let probes = 198 * 2 + 128;
        let pool = SignerJournalInventoryPoolV1::for_test(file_bytes + read_bytes, probes, 5);
        let file = pool.admit_file(64 * 1024, 2).unwrap();
        let read = pool.admit_inspection(2, 64 * 1024).unwrap();
        assert_eq!(pool.resident.reserved_bytes(), file_bytes + read_bytes);
        assert!(matches!(
            pool.admit_file(1, 2),
            Err(SignerReceiptJournalErrorV1::Capacity)
        ));
        drop(read);
        assert_eq!(pool.resident.reserved_bytes(), file_bytes);
        drop(file);
        assert_eq!(pool.resident.reserved_bytes(), 0);
        assert_eq!(pool.handles.held.load(Ordering::Acquire), 0);
    }

    #[test]
    fn configured_minimum_funds_maximum_portable_path_scan_and_pending_read() {
        let policy = SorafsSignerJournalInventory {
            resident_bytes: iroha_config_base::util::Bytes(
                SorafsSignerJournalInventory::MIN_RESIDENT_BYTES,
            ),
            metadata_probes: SorafsSignerJournalInventory::MIN_METADATA_PROBES,
            open_handles: SorafsSignerJournalInventory::MIN_OPEN_HANDLES,
        };
        let pool = SignerJournalInventoryPoolV1::new(policy).unwrap();
        let (_open, probes) = pool.admit_open(4096, 64).unwrap();
        drop(probes);
        let _file = pool.admit_file(136 * 1024, 65).unwrap();
        let scan = pool.admit_scan(MAX_RECORDS, false, 65).unwrap();
        assert_eq!(
            pool.metadata.held.load(Ordering::Acquire),
            policy.metadata_probes
        );
        drop(scan);
        let pending = pool.admit_scan(4096, true, 65).unwrap();
        drop(pending);
        let read = pool.admit_inspection(65, 136 * 1024).unwrap();
        drop(read);
        assert!(
            pool.resident.peak_reserved_bytes()
                <= usize::try_from(policy.resident_bytes.0).expect("fixture budget fits usize")
        );
    }
}
