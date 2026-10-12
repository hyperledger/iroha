//! Design §5.3 runtime capacity check at the coordinator: before an operation proves its step
//! and again before it commits.

use super::preparation_custody::SOURCE_CUSTODY_MAX_BYTES;
use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KAGEMUSHA_WALLET_BALLAST_BYTES_V1, KAGEMUSHA_WALLET_CAPACITY_HEADROOM_BYTES_V1,
    KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1,
};
use crate::kagemusha_wallet_capacity_v1::{
    KagemushaWalletCapacityShortfallV1, KagemushaWalletRuntimeCapacityV1,
};

/// Bound of one archived frozen transition (capsule and credential).
pub(super) const FROZEN_BOUND: usize =
    KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1 + KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1 + 1024;
/// Bound of one archived preparation plan.
pub(super) const PLAN_BOUND: usize = PREPARATION_MAX_BYTES + SOURCE_CUSTODY_MAX_BYTES + 1024;

/// Custody bytes one operation writes before a durable Ω covers it, apart from its fold
/// witnesses: the request and plan originals, the archived frozen transition, Advance's two
/// capsule copies and two completion-record copies, its growth headroom, and the ballast it
/// keeps for cleanup.
pub(super) const OPERATION_RESERVATION_BYTES: u64 = {
    let frozen = FROZEN_BOUND as u64;
    let copy = frozen + KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1 as u64;
    REQUEST_MAX_BYTES as u64
        + PLAN_BOUND as u64
        + frozen
        + 2 * copy
        + 2 * KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1 as u64
        + KAGEMUSHA_WALLET_CAPACITY_HEADROOM_BYTES_V1
        + KAGEMUSHA_WALLET_BALLAST_BYTES_V1
};

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Check this phone now against the operation's design §5.3 bounds.
    ///
    /// Storage must cover [`OPERATION_RESERVATION_BYTES`] plus the installed relations' largest
    /// fold-witness bytes, and available memory must cover their largest peak proving memory.
    /// Retained retries and resumes of selected operations never run this check: their outcome
    /// is already fixed.
    ///
    /// # Errors
    /// `NotEnoughStorage` or `NotEnoughMemory` before anything is proven or committed;
    /// provider errors for unreadable storage, never converted to a shortfall.
    pub(crate) fn require_runtime_capacity(&mut self) -> Result<(), Error> {
        let relations = self.proofs.runtime_capacity()?;
        let required = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: relations
                .storage_bytes
                .checked_add(OPERATION_RESERVATION_BYTES)
                .ok_or(Error::Invalid("runtime capacity bound"))?,
            memory_bytes: relations.memory_bytes,
        };
        let available = self.custody.runtime_resources()?;
        required
            .check(&available)
            .map_err(|shortfall| match shortfall {
                KagemushaWalletCapacityShortfallV1::Storage => Error::NotEnoughStorage,
                KagemushaWalletCapacityShortfallV1::Memory => Error::NotEnoughMemory,
            })
    }
}
