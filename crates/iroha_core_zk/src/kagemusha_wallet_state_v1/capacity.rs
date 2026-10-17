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

// Additional logical serialized growth after the fixed Bound publication. The fresh
// probe already accounts for that earlier publication. This includes two new recovery
// copies, two copies of every promoted object with its archive envelope, the request /
// plan copies not already charged by OPERATION_RESERVATION_BYTES, and one index update.
// Eight bounded provider pages conservatively cover manifest / marker / anchor records.
// This is an admission bound, not an exclusive filesystem reservation; later provider
// resource changes and filesystem allocation overhead retain their real error semantics.
pub(super) const INTAKE_STORAGE_RESERVATION_BYTES: u64 = {
    let envelope = archive::METADATA_BOUND as u64;
    let batch = lifecycle::INTAKE_BATCH_BYTES as u64;
    let originals =
        lifecycle::INTAKE_DRAFT_BYTES as u64 + lifecycle::INTAKE_DRAFT_OBJECTS as u64 * envelope;
    let publication = 2 * 258 * (index::INDEX_VALUE_LIMIT as u64 + 2 * envelope) + 8 * 4096;
    OPERATION_RESERVATION_BYTES
        + 2 * (batch + envelope)
        + 2 * originals
        + REQUEST_MAX_BYTES as u64
        + PLAN_BOUND as u64
        + 4 * envelope
        + publication
};

// Conservative logical requested-byte allowance, independent of proving memory:
// recovery decoding can hold its input, clearing payload copies outside Norito's
// allocation counter, and up to two batch bounds of codec-managed allocation.
// Redundant archive reads separately hold the first content while decoding the
// second envelope. Six enveloped batch bounds cover these peaks and put encoding;
// put drops copied content before comparing an existing frame, and the coordinator
// drops its encoded recovery frame before materialization. Extra item metadata,
// two request/plan owner bounds and fixed codec scratch are charged explicitly.
// This is not an allocator-capacity/RSS bound and reserves no allocator or OS pages.
pub(super) const INTAKE_MEMORY_RESERVATION_BYTES: u64 = 6
    * (lifecycle::INTAKE_BATCH_BYTES as u64 + archive::METADATA_BOUND as u64)
    + 256 * lifecycle::INTAKE_DRAFT_OBJECTS as u64
    + 2 * (REQUEST_MAX_BYTES as u64 + PLAN_BOUND as u64)
    + 64 * 1024;

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Admit the bounded intake workspace and its redundant recovery batch before allocating
    /// variable draft data. The batch is gone before proving; this conservative bound still
    /// covers native source validation and all guarded envelope copies simultaneously.
    pub(super) fn require_intake_capacity(&mut self) -> Result<(), Error> {
        let relations = self.proofs.runtime_capacity()?;
        let required = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: relations
                .storage_bytes
                .checked_add(INTAKE_STORAGE_RESERVATION_BYTES)
                .ok_or(Error::Invalid("intake storage bound"))?,
            memory_bytes: relations
                .memory_bytes
                .checked_add(INTAKE_MEMORY_RESERVATION_BYTES)
                .ok_or(Error::Invalid("intake memory bound"))?,
        };
        required
            .check(&self.custody.runtime_resources()?)
            .map_err(|shortfall| match shortfall {
                KagemushaWalletCapacityShortfallV1::Storage => Error::NotEnoughStorage,
                KagemushaWalletCapacityShortfallV1::Memory => Error::NotEnoughMemory,
            })
    }

    /// Admit recovery decoding independently of fresh-operation disk reservations.
    /// This precedes any archive read because even a rejected outer frame is private.
    pub(super) fn require_intake_memory(&mut self) -> Result<(), Error> {
        let relations = self.proofs.runtime_capacity()?;
        let required = KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: 0,
            memory_bytes: relations
                .memory_bytes
                .checked_add(INTAKE_MEMORY_RESERVATION_BYTES)
                .ok_or(Error::Invalid("intake memory bound"))?,
        };
        required
            .check(&self.custody.runtime_resources()?)
            .map_err(|shortfall| match shortfall {
                KagemushaWalletCapacityShortfallV1::Storage => Error::NotEnoughStorage,
                KagemushaWalletCapacityShortfallV1::Memory => Error::NotEnoughMemory,
            })
    }

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
