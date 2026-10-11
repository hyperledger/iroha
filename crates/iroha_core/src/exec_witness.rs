//! Guard-owned, per-block execution witness recorder.
//!
//! Records observed reads (pre-values) and writes (post-values) during execution.
//! Keys are encoded deterministically with a tag and ID strings. Values are the
//! canonical JSON strings from `iroha_primitives::json::Json` for metadata maps.
//!
//! This module is internal and accessed from execution/merge paths and the actor.
//! The sparse Merkle tree ([`smt`]) and the witness-to-root projections
//! ([`roots`]) that turn a drained witness into state roots live alongside it.
#[cfg(test)]
use crate::state::{StateBlock, WorldReadOnly};
#[cfg(test)]
use core::str::FromStr as _;
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    execution_witness::ExecutionWitnessKeyTagV1,
    nft::NftId,
};
use iroha_data_model::{
    block::consensus::{ExecKv, ExecWitness},
    fastpq::{TransferTranscript, TransferTranscriptBundle},
};
#[cfg(test)]
use iroha_model_base::domain::DomainId;
#[cfg(test)]
use iroha_model_base::name::Name;
#[cfg(test)]
use iroha_primitives::{json::Json, numeric::Quantity};
#[cfg(test)]
use mv::storage::StorageReadOnly;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};
/// Witness-to-root projections (`parent_state_root`, `post_state_root`).
pub(crate) mod roots;
/// Deterministic sparse Merkle tree over witnessed key/value pairs.
pub(crate) mod smt;
/// One local capture identity; its strong references prevent reuse while an old overlay exists.
/// This token never enters witness bytes, hashes, logs or protocol identifiers.
struct RecorderGeneration;

/// Non-forgeable local identity of the original active block recorder.
/// It cannot be serialized or reconstructed from a block hash or witness bytes.
#[derive(Clone)]
pub(crate) struct ExecWitnessCaptureIdentity(Arc<RecorderGeneration>);

impl ExecWitnessCaptureIdentity {
    /// Refuse a reset, foreign thread, suppressed scope, or retired recorder.
    pub(crate) fn require_current(&self) -> Result<(), String> {
        if !owns_exec_witness() || witness_recording_suppressed() {
            return Err("execution prefix lost its original recording scope".into());
        }
        let current = lock_slot();
        if !current.active
            || !current
                .generation
                .as_ref()
                .is_some_and(|generation| Arc::ptr_eq(generation, &self.0))
        {
            return Err("execution prefix recorder was reset or retired".into());
        }
        Ok(())
    }
}

/// Capture only an already active, owned, unsuppressed recorder identity.
/// Scratch execution has no recording authority and cannot invent it later.
pub(crate) fn current_exec_witness_capture_identity() -> Option<ExecWitnessCaptureIdentity> {
    if !owns_exec_witness() || witness_recording_suppressed() {
        return None;
    }
    let current = lock_slot();
    current
        .active
        .then(|| {
            current
                .generation
                .as_ref()
                .map(|generation| ExecWitnessCaptureIdentity(Arc::clone(generation)))
        })
        .flatten()
}

#[derive(Default)]
struct BlockWitness {
    active: bool,
    generation: Option<Arc<RecorderGeneration>>,
    reads: BTreeMap<Vec<u8>, Vec<u8>>,  // key -> value (pre)
    writes: BTreeMap<Vec<u8>, Vec<u8>>, // key -> value (post; empty for delete)
    fastpq_transcripts: BTreeMap<Hash, Vec<TransferTranscript>>,
}
#[derive(Default)]
struct WitnessOverlayFrame {
    witness: BlockWitness,
    replaces_fastpq_transcripts: bool,
}
/// Exclusive access guard for the global execution witness recorder.
///
/// Recording and capture mutation belong to the thread holding this guard.
/// Dropping the guard clears any unfinished capture so early validation returns
/// or panics cannot leak stale witness records into the next block.
pub struct ExecWitnessGuard {
    _guard: MutexGuard<'static, ()>,
}
impl Drop for ExecWitnessGuard {
    fn drop(&mut self) {
        clear_block();
        EXEC_WITNESS_OWNER.with(|owner| owner.set(false));
    }
}
static SLOT: OnceLock<Mutex<BlockWitness>> = OnceLock::new();
static EXEC_WITNESS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
thread_local! {
    // ExecWitnessGuard is !Send and serializes ownership. Only its thread may mutate SLOT;
    // detached execution workers return their results for application on that thread.
    static EXEC_WITNESS_OWNER: Cell<bool> = const { Cell::new(false) };
    static WITNESS_RECORDING_SUPPRESSION_DEPTH: Cell<u32> = const { Cell::new(0) };
    static EXEC_WITNESS_OVERLAYS: RefCell<Vec<WitnessOverlayFrame>> = const { RefCell::new(Vec::new()) };
}
/// Transaction-local execution-witness overlay.
///
/// Records emitted on the creating thread remain private until [`Self::commit`]
/// is called. Dropping the guard without committing discards reads, writes, and
/// FASTPQ transcripts recorded since the overlay began. Overlays are nestable
/// and must be completed in last-in, first-out order.
#[must_use = "dropping an execution-witness overlay rolls back its records"]
pub(crate) struct ExecWitnessOverlay {
    depth: usize,
    finished: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}
impl ExecWitnessOverlay {
    /// Merge this overlay into its parent overlay or the active block witness.
    pub(crate) fn commit(mut self) {
        self.finish(true);
    }
    fn finish(&mut self, commit: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let commit = commit && owns_exec_witness() && !witness_recording_suppressed();
        // Commit follows the same SLOT -> TLS order as recording and overlay creation.
        // Rollback only pops TLS and cannot publish into any capture generation.
        let mut witness = commit.then(lock_slot);
        let frame_for_block = EXEC_WITNESS_OVERLAYS.with(|overlays| {
            let mut overlays = overlays.borrow_mut();
            assert_eq!(
                overlays.len(),
                self.depth,
                "execution-witness overlays must be completed in last-in, first-out order"
            );
            let frame = overlays
                .pop()
                .expect("execution-witness overlay stack must contain the active guard");
            let Some(witness) = witness.as_deref() else {
                return None;
            };
            if !witness.active || !same_recorder_generation(witness, &frame.witness) {
                return None;
            }
            if let Some(parent) = overlays.last_mut() {
                merge_overlay_frame(parent, frame);
                None
            } else {
                Some(frame)
            }
        });
        if let Some(frame) = frame_for_block {
            merge_overlay_into_witness(
                witness
                    .as_deref_mut()
                    .expect("committing overlay must hold SLOT"),
                frame,
            );
        }
    }
}
impl Drop for ExecWitnessOverlay {
    fn drop(&mut self) {
        self.finish(false);
    }
}
/// Current-thread guard that prevents speculative execution from writing the global recorder.
///
/// The marker deliberately makes this guard `!Send` and `!Sync`: its nesting depth belongs to the
/// thread on which it was created and must be decremented on that same thread.
pub(crate) struct WitnessRecordingSuppressionGuard {
    _not_send_or_sync: PhantomData<Rc<()>>,
}
impl Drop for WitnessRecordingSuppressionGuard {
    fn drop(&mut self) {
        WITNESS_RECORDING_SUPPRESSION_DEPTH.with(|depth| {
            depth.set(
                depth
                    .get()
                    .checked_sub(1)
                    .expect("witness-recording suppression depth underflow"),
            );
        });
    }
}
fn witness_recording_suppressed() -> bool {
    WITNESS_RECORDING_SUPPRESSION_DEPTH.with(|depth| depth.get() != 0)
}
fn owns_exec_witness() -> bool {
    EXEC_WITNESS_OWNER.with(Cell::get)
}
/// Absent identities never match, including two overlays opened outside a capture.
fn same_recorder_generation(left: &BlockWitness, right: &BlockWitness) -> bool {
    match (&left.generation, &right.generation) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

fn merge_witness_records(
    target: &mut BlockWitness,
    source: BlockWitness,
    replaces_fastpq_transcripts: bool,
) -> bool {
    if !same_recorder_generation(target, &source) {
        return false;
    }
    for (key, value) in source.reads {
        target.reads.entry(key).or_insert(value);
    }
    target.writes.extend(source.writes);
    if replaces_fastpq_transcripts {
        target.fastpq_transcripts = source.fastpq_transcripts;
    } else {
        for (batch_hash, mut transcripts) in source.fastpq_transcripts {
            target
                .fastpq_transcripts
                .entry(batch_hash)
                .or_default()
                .append(&mut transcripts);
        }
    }
    true
}
fn merge_overlay_frame(target: &mut WitnessOverlayFrame, source: WitnessOverlayFrame) {
    let replaces_fastpq_transcripts = source.replaces_fastpq_transcripts;
    if merge_witness_records(
        &mut target.witness,
        source.witness,
        replaces_fastpq_transcripts,
    ) {
        target.replaces_fastpq_transcripts |= replaces_fastpq_transcripts;
    }
}
fn merge_overlay_into_witness(target: &mut BlockWitness, source: WitnessOverlayFrame) {
    if target.active {
        merge_witness_records(target, source.witness, source.replaces_fastpq_transcripts);
    }
}
/// Begin a transaction-local execution-witness overlay on the current thread.
///
/// Records are merged into the active block witness only after
/// [`ExecWitnessOverlay::commit`]. Dropping the returned guard rolls them back.
/// Only the guard-owning thread can acquire the capture identity. Unrelated execution
/// gets an unbound overlay and cannot publish into another block's recorder.
/// An overlay keeps the capture identity present at creation. Nested overlays inherit
/// their parent's identity even when it is absent or stale; they never bind to a later block.
pub(crate) fn begin_exec_witness_overlay() -> ExecWitnessOverlay {
    let witness = lock_slot();
    let depth = EXEC_WITNESS_OVERLAYS.with(|overlays| {
        let mut overlays = overlays.borrow_mut();
        let generation = if let Some(parent) = overlays.last() {
            parent.witness.generation.clone()
        } else if owns_exec_witness() && witness.active {
            witness.generation.clone()
        } else {
            None
        };
        overlays.push(WitnessOverlayFrame {
            witness: BlockWitness {
                generation,
                ..BlockWitness::default()
            },
            replaces_fastpq_transcripts: false,
        });
        overlays.len()
    });
    ExecWitnessOverlay {
        depth,
        finished: false,
        _not_send_or_sync: PhantomData,
    }
}
/// Suppress writes to the process-global witness recorder on the current thread.
///
/// Autonomous merge pre-execution captures its evidence in the `StateBlock` overlay and runs
/// before any legitimate block witness window. Suppression prevents that speculative work from
/// contaminating a witness window owned by another in-process `State` instance.
pub(crate) fn suppress_recording_for_current_thread() -> WitnessRecordingSuppressionGuard {
    WITNESS_RECORDING_SUPPRESSION_DEPTH.with(|depth| {
        depth.set(
            depth
                .get()
                .checked_add(1)
                .expect("witness-recording suppression depth overflow"),
        );
    });
    WitnessRecordingSuppressionGuard {
        _not_send_or_sync: PhantomData,
    }
}
fn slot() -> &'static Mutex<BlockWitness> {
    SLOT.get_or_init(|| Mutex::new(BlockWitness::default()))
}
fn exec_witness_lock() -> &'static Mutex<()> {
    EXEC_WITNESS_LOCK.get_or_init(|| Mutex::new(()))
}
fn lock_slot() -> MutexGuard<'static, BlockWitness> {
    match slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            iroha_logger::warn!(
                "execution witness recorder mutex was poisoned; recovering block witness state"
            );
            poisoned.into_inner()
        }
    }
}
fn lock_exec_witness_lock() -> MutexGuard<'static, ()> {
    match exec_witness_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            iroha_logger::warn!(
                "execution witness guard mutex was poisoned; recovering exclusive witness access"
            );
            poisoned.into_inner()
        }
    }
}
fn with_active_slot(f: impl FnOnce(&mut BlockWitness)) {
    if !owns_exec_witness() || witness_recording_suppressed() {
        return;
    }
    let mut g = lock_slot();
    if !g.active {
        return;
    }
    let mut f = Some(f);
    let recorded_in_overlay = EXEC_WITNESS_OVERLAYS.with(|overlays| {
        let mut overlays = overlays.borrow_mut();
        let Some(overlay) = overlays.last_mut() else {
            return false;
        };
        if same_recorder_generation(&g, &overlay.witness) {
            f.take()
                .expect("witness recorder closure must be available")(
                &mut overlay.witness
            );
        }
        // A stale overlay consumes this operation. It must never fall through to the global slot.
        true
    });
    if !recorded_in_overlay {
        f.expect("witness recorder closure must be available")(&mut g);
    }
}
fn clear_block() {
    if !owns_exec_witness() {
        return;
    }
    let mut g = lock_slot();
    g.active = false;
    g.generation = None;
    g.reads.clear();
    g.writes.clear();
    g.fastpq_transcripts.clear();
}
/// Hold exclusive access to the global witness recorder for the duration of a block execution.
///
/// Only this guard's thread may record, synchronize or mutate the capture lifecycle.
/// Execution workers return detached results for application by the owner; they cannot
/// attach to a capture by observing that the process-global recorder is active.
/// Generation checks additionally reject stale overlays on the owning thread.
pub fn exec_witness_guard() -> ExecWitnessGuard {
    let guard = ExecWitnessGuard {
        _guard: lock_exec_witness_lock(),
    };
    EXEC_WITNESS_OWNER.with(|owner| owner.set(true));
    guard
}

/// Start one capture after the caller has acquired its State writers.
/// Reentrant or suppressed execution is refused without resetting an existing
/// recorder or waiting for the caller's own non-reentrant recorder lock.
pub(crate) fn begin_exec_witness_capture() -> Result<ExecWitnessGuard, String> {
    ensure_exec_witness_capture_available()?;
    let guard = exec_witness_guard();
    start_block();
    Ok(guard)
}

/// Check only thread-local capture eligibility, before acquiring State writers.
/// The caller must still acquire its recorder after those writers. Checking both
/// boundaries avoids reentrant State/recorder inversion without reserving a lock.
pub(crate) fn ensure_exec_witness_capture_available() -> Result<(), String> {
    ensure_state_access_without_exec_witness()?;
    if witness_recording_suppressed() {
        return Err("execution witness capture cannot begin in a suppressed scope".into());
    }
    if EXEC_WITNESS_OVERLAYS.with(|overlays| !overlays.borrow().is_empty()) {
        return Err("execution witness capture cannot begin with a pending overlay".into());
    }
    Ok(())
}

/// Refuse a State read or writer acquisition while this thread owns the recorder.
/// Another execution may already own that State and be waiting for the recorder;
/// suppression prevents recording but cannot break that lock-order cycle.
/// This check is thread-local and acquires no lock. Suppression alone is allowed.
pub(crate) fn ensure_state_access_without_exec_witness() -> Result<(), String> {
    if owns_exec_witness() {
        return Err("execution witness capture already belongs to this thread; acquire State before the recorder".into());
    }
    Ok(())
}
/// Start a new witness capture for the guard-owning thread (clears previous data).
/// Calls without the exclusive guard leave the recorder untouched.
pub fn start_block() {
    if !owns_exec_witness() {
        return;
    }
    let mut g = lock_slot();
    g.active = true;
    g.generation = Some(Arc::new(RecorderGeneration));
    g.reads.clear();
    g.writes.clear();
    g.fastpq_transcripts.clear();
}
/// Drain the accumulated witness into an `ExecWitness` and clear the store.
/// Calls without the exclusive guard return an empty witness without touching the recorder.
pub fn drain_exec_witness() -> ExecWitness {
    if !owns_exec_witness() {
        return ExecWitness::default();
    }
    let mut g = lock_slot();
    let mut reads: Vec<ExecKv> = Vec::with_capacity(g.reads.len());
    let mut writes: Vec<ExecKv> = Vec::with_capacity(g.writes.len());
    for (k, v) in &g.reads {
        reads.push(ExecKv {
            key: k.clone(),
            value: v.clone(),
        });
    }
    for (k, v) in &g.writes {
        writes.push(ExecKv {
            key: k.clone(),
            value: v.clone(),
        });
    }
    g.reads.clear();
    g.writes.clear();
    g.active = false;
    g.generation = None;
    let mut fastpq_map = std::mem::take(&mut g.fastpq_transcripts);
    crate::fastpq::finalize_transfer_transcript_digests_in_map(&mut fastpq_map);
    let fastpq_transcripts = map_to_bundles(fastpq_map);
    ExecWitness {
        reads,
        writes,
        fastpq_transcripts,
        fastpq_batches: Vec::new(),
    }
}
/// Reset a checked capture while SLOT is still held, including validator unwinding.
struct CheckedCaptureReset<'a> {
    witness: &'a mut BlockWitness,
}
impl Drop for CheckedCaptureReset<'_> {
    fn drop(&mut self) {
        *self.witness = BlockWitness::default();
    }
}

/// Drain only the exact ordinary witness content accepted by its execution owner.
///
/// This is a first-capture operation and requires an active global recorder.
/// Call while holding [`ExecWitnessGuard`] after execution workers and their
/// overlays have completed. The validator borrows the raw transcript map under
/// the recorder lock before any digest repair or read/write copying. It must not
/// call recorder APIs, which acquire that same lock. Accepted digest options,
/// transcript grouping/order and private paths are preserved without repair.
///
/// Any current-thread overlay is rejected, including an empty one. Rejection
/// clears and deactivates the global recorder directly while holding its lock.
/// Unwinding from the validator also resets the recorder before unlocking, even if
/// an outer caller catches the panic while retaining its exclusive execution guard.
/// Overlay guards remain intact so their normal last-in, first-out cleanup works.
/// Finish or drop every outstanding owner-thread overlay before starting another capture.
/// Unrelated threads cannot acquire or mutate this capture's generation.
///
/// # Errors
/// Rejects calls without the exclusive guard without touching its owner's recorder.
/// Otherwise returns the validator's error unchanged, or rejects an inactive recorder or
/// pending current-thread overlay before invoking the validator. Rejected records
/// cannot be drained or extended until a new block capture is started.
pub(crate) fn drain_exec_witness_checked(
    validate: impl FnOnce(&BTreeMap<Hash, Vec<TransferTranscript>>) -> Result<(), String>,
) -> Result<ExecWitness, String> {
    if !owns_exec_witness() {
        return Err("ordinary witness capture requires the execution-witness guard".to_owned());
    }
    let mut g = lock_slot();
    let record = {
        // This borrow drops before the mutex guard. It also clears a capture when the
        // validator unwinds and an outer caller catches that panic without dropping its
        // exclusive execution guard. A stale overlay keeps only its invalidated token.
        let reset = CheckedCaptureReset { witness: &mut g };
        if EXEC_WITNESS_OVERLAYS.with(|overlays| !overlays.borrow().is_empty()) {
            return Err("ordinary witness capture has a pending current-thread overlay".to_owned());
        }
        if !reset.witness.active {
            return Err("ordinary witness capture has no active global recorder".to_owned());
        }
        validate(&reset.witness.fastpq_transcripts)?;
        std::mem::take(&mut *reset.witness)
    };
    let reads = record
        .reads
        .into_iter()
        .map(|(key, value)| ExecKv { key, value })
        .collect();
    let writes = record
        .writes
        .into_iter()
        .map(|(key, value)| ExecKv { key, value })
        .collect();
    let fastpq_transcripts = map_to_bundles(record.fastpq_transcripts);
    Ok(ExecWitness {
        reads,
        writes,
        fastpq_transcripts,
        fastpq_batches: Vec::new(),
    })
}

/// Confirm that an already-captured witness has no later recorder activity.
///
/// Call after independently checking the retained witness content and ownership.
/// An intact cached capture has an inactive recorder with no reads, writes,
/// FASTPQ transcripts or current-thread overlays. Any other state is discarded
/// and deactivated directly under the same recorder lock. This does not perform
/// another first capture or repair any transcript digest.
///
/// # Errors
/// Rejects calls without the exclusive guard without touching its owner's recorder.
/// Otherwise rejects an active recorder, unexpected records or a pending current-thread
/// overlay. Overlay guards must finish before the caller starts another capture.
pub(crate) fn finish_cached_exec_witness_capture() -> Result<(), String> {
    if !owns_exec_witness() {
        return Err("cached witness capture requires the execution-witness guard".to_owned());
    }
    let mut g = lock_slot();
    let error = if EXEC_WITNESS_OVERLAYS.with(|overlays| !overlays.borrow().is_empty()) {
        Some("cached witness capture has a pending current-thread overlay")
    } else if g.active {
        Some("cached witness capture has an unexpected active global recorder")
    } else if !g.reads.is_empty() || !g.writes.is_empty() || !g.fastpq_transcripts.is_empty() {
        Some("cached witness capture has unexpected recorder contents")
    } else {
        None
    };
    if let Some(error) = error {
        *g = BlockWitness::default();
        return Err(error.to_owned());
    }
    Ok(())
}

fn map_to_bundles(map: BTreeMap<Hash, Vec<TransferTranscript>>) -> Vec<TransferTranscriptBundle> {
    map.into_iter()
        .map(|(entry_hash, transcripts)| TransferTranscriptBundle {
            entry_hash,
            transcripts,
        })
        .collect()
}
#[cfg(any(test, feature = "telemetry"))]
fn map_ref_to_bundles(
    map: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> Vec<TransferTranscriptBundle> {
    map.iter()
        .map(|(entry_hash, transcripts)| TransferTranscriptBundle {
            entry_hash: *entry_hash,
            transcripts: transcripts.clone(),
        })
        .collect()
}
#[cfg(test)]
fn key_sep() -> u8 {
    0x1F // Unit Separator
}
#[cfg(test)]
fn enc_key_prefix(tag: ExecutionWitnessKeyTagV1, a: &str, b: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + a.len() + 1 + b.len());
    out.push(tag as u8);
    out.extend_from_slice(a.as_bytes());
    out.push(key_sep());
    out.extend_from_slice(b.as_bytes());
    out
}
#[cfg(test)]
fn key_account_kv(id: &AccountId, key: &Name) -> Vec<u8> {
    enc_key_prefix(
        ExecutionWitnessKeyTagV1::AccountMetadata,
        &id.to_string(),
        key.as_ref(),
    )
}
#[cfg(test)]
fn key_domain_kv(id: &DomainId, key: &Name) -> Vec<u8> {
    enc_key_prefix(
        ExecutionWitnessKeyTagV1::DomainMetadata,
        &id.to_string(),
        key.as_ref(),
    )
}
#[cfg(test)]
fn key_nft_kv(id: &NftId, key: &Name) -> Vec<u8> {
    enc_key_prefix(
        ExecutionWitnessKeyTagV1::NftMetadata,
        &id.to_string(),
        key.as_ref(),
    )
}
#[cfg(test)]
fn key_asset_def_kv(id: &AssetDefinitionId, key: &Name) -> Vec<u8> {
    enc_key_prefix(
        ExecutionWitnessKeyTagV1::AssetDefinitionMetadata,
        &id.to_string(),
        key.as_ref(),
    )
}
#[cfg(test)]
fn key_asset_balance(id: &AssetId) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + id.to_string().len());
    out.push(ExecutionWitnessKeyTagV1::AssetBalance as u8);
    out.extend_from_slice(id.to_string().as_bytes());
    out
}
#[cfg(test)]
fn key_asset_def_total(id: &AssetDefinitionId) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + id.to_string().len());
    out.push(ExecutionWitnessKeyTagV1::AssetDefinitionTotalSupply as u8);
    out.extend_from_slice(id.to_string().as_bytes());
    out
}
#[cfg(test)]
fn bytes_from_json(j: &iroha_primitives::json::Json) -> Vec<u8> {
    j.get().as_bytes().to_vec()
}
#[cfg(test)]
/// Record a read (pre-value) of account metadata.
pub fn record_read_account_kv(
    id: &AccountId,
    key: &Name,
    val: Option<&iroha_primitives::json::Json>,
) {
    let k = key_account_kv(id, key);
    let v = val.map(bytes_from_json).unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Record a write (post-value) of account metadata.
pub fn record_write_account_kv(id: &AccountId, key: &Name, val: &iroha_primitives::json::Json) {
    let k = key_account_kv(id, key);
    let v = bytes_from_json(val);
    with_active_slot(|g| {
        g.writes.insert(k, v);
    });
}
#[cfg(test)]
/// Record a delete (post empty) of account metadata, with read pre-value supplied.
pub fn record_delete_account_kv(id: &AccountId, key: &Name, pre: &iroha_primitives::json::Json) {
    let k = key_account_kv(id, key);
    with_active_slot(|g| {
        g.reads
            .entry(k.clone())
            .or_insert_with(|| bytes_from_json(pre));
        g.writes.insert(k, Vec::new());
    });
}
#[cfg(test)]
/// Record a read (pre-value) of domain metadata.
pub fn record_read_domain_kv(
    id: &DomainId,
    key: &Name,
    val: Option<&iroha_primitives::json::Json>,
) {
    let k = key_domain_kv(id, key);
    let v = val.map(bytes_from_json).unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Record a read (pre-value) of NFT metadata.
pub fn record_read_nft_kv(id: &NftId, key: &Name, val: Option<&iroha_primitives::json::Json>) {
    let k = key_nft_kv(id, key);
    let v = val.map(bytes_from_json).unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Record asset balance read (pre-value) for an asset.
pub fn record_read_asset(id: &AssetId, val: Option<&Quantity>) {
    let k = key_asset_balance(id);
    let v = val
        .map(|n| Json::new(n.clone()).get().as_bytes().to_vec())
        .unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Record asset balance write (post-value) for an asset.
pub fn record_write_asset(id: &AssetId, val: &Quantity) {
    let k = key_asset_balance(id);
    let v = Json::new(val.clone()).get().as_bytes().to_vec();
    with_active_slot(|g| {
        g.writes.insert(k, v);
    });
}
#[cfg(test)]
/// Record asset definition total supply read (pre-value).
pub fn record_read_asset_def_total(id: &AssetDefinitionId, val: Option<&Quantity>) {
    let k = key_asset_def_total(id);
    let v = val
        .map(|n| Json::new(n.clone()).get().as_bytes().to_vec())
        .unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Record asset definition total supply write (post-value).
pub fn record_write_asset_def_total(id: &AssetDefinitionId, val: &Quantity) {
    let k = key_asset_def_total(id);
    let v = Json::new(val.clone()).get().as_bytes().to_vec();
    with_active_slot(|g| {
        g.writes.insert(k, v);
    });
}
/// Record the write of one AMX record (`specs/sumeragi.md` §11) under its reserved key, so the
/// block's ordinary-write root commits it for record proofs.
pub(crate) fn record_write_amx_record(
    record: &iroha_data_model::sumeragi_amx::AmxRecordV1,
) -> Result<(), iroha_data_model::sumeragi_amx::AmxError> {
    let key = record.witness_key().to_vec();
    let value = record.witness_value()?;
    with_active_slot(|witness| {
        witness.writes.insert(key, value);
    });
    Ok(())
}
/// Commit a public private-root registration/cursor under its domain-separated proof key.
pub(crate) fn record_write_private_dataspace(
    record: &iroha_data_model::private_dataspace::PrivateDataspaceRecord,
) -> Result<(), norito::Error> {
    let key = record.witness_key();
    let value = norito::encode_canonical(record)?;
    with_active_slot(|witness| {
        witness.writes.insert(key, value);
    });
    Ok(())
}
/// Record a FASTPQ transfer transcript so `ExecWitness` consumers can replay transfers.
pub fn record_fastpq_transcript(transcript: &TransferTranscript) {
    with_active_slot(|g| {
        g.fastpq_transcripts
            .entry(transcript.batch_hash)
            .or_default()
            .push(transcript.clone());
    });
}
/// Replace speculative FASTPQ transcripts with the transactionally finalized block set.
///
/// Transfer execution records into this process-global witness before the surrounding
/// [`StateTransaction`](crate::state::StateTransaction) commits. A later instruction can still
/// reject that transaction, so the global copy is not authoritative. The block-local map is
/// updated only by `StateTransaction::apply`; copying it wholesale here both installs finalized
/// digests and removes transcripts from rolled-back transactions. When an execution-witness
/// overlay is active, the replacement remains private until the overlay commits.
/// Only the guard-owning thread may synchronize; draining another `StateBlock` on an
/// unrelated thread cannot replace this capture's finalized transcript inventory.
pub(crate) fn synchronize_fastpq_transcripts(finalized: &BTreeMap<Hash, Vec<TransferTranscript>>) {
    if !owns_exec_witness() || witness_recording_suppressed() {
        return;
    }
    let mut witness = lock_slot();
    if !witness.active {
        return;
    }
    let synchronized_overlay = EXEC_WITNESS_OVERLAYS.with(|overlays| {
        let mut overlays = overlays.borrow_mut();
        let Some(overlay) = overlays.last_mut() else {
            return false;
        };
        if same_recorder_generation(&witness, &overlay.witness) {
            overlay.witness.fastpq_transcripts.clone_from(finalized);
            overlay.replaces_fastpq_transcripts = true;
        }
        // Discard stale replacement, including an empty map, without a global fallback.
        true
    });
    if !synchronized_overlay {
        witness.fastpq_transcripts.clone_from(finalized);
    }
}
#[cfg(test)]
/// Record a read (pre-value) of asset-definition metadata.
pub fn record_read_asset_def_kv(
    id: &AssetDefinitionId,
    key: &Name,
    val: Option<&iroha_primitives::json::Json>,
) {
    let k = key_asset_def_kv(id, key);
    let v = val.map(bytes_from_json).unwrap_or_default();
    with_active_slot(|g| {
        g.reads.entry(k).or_insert(v);
    });
}
#[cfg(test)]
/// Parse an access key string and record a pure read (if supported).
/// Currently supports only metadata detail keys:
/// - `account.detail:{account_id}:{key}`
/// - `domain.detail:{domain_id}:{key}`
/// - `asset_def.detail:{asset_def_id}:{key}`
/// - `nft.detail:{nft_id}:{key}`
///   Other keys are ignored.
#[allow(clippy::too_many_lines)]
pub fn record_read_from_access_key(state_block: &StateBlock<'_>, access_key: &str) {
    if let Some(rest) = access_key.strip_prefix("account.detail:") {
        let mut it = rest.splitn(2, ':');
        if let (Some(acc_s), Some(name_s)) = (it.next(), it.next()) {
            if let (Ok(acc), Ok(name)) = (
                iroha_data_model::account::AccountId::parse_encoded(acc_s),
                Name::from_str(name_s),
            ) {
                if let Ok(acct) = state_block.world.account(&acc) {
                    let pre = acct.value().metadata().get(&name).cloned();
                    record_read_account_kv(&acc, &name, pre.as_ref());
                } else {
                    record_read_account_kv(&acc, &name, None);
                }
            }
        }
    }
    if let Some(rest) = access_key.strip_prefix("domain.detail:") {
        let mut it = rest.splitn(2, ':');
        if let (Some(dom_s), Some(name_s)) = (it.next(), it.next()) {
            if let (Ok(dom), Ok(name)) = (
                iroha_model_base::domain::DomainId::parse_fully_qualified(dom_s),
                Name::from_str(name_s),
            ) {
                if let Ok(domv) = state_block.world.domain(&dom) {
                    let pre = domv.metadata.get(&name).cloned();
                    record_read_domain_kv(&dom, &name, pre.as_ref());
                } else {
                    record_read_domain_kv(&dom, &name, None);
                }
            }
        }
    }
    if let Some(rest) = access_key.strip_prefix("asset_def.detail:") {
        let mut it = rest.splitn(2, ':');
        if let (Some(ad_s), Some(name_s)) = (it.next(), it.next()) {
            if let (Ok(ad), Ok(name)) = (
                iroha_data_model::asset::AssetDefinitionId::parse_address_literal(ad_s),
                Name::from_str(name_s),
            ) {
                if let Ok(def) = state_block.world.asset_definition(&ad) {
                    let pre = def.metadata.get(&name).cloned();
                    record_read_asset_def_kv(&ad, &name, pre.as_ref());
                } else {
                    record_read_asset_def_kv(&ad, &name, None);
                }
            }
        }
    }
    if let Some(rest) = access_key.strip_prefix("nft.detail:") {
        let mut it = rest.splitn(2, ':');
        if let (Some(nft_s), Some(name_s)) = (it.next(), it.next()) {
            if let (Ok(nft), Ok(name)) = (
                iroha_data_model::nft::NftId::from_str(nft_s),
                Name::from_str(name_s),
            ) {
                if let Ok(nftv) = state_block.world.nft(&nft) {
                    let pre = nftv.content.get(&name).cloned();
                    record_read_nft_kv(&nft, &name, pre.as_ref());
                } else {
                    record_read_nft_kv(&nft, &name, None);
                }
            }
        }
    }
    if let Some(rest) = access_key.strip_prefix("role.binding:") {
        // role.binding:{account}:{role}
        let mut it = rest.splitn(2, ':');
        if let (Some(acc_s), Some(role_s)) = (it.next(), it.next()) {
            if let (Ok(acc), Ok(role)) = (
                iroha_data_model::account::AccountId::parse_encoded(acc_s),
                iroha_data_model::role::RoleId::from_str(role_s),
            ) {
                let present = state_block
                    .world
                    .account_roles_iter(&acc)
                    .any(|r| r == &role);
                let k = enc_key_prefix(
                    ExecutionWitnessKeyTagV1::AccountRoleBinding,
                    &acc.to_string(),
                    &role.to_string(),
                );
                let v = Json::new(present).get().as_bytes().to_vec();
                with_active_slot(|g| {
                    g.reads.entry(k).or_insert(v);
                });
            }
        }
    }
    if let Some(rest) = access_key.strip_prefix("role:") {
        if let Ok(role) = iroha_data_model::role::RoleId::from_str(rest) {
            let present = state_block.world.roles().get(&role).is_some();
            let mut out = Vec::with_capacity(1 + rest.len());
            out.push(ExecutionWitnessKeyTagV1::Role as u8);
            out.extend_from_slice(rest.as_bytes());
            let v = Json::new(present).get().as_bytes().to_vec();
            with_active_slot(|g| {
                g.reads.entry(out).or_insert(v);
            });
        }
    }
    if let Some(rest) = access_key.strip_prefix("perm.account:") {
        // perm.account:{account}:{perm}
        let mut it = rest.splitn(2, ':');
        if let (Some(acc_s), Some(perm_s)) = (it.next(), it.next())
            && let Ok(acc) = iroha_data_model::account::AccountId::parse_encoded(acc_s)
        {
            let present = state_block
                .world
                .account_permissions_iter(&acc)
                .ok()
                .is_some_and(|mut it| it.any(|p| p.name() == perm_s));
            let canonical_account = acc.to_string();
            let k = enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountPermission,
                &canonical_account,
                perm_s,
            );
            let v = Json::new(present).get().as_bytes().to_vec();
            with_active_slot(|g| {
                g.reads.entry(k).or_insert(v);
            });
        }
    }
    if let Some(rest) = access_key.strip_prefix("perm.role:") {
        // perm.role:{role}:{perm}
        let mut it = rest.splitn(2, ':');
        if let (Some(role_s), Some(perm_s)) = (it.next(), it.next())
            && let Ok(role_id) = iroha_data_model::role::RoleId::from_str(role_s)
        {
            let present = state_block
                .world
                .role(&role_id)
                .ok()
                .is_some_and(|r| r.permissions().any(|p| p.name() == perm_s));
            let k = enc_key_prefix(ExecutionWitnessKeyTagV1::RolePermission, role_s, perm_s);
            let v = Json::new(present).get().as_bytes().to_vec();
            with_active_slot(|g| {
                g.reads.entry(k).or_insert(v);
            });
        }
    }
    if let Some(rest) = access_key.strip_prefix("asset:")
        && let Ok(id) = iroha_data_model::asset::AssetId::parse_literal(rest)
    {
        let pre = state_block.world.assets().get(&id).map(|v| v.as_ref());
        record_read_asset(&id, pre);
        // no further processing needed for asset access
    }
    if let Some(rest) = access_key.strip_prefix("asset_def:")
        && let Ok(ad) = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(rest)
    {
        if let Ok(def) = state_block.world.asset_definition(&ad) {
            record_read_asset_def_total(&ad, Some(def.total_quantity()));
        } else {
            record_read_asset_def_total(&ad, None);
        }
        // no further processing needed for asset_def access
    }
}
#[cfg(any(test, feature = "telemetry"))]
/// Snapshot the current witness without clearing it (for debugging/inspection).
pub fn snapshot_exec_witness() -> ExecWitness {
    let g = lock_slot();
    let mut reads: Vec<ExecKv> = Vec::with_capacity(g.reads.len());
    let mut writes: Vec<ExecKv> = Vec::with_capacity(g.writes.len());
    for (k, v) in &g.reads {
        reads.push(ExecKv {
            key: k.clone(),
            value: v.clone(),
        });
    }
    for (k, v) in &g.writes {
        writes.push(ExecKv {
            key: k.clone(),
            value: v.clone(),
        });
    }
    let mut fastpq_transcripts = map_ref_to_bundles(&g.fastpq_transcripts);
    crate::fastpq::finalize_transfer_transcript_bundle_digests_in_place(&mut fastpq_transcripts);
    ExecWitness {
        reads,
        writes,
        fastpq_transcripts,
        fastpq_batches: Vec::new(),
    }
}
#[cfg(test)]
mod checked_tests;
#[cfg(test)]
mod generation_tests;
#[cfg(test)]
mod tests {
    use super::smt::{KvPair, compute_post_state_root};
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{Asset, AssetDefinition},
        block::BlockHeader,
        domain::Domain,
        nft::Nft,
        permission::{Permission, Permissions},
        role::{Role, RoleId},
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID};
    use nonzero_ext::nonzero;
    use std::collections::BTreeMap;
    struct AccessKeyFixture {
        state: State,
        account: AccountId,
        missing_account: AccountId,
        domain: DomainId,
        missing_domain: DomainId,
        asset_definition: AssetDefinitionId,
        missing_asset_definition: AssetDefinitionId,
        asset: AssetId,
        missing_asset: AssetId,
        nft: NftId,
        missing_nft: NftId,
        role: RoleId,
        unicode_role_raw: String,
        unicode_role: RoleId,
        account_perm: &'static str,
        role_perm: &'static str,
    }
    fn metadata_entry(key: &str, value: &str) -> Metadata {
        let mut metadata = Metadata::default();
        metadata.insert(key.parse::<Name>().expect("metadata key"), value);
        metadata
    }
    #[allow(clippy::too_many_lines)]
    fn access_key_fixture() -> AccessKeyFixture {
        let account = (*ALICE_ID).clone();
        let missing_account = (*BOB_ID).clone();
        let supply_account = (*CARPENTER_ID).clone();
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        let missing_domain = DomainId::try_new("looking_glass", "universal").expect("domain");
        let asset_definition = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "rose".parse::<Name>().expect("asset definition name"),
        );
        let missing_asset_definition = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "missing_rose"
                .parse::<Name>()
                .expect("missing asset definition name"),
        );
        let asset = AssetId::new(asset_definition.clone(), account.clone());
        let missing_asset = AssetId::new(missing_asset_definition.clone(), account.clone());
        let nft: NftId = "ticket$wonderland.universal".parse().expect("nft id");
        let missing_nft: NftId = "missing_ticket$wonderland.universal"
            .parse()
            .expect("missing nft id");
        let role: RoleId = "auditor".parse().expect("role id");
        let unicode_role_raw = String::from("cafe\u{301}");
        let unicode_role: RoleId = "café".parse().expect("canonical Unicode role id");
        assert!(
            unicode_role_raw.parse::<RoleId>().is_err(),
            "non-NFC role spellings must remain invalid"
        );
        let account_perm = "can_account_read";
        let role_perm = "can_role_read";
        let mut account_metadata = metadata_entry("color", "red");
        account_metadata.insert(
            "color:shade".parse::<Name>().expect("colon metadata key"),
            "maroon",
        );
        let account_record = Account::new(account.clone())
            .with_metadata(account_metadata)
            .build(&account);
        let domain_record = Domain::new(domain.clone())
            .with_metadata(metadata_entry("region", "west"))
            .build(&account);
        let mut asset_definition_record = AssetDefinition::numeric(
            asset_definition.clone(),
            String::from("Rose"),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&account);
        asset_definition_record
            .metadata_mut()
            .insert("issuer".parse::<Name>().expect("metadata key"), "alice");
        let asset_record = Asset::new(asset.clone(), 11_u32);
        // World derives canonical supply from every real balance. Keep the total
        // distinct from the queried account while the missing account stays absent.
        let supply_account_record = Account::new(supply_account.clone()).build(&supply_account);
        let remaining_supply = Asset::new(
            AssetId::new(asset_definition.clone(), supply_account),
            26_u32,
        );
        let nft_record = Nft::new(nft.clone(), metadata_entry("artist", "carroll")).build(&account);
        let role_record = Role::new(role.clone(), account.clone())
            .add_permission(Permission::new(role_perm.into(), Json::new(true)))
            .build(&account);
        let unicode_role_record = Role::new(unicode_role.clone(), account.clone())
            .add_permission(Permission::new(role_perm.into(), Json::new(true)))
            .build(&account);
        let mut world = World::with_assets_and_roles(
            [domain_record],
            [account_record, supply_account_record],
            [asset_definition_record],
            [asset_record, remaining_supply],
            [nft_record],
            [role_record, unicode_role_record],
        );
        world.grant_role_for_tests(account.clone(), role.clone());
        let mut account_permissions = Permissions::new();
        account_permissions.insert(Permission::new(account_perm.into(), Json::new(true)));
        world
            .account_permissions_mut_for_testing()
            .insert(account.clone(), account_permissions);
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        AccessKeyFixture {
            state,
            account,
            missing_account,
            domain,
            missing_domain,
            asset_definition,
            missing_asset_definition,
            asset,
            missing_asset,
            nft,
            missing_nft,
            role,
            unicode_role_raw,
            unicode_role,
            account_perm,
            role_perm,
        }
    }
    fn access_key_header() -> BlockHeader {
        BlockHeader::new(nonzero!(1_u64), None, None, 0, 0)
    }
    fn bool_json_bytes(value: bool) -> Vec<u8> {
        Json::new(value).get().as_bytes().to_vec()
    }
    fn quantity_json_bytes(value: u32) -> Vec<u8> {
        Json::new(Quantity::from(value)).get().as_bytes().to_vec()
    }
    fn assert_read_value(witness: &ExecWitness, key: Vec<u8>, expected: Vec<u8>) {
        let value = witness
            .reads
            .iter()
            .find(|kv| kv.key == key)
            .unwrap_or_else(|| panic!("expected read key {:?}", key))
            .value
            .clone();
        assert_eq!(value, expected);
    }
    fn assert_no_read_key(witness: &ExecWitness, key: Vec<u8>) {
        assert!(
            witness.reads.iter().all(|kv| kv.key != key),
            "unexpected read key {:?}",
            key
        );
    }
    fn sample_fastpq_transcript(seed: u8, batch_hash: Hash) -> (TransferTranscript, Hash) {
        use iroha_data_model::{
            asset::id::AssetDefinitionId,
            fastpq::{TransferDeltaTranscript, TransferTranscript},
        };
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            format!("rose_{seed}").parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(u32::from(seed) + 1),
            from_balance_before: Quantity::from(100u32 + u32::from(seed)),
            from_balance_after: Quantity::from(95u32 + u32::from(seed)),
            to_balance_before: Quantity::from(u32::from(seed)),
            to_balance_after: Quantity::from(5u32 + u32::from(seed)),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let digest = crate::fastpq::poseidon_preimage_digest(&delta, &batch_hash);
        (
            TransferTranscript {
                batch_hash,
                deltas: vec![delta],
                authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
                poseidon_preimage_digest: None,
            },
            digest,
        )
    }
    #[test]
    fn speculative_witness_suppression_is_thread_local_and_nestable() {
        let _guard = exec_witness_guard();
        start_block();
        let retained_hash = Hash::prehashed([0x31; Hash::LENGTH]);
        let suppressed_hash = Hash::prehashed([0x32; Hash::LENGTH]);
        let (retained, _) = sample_fastpq_transcript(1, retained_hash);
        let (suppressed, _) = sample_fastpq_transcript(2, suppressed_hash);
        record_fastpq_transcript(&retained);
        std::thread::spawn(move || {
            assert!(!witness_recording_suppressed());
            let outer = suppress_recording_for_current_thread();
            assert!(witness_recording_suppressed());
            {
                let _inner = suppress_recording_for_current_thread();
                assert!(witness_recording_suppressed());
                record_fastpq_transcript(&suppressed);
            }
            assert!(witness_recording_suppressed());
            drop(outer);
            assert!(!witness_recording_suppressed());
        })
        .join()
        .expect("suppressed witness thread completes");
        let witness = drain_exec_witness();
        assert_eq!(witness.fastpq_transcripts.len(), 1);
        assert_eq!(witness.fastpq_transcripts[0].entry_hash, retained_hash);
        assert!(
            witness
                .fastpq_transcripts
                .iter()
                .all(|bundle| bundle.entry_hash != suppressed_hash)
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn access_key_supported_present_and_missing_reads_match_formal_gate() {
        let fixture = access_key_fixture();
        let state_block = fixture.state.block(access_key_header());
        let guard = exec_witness_guard();
        start_block();
        let color = "color".parse::<Name>().expect("metadata key");
        let region = "region".parse::<Name>().expect("metadata key");
        let issuer = "issuer".parse::<Name>().expect("metadata key");
        let artist = "artist".parse::<Name>().expect("metadata key");
        let missing_role: RoleId = "observer".parse().expect("role id");
        record_read_from_access_key(
            &state_block,
            &format!("account.detail:{}:color", fixture.account),
        );
        record_read_from_access_key(
            &state_block,
            &format!("account.detail:{}:color", fixture.missing_account),
        );
        record_read_from_access_key(
            &state_block,
            &format!("domain.detail:{}:region", fixture.domain),
        );
        record_read_from_access_key(
            &state_block,
            &format!("domain.detail:{}:region", fixture.missing_domain),
        );
        record_read_from_access_key(
            &state_block,
            &format!("asset_def.detail:{}:issuer", fixture.asset_definition),
        );
        record_read_from_access_key(
            &state_block,
            &format!(
                "asset_def.detail:{}:issuer",
                fixture.missing_asset_definition
            ),
        );
        record_read_from_access_key(&state_block, &format!("nft.detail:{}:artist", fixture.nft));
        record_read_from_access_key(
            &state_block,
            &format!("nft.detail:{}:artist", fixture.missing_nft),
        );
        record_read_from_access_key(
            &state_block,
            &format!("role.binding:{}:{}", fixture.account, fixture.role),
        );
        record_read_from_access_key(
            &state_block,
            &format!("role.binding:{}:{}", fixture.account, missing_role),
        );
        record_read_from_access_key(&state_block, &format!("role:{}", fixture.role));
        record_read_from_access_key(&state_block, &format!("role:{missing_role}"));
        record_read_from_access_key(
            &state_block,
            &format!("perm.account:{}:{}", fixture.account, fixture.account_perm),
        );
        record_read_from_access_key(
            &state_block,
            &format!("perm.account:{}:can_missing", fixture.account),
        );
        record_read_from_access_key(
            &state_block,
            &format!("perm.role:{}:{}", fixture.role, fixture.role_perm),
        );
        record_read_from_access_key(
            &state_block,
            &format!("perm.role:{}:can_missing", fixture.role),
        );
        record_read_from_access_key(&state_block, &format!("asset:{}", fixture.asset));
        record_read_from_access_key(&state_block, &format!("asset:{}", fixture.missing_asset));
        record_read_from_access_key(
            &state_block,
            &format!("asset_def:{}", fixture.asset_definition),
        );
        record_read_from_access_key(
            &state_block,
            &format!("asset_def:{}", fixture.missing_asset_definition),
        );
        let witness = drain_exec_witness();
        drop(guard);
        assert_eq!(witness.reads.len(), 20);
        assert!(witness.writes.is_empty());
        assert_read_value(
            &witness,
            key_account_kv(&fixture.account, &color),
            bytes_from_json(&Json::new("red")),
        );
        assert_read_value(
            &witness,
            key_account_kv(&fixture.missing_account, &color),
            Vec::new(),
        );
        assert_read_value(
            &witness,
            key_domain_kv(&fixture.domain, &region),
            bytes_from_json(&Json::new("west")),
        );
        assert_read_value(
            &witness,
            key_domain_kv(&fixture.missing_domain, &region),
            Vec::new(),
        );
        assert_read_value(
            &witness,
            key_asset_def_kv(&fixture.asset_definition, &issuer),
            bytes_from_json(&Json::new("alice")),
        );
        assert_read_value(
            &witness,
            key_asset_def_kv(&fixture.missing_asset_definition, &issuer),
            Vec::new(),
        );
        assert_read_value(
            &witness,
            key_nft_kv(&fixture.nft, &artist),
            bytes_from_json(&Json::new("carroll")),
        );
        assert_read_value(
            &witness,
            key_nft_kv(&fixture.missing_nft, &artist),
            Vec::new(),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountRoleBinding,
                &fixture.account.to_string(),
                &fixture.role.to_string(),
            ),
            bool_json_bytes(true),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountRoleBinding,
                &fixture.account.to_string(),
                &missing_role.to_string(),
            ),
            bool_json_bytes(false),
        );
        let mut present_role_key = vec![0xC2];
        present_role_key.extend_from_slice(fixture.role.to_string().as_bytes());
        assert_read_value(&witness, present_role_key, bool_json_bytes(true));
        let mut missing_role_key = vec![0xC2];
        missing_role_key.extend_from_slice(missing_role.to_string().as_bytes());
        assert_read_value(&witness, missing_role_key, bool_json_bytes(false));
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountPermission,
                &fixture.account.to_string(),
                fixture.account_perm,
            ),
            bool_json_bytes(true),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountPermission,
                &fixture.account.to_string(),
                "can_missing",
            ),
            bool_json_bytes(false),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::RolePermission,
                &fixture.role.to_string(),
                fixture.role_perm,
            ),
            bool_json_bytes(true),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::RolePermission,
                &fixture.role.to_string(),
                "can_missing",
            ),
            bool_json_bytes(false),
        );
        assert_read_value(
            &witness,
            key_asset_balance(&fixture.asset),
            quantity_json_bytes(11),
        );
        assert_read_value(
            &witness,
            key_asset_balance(&fixture.missing_asset),
            Vec::new(),
        );
        assert_read_value(
            &witness,
            key_asset_def_total(&fixture.asset_definition),
            quantity_json_bytes(37),
        );
        assert_read_value(
            &witness,
            key_asset_def_total(&fixture.missing_asset_definition),
            Vec::new(),
        );
    }
    #[test]
    fn access_key_rejects_unsupported_malformed_and_invalid_inputs_match_formal_gate() {
        let fixture = access_key_fixture();
        let state_block = fixture.state.block(access_key_header());
        let guard = exec_witness_guard();
        start_block();
        let invalid_keys = [
            format!("unsupported:{}:color", fixture.account),
            format!("account.detail:{}", fixture.account),
            format!("domain.detail:{}", fixture.domain),
            format!("asset_def.detail:{}", fixture.asset_definition),
            format!("nft.detail:{}", fixture.nft),
            format!("role.binding:{}", fixture.account),
            format!("perm.account:{}", fixture.account),
            format!("perm.role:{}", fixture.role),
            String::from("account.detail:not_an_account:color"),
            format!("account.detail: {} :color", fixture.account),
            format!(
                "perm.account: {} :{}",
                fixture.account, fixture.account_perm
            ),
            String::from("domain.detail:not_a_domain:region"),
            String::from("asset_def.detail:not_an_asset_definition:issuer"),
            String::from("nft.detail:not_an_nft:artist"),
            format!("role.binding:{}:bad role", fixture.account),
            String::from("role:bad role"),
            String::from("perm.account:not_an_account:can_account_read"),
            String::from("perm.role:bad role:can_role_read"),
            format!("role:{}", fixture.unicode_role_raw),
            format!(
                "role.binding:{}:{}",
                fixture.account, fixture.unicode_role_raw
            ),
            format!(
                "perm.role:{}:{}",
                fixture.unicode_role_raw, fixture.role_perm
            ),
            String::from("asset:not_an_asset"),
            String::from("asset_def:not_an_asset_definition"),
            format!("account.detail:{}:bad key", fixture.account),
        ];
        for key in invalid_keys {
            record_read_from_access_key(&state_block, &key);
        }
        let witness = drain_exec_witness();
        drop(guard);
        assert!(
            witness.reads.is_empty(),
            "unsupported, malformed, and invalid keys must be ignored"
        );
        assert!(witness.writes.is_empty());
    }
    #[test]
    fn access_key_canonicalization_tail_and_prefix_isolation_match_formal_gate() {
        let fixture = access_key_fixture();
        let state_block = fixture.state.block(access_key_header());
        let guard = exec_witness_guard();
        start_block();
        let color = "color".parse::<Name>().expect("metadata key");
        let shade = "color:shade".parse::<Name>().expect("metadata key");
        let issuer = "issuer".parse::<Name>().expect("metadata key");
        record_read_from_access_key(
            &state_block,
            &format!("account.detail:{}:color", fixture.account),
        );
        record_read_from_access_key(
            &state_block,
            &format!("perm.account:{}:{}", fixture.account, fixture.account_perm),
        );
        record_read_from_access_key(
            &state_block,
            &format!("account.detail:{}:color:shade", fixture.account),
        );
        record_read_from_access_key(
            &state_block,
            &format!("asset_def.detail:{}:issuer", fixture.asset_definition),
        );
        record_read_from_access_key(
            &state_block,
            &format!("role.binding:{}:{}", fixture.account, fixture.role),
        );
        record_read_from_access_key(
            &state_block,
            &format!("perm.role:{}:{}", fixture.unicode_role, fixture.role_perm),
        );
        let witness = drain_exec_witness();
        drop(guard);
        assert_eq!(witness.reads.len(), 6);
        assert_read_value(
            &witness,
            key_account_kv(&fixture.account, &color),
            bytes_from_json(&Json::new("red")),
        );
        assert_no_read_key(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountMetadata,
                &format!(" {} ", fixture.account),
                color.as_ref(),
            ),
        );
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountPermission,
                &fixture.account.to_string(),
                fixture.account_perm,
            ),
            bool_json_bytes(true),
        );
        assert_no_read_key(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountPermission,
                &format!(" {} ", fixture.account),
                fixture.account_perm,
            ),
        );
        assert_read_value(
            &witness,
            key_account_kv(&fixture.account, &shade),
            bytes_from_json(&Json::new("maroon")),
        );
        assert_read_value(
            &witness,
            key_asset_def_kv(&fixture.asset_definition, &issuer),
            bytes_from_json(&Json::new("alice")),
        );
        assert_no_read_key(&witness, key_asset_def_total(&fixture.asset_definition));
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::AccountRoleBinding,
                &fixture.account.to_string(),
                &fixture.role.to_string(),
            ),
            bool_json_bytes(true),
        );
        let mut role_fallthrough_key = vec![0xC2];
        role_fallthrough_key
            .extend_from_slice(format!("binding:{}:{}", fixture.account, fixture.role).as_bytes());
        assert_no_read_key(&witness, role_fallthrough_key);
        assert_read_value(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::RolePermission,
                &fixture.unicode_role.to_string(),
                fixture.role_perm,
            ),
            bool_json_bytes(true),
        );
        assert_no_read_key(
            &witness,
            enc_key_prefix(
                ExecutionWitnessKeyTagV1::RolePermission,
                &fixture.unicode_role_raw,
                fixture.role_perm,
            ),
        );
    }
    #[test]
    fn parity_same_witness_twice_same_root() {
        let _guard = exec_witness_guard();
        // First run
        start_block();
        // Simulate asset balance read+write
        let ad = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let aid = iroha_data_model::asset::AssetId::new(ad.clone(), (*ALICE_ID).clone());
        let pre = Quantity::from(10u32);
        let post = Quantity::from(15u32);
        record_read_asset(&aid, Some(&pre));
        record_write_asset(&aid, &post);
        // Simulate total supply
        let tot_pre = Quantity::from(100u32);
        let tot_post = Quantity::from(105u32);
        record_read_asset_def_total(&ad, Some(&tot_pre));
        record_write_asset_def_total(&ad, &tot_post);
        let w1 = drain_exec_witness();
        let r1 = compute_post_state_root(
            &w1.reads
                .iter()
                .map(|kv| KvPair::new(kv.key.clone(), kv.value.clone()))
                .collect::<Vec<_>>(),
            &w1.writes
                .iter()
                .map(|kv| KvPair::new(kv.key.clone(), kv.value.clone()))
                .collect::<Vec<_>>(),
        );
        // Second run (identical)
        start_block();
        record_read_asset(&aid, Some(&pre));
        record_write_asset(&aid, &post);
        record_read_asset_def_total(&ad, Some(&tot_pre));
        record_write_asset_def_total(&ad, &tot_post);
        let w2 = drain_exec_witness();
        let r2 = compute_post_state_root(
            &w2.reads
                .iter()
                .map(|kv| KvPair::new(kv.key.clone(), kv.value.clone()))
                .collect::<Vec<_>>(),
            &w2.writes
                .iter()
                .map(|kv| KvPair::new(kv.key.clone(), kv.value.clone()))
                .collect::<Vec<_>>(),
        );
        assert_eq!(r1, r2);
    }
    #[test]
    fn recorder_lifecycle_read_write_delete_and_drain_match_formal_gate() {
        let _guard = exec_witness_guard();
        start_block();
        let key: Name = "color".parse().expect("metadata key");
        let account = (*ALICE_ID).clone();
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset = AssetId::new(asset_definition, account.clone());
        record_read_asset(&asset, Some(&Quantity::from(1u32)));
        record_write_asset(&asset, &Quantity::from(2u32));
        start_block();
        assert!(snapshot_exec_witness().reads.is_empty());
        assert!(snapshot_exec_witness().writes.is_empty());
        let first = Json::new("first");
        let second = Json::new("second");
        let post = Json::new("post");
        let delete_pre = Json::new("delete_pre");
        record_read_account_kv(&account, &key, Some(&first));
        record_read_account_kv(&account, &key, Some(&second));
        record_write_account_kv(&account, &key, &second);
        record_write_account_kv(&account, &key, &post);
        record_delete_account_kv(&account, &key, &delete_pre);
        record_read_asset(&asset, Some(&Quantity::from(7u32)));
        record_write_asset(&asset, &Quantity::from(9u32));
        let snapshot = snapshot_exec_witness();
        assert_eq!(snapshot.reads.len(), 2);
        assert_eq!(snapshot.writes.len(), 2);
        let drained = drain_exec_witness();
        assert_eq!(drained.fastpq_batches, Vec::new());
        assert!(
            drained
                .reads
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
        );
        assert!(
            drained
                .writes
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
        );
        let account_key = key_account_kv(&account, &key);
        let read = drained
            .reads
            .iter()
            .find(|kv| kv.key == account_key)
            .expect("account read recorded");
        assert_eq!(read.value, bytes_from_json(&first));
        let write = drained
            .writes
            .iter()
            .find(|kv| kv.key == account_key)
            .expect("account write recorded");
        assert!(
            write.value.is_empty(),
            "delete should record an empty post value"
        );
        record_read_account_kv(&account, &key, Some(&second));
        assert!(
            drain_exec_witness().reads.is_empty(),
            "drain must deactivate capture so inactive records are ignored"
        );
    }
    #[test]
    fn transaction_overlay_drop_discards_all_record_types() {
        let _guard = exec_witness_guard();
        start_block();
        let account = (*ALICE_ID).clone();
        let retained_key: Name = "retained".parse().expect("metadata key");
        let rolled_back_key: Name = "rolled_back".parse().expect("metadata key");
        let retained_value = Json::new("retained");
        let rolled_back_value = Json::new("rolled_back");
        let retained_hash = Hash::prehashed([0x71; Hash::LENGTH]);
        let rolled_back_hash = Hash::prehashed([0x72; Hash::LENGTH]);
        let (retained_transcript, _) = sample_fastpq_transcript(7, retained_hash);
        let (rolled_back_transcript, _) = sample_fastpq_transcript(8, rolled_back_hash);

        record_read_account_kv(&account, &retained_key, Some(&retained_value));
        record_write_account_kv(&account, &retained_key, &retained_value);
        record_fastpq_transcript(&retained_transcript);
        {
            let _overlay = begin_exec_witness_overlay();
            record_read_account_kv(&account, &rolled_back_key, Some(&rolled_back_value));
            record_write_account_kv(&account, &rolled_back_key, &rolled_back_value);
            record_fastpq_transcript(&rolled_back_transcript);

            let snapshot = snapshot_exec_witness();
            assert_no_read_key(&snapshot, key_account_kv(&account, &rolled_back_key));
            assert!(
                snapshot
                    .fastpq_transcripts
                    .iter()
                    .all(|bundle| bundle.entry_hash != rolled_back_hash),
                "uncommitted transcripts must remain private"
            );
        }

        let witness = drain_exec_witness();
        assert_eq!(witness.reads.len(), 1);
        assert_eq!(witness.writes.len(), 1);
        assert_read_value(
            &witness,
            key_account_kv(&account, &retained_key),
            bytes_from_json(&retained_value),
        );
        assert!(
            witness
                .writes
                .iter()
                .all(|kv| kv.key != key_account_kv(&account, &rolled_back_key))
        );
        assert_eq!(witness.fastpq_transcripts.len(), 1);
        assert_eq!(witness.fastpq_transcripts[0].entry_hash, retained_hash);
    }
    #[test]
    fn transaction_overlay_commit_merges_all_record_types() {
        let _guard = exec_witness_guard();
        start_block();
        let account = (*ALICE_ID).clone();
        let key: Name = "committed".parse().expect("metadata key");
        let value = Json::new("committed");
        let batch_hash = Hash::prehashed([0x73; Hash::LENGTH]);
        let (transcript, _) = sample_fastpq_transcript(9, batch_hash);

        let overlay = begin_exec_witness_overlay();
        record_read_account_kv(&account, &key, Some(&value));
        record_write_account_kv(&account, &key, &value);
        record_fastpq_transcript(&transcript);
        overlay.commit();

        let witness = drain_exec_witness();
        assert_read_value(
            &witness,
            key_account_kv(&account, &key),
            bytes_from_json(&value),
        );
        assert_eq!(witness.writes.len(), 1);
        assert_eq!(witness.writes[0].key, key_account_kv(&account, &key));
        assert_eq!(witness.writes[0].value, bytes_from_json(&value));
        assert_eq!(witness.fastpq_transcripts.len(), 1);
        assert_eq!(witness.fastpq_transcripts[0].entry_hash, batch_hash);
    }
    #[test]
    fn nested_overlay_commit_is_still_rolled_back_with_its_parent() {
        let _guard = exec_witness_guard();
        start_block();
        let account = (*ALICE_ID).clone();
        let outer_key: Name = "outer".parse().expect("metadata key");
        let inner_key: Name = "inner".parse().expect("metadata key");
        let value = Json::new("value");

        {
            let _outer = begin_exec_witness_overlay();
            record_write_account_kv(&account, &outer_key, &value);
            let inner = begin_exec_witness_overlay();
            record_write_account_kv(&account, &inner_key, &value);
            inner.commit();
        }

        let witness = drain_exec_witness();
        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
    }
    #[test]
    fn transaction_overlay_preserves_fastpq_replacement_semantics() {
        let _guard = exec_witness_guard();
        let original_hash = Hash::prehashed([0x74; Hash::LENGTH]);
        let replacement_hash = Hash::prehashed([0x75; Hash::LENGTH]);
        let (original, _) = sample_fastpq_transcript(10, original_hash);
        let (replacement, _) = sample_fastpq_transcript(11, replacement_hash);
        let finalized = BTreeMap::from([(replacement_hash, vec![replacement])]);

        start_block();
        record_fastpq_transcript(&original);
        {
            let _overlay = begin_exec_witness_overlay();
            synchronize_fastpq_transcripts(&finalized);
        }
        let rolled_back = drain_exec_witness();
        assert_eq!(rolled_back.fastpq_transcripts.len(), 1);
        assert_eq!(rolled_back.fastpq_transcripts[0].entry_hash, original_hash);

        start_block();
        record_fastpq_transcript(&original);
        let outer = begin_exec_witness_overlay();
        let inner = begin_exec_witness_overlay();
        synchronize_fastpq_transcripts(&finalized);
        inner.commit();
        outer.commit();
        let committed = drain_exec_witness();
        assert_eq!(committed.fastpq_transcripts.len(), 1);
        assert_eq!(committed.fastpq_transcripts[0].entry_hash, replacement_hash);
    }
    #[test]
    fn recorder_recovers_poisoned_witness_locks() {
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock_exec_witness_lock();
            panic!("poison execution witness guard for recovery test");
        });
        // Even deliberate corruption must own the recorder so concurrent captures
        // cannot observe this test's unfinished poisoning fixture.
        let _guard = exec_witness_guard();
        let _ = std::panic::catch_unwind(|| {
            let mut guard = lock_slot();
            guard.active = true;
            panic!("poison execution witness slot for recovery test");
        });
        start_block();
        let account = (*ALICE_ID).clone();
        let key: Name = "color".parse().expect("metadata key");
        let value = Json::new("red");
        record_read_account_kv(&account, &key, Some(&value));
        let drained = drain_exec_witness();
        assert_eq!(drained.reads.len(), 1);
        assert_eq!(drained.reads[0].key, key_account_kv(&account, &key));
        assert_eq!(drained.reads[0].value, bytes_from_json(&value));
    }
    #[test]
    fn recorder_key_namespaces_match_formal_tags_and_separators() {
        let account = (*ALICE_ID).clone();
        let domain = DomainId::try_new("wonderland", "universal").unwrap();
        let nft: NftId = "ticket$wonderland.universal".parse().expect("nft id");
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain.clone(),
            "rose".parse().unwrap(),
        );
        let asset = AssetId::new(asset_definition.clone(), account.clone());
        let key: Name = "color".parse().expect("metadata key");
        let sep = key_sep();
        let metadata_keys = [
            key_account_kv(&account, &key),
            key_domain_kv(&domain, &key),
            key_nft_kv(&nft, &key),
            key_asset_def_kv(&asset_definition, &key),
        ];
        let metadata_tags = metadata_keys
            .iter()
            .map(|key| key[0])
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(metadata_tags, [0xA1, 0xA2, 0xA3, 0xA4].into());
        assert!(
            metadata_keys.iter().all(|key| key.contains(&sep)),
            "metadata keys must include the unit separator between id and field"
        );
        let balance_key = key_asset_balance(&asset);
        assert_eq!(balance_key[0], 0xB1);
        assert!(!balance_key.contains(&sep));
        let total_key = key_asset_def_total(&asset_definition);
        assert_eq!(total_key[0], 0xB2);
        assert!(!total_key.contains(&sep));
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fastpq_grouping_and_finalized_sync_match_formal_gate() {
        let _guard = exec_witness_guard();
        start_block();
        let batch_hash = Hash::prehashed([0x44; Hash::LENGTH]);
        let other_hash = Hash::prehashed([0x45; Hash::LENGTH]);
        let missing_hash = Hash::prehashed([0x46; Hash::LENGTH]);
        let (first, first_digest) = sample_fastpq_transcript(1, batch_hash);
        let (second, second_digest) = sample_fastpq_transcript(2, batch_hash);
        let (other, _) = sample_fastpq_transcript(3, other_hash);
        record_fastpq_transcript(&first);
        record_fastpq_transcript(&second);
        record_fastpq_transcript(&other);
        let snapshot = snapshot_exec_witness();
        let grouped = snapshot
            .fastpq_transcripts
            .iter()
            .find(|bundle| bundle.entry_hash == batch_hash)
            .expect("same-batch transcripts grouped");
        assert_eq!(grouped.transcripts.len(), 2);
        assert_eq!(grouped.transcripts[0].deltas, first.deltas);
        assert_eq!(grouped.transcripts[1].deltas, second.deltas);
        assert_eq!(
            grouped.transcripts[0].poseidon_preimage_digest,
            Some(first_digest)
        );
        assert_eq!(
            grouped.transcripts[1].poseidon_preimage_digest,
            Some(second_digest)
        );
        let mut finalized_second = second.clone();
        finalized_second.poseidon_preimage_digest = Some(second_digest);
        let mut finalized_first = first.clone();
        finalized_first.poseidon_preimage_digest = Some(first_digest);
        let mut finalized = BTreeMap::new();
        finalized.insert(batch_hash, vec![finalized_first, finalized_second]);
        let (mut finalized_missing, missing_digest) = sample_fastpq_transcript(4, missing_hash);
        finalized_missing.poseidon_preimage_digest = Some(missing_digest);
        finalized.insert(missing_hash, vec![finalized_missing]);
        synchronize_fastpq_transcripts(&finalized);
        {
            let g = lock_slot();
            let stored = g
                .fastpq_transcripts
                .get(&batch_hash)
                .expect("batch still recorded");
            assert_eq!(stored[0].poseidon_preimage_digest, Some(first_digest));
            assert_eq!(stored[1].poseidon_preimage_digest, Some(second_digest));
            assert!(
                !g.fastpq_transcripts.contains_key(&other_hash),
                "a speculative transcript absent from finalized state must be removed"
            );
            assert_eq!(
                g.fastpq_transcripts
                    .get(&missing_hash)
                    .expect("finalized transcript absent from speculative recorder is installed")
                    [0]
                .poseidon_preimage_digest,
                Some(missing_digest),
            );
        }
        let drained = drain_exec_witness();
        assert_eq!(drained.fastpq_transcripts.len(), finalized.len());
        assert!(drained.fastpq_batches.is_empty());
    }
    #[test]
    fn finalized_fastpq_sync_honors_witness_window_and_suppression() {
        let _guard = exec_witness_guard();
        start_block();
        let active_hash = Hash::prehashed([0x47; Hash::LENGTH]);
        let suppressed_hash = Hash::prehashed([0x48; Hash::LENGTH]);
        let (active, _) = sample_fastpq_transcript(5, active_hash);
        let (suppressed, _) = sample_fastpq_transcript(6, suppressed_hash);
        record_fastpq_transcript(&active);
        let suppressed_finalized = BTreeMap::from([(suppressed_hash, vec![suppressed])]);
        {
            let _suppression = suppress_recording_for_current_thread();
            synchronize_fastpq_transcripts(&suppressed_finalized);
        }
        let drained = drain_exec_witness();
        assert!(
            drained
                .fastpq_transcripts
                .iter()
                .any(|bundle| bundle.entry_hash == active_hash),
            "suppressed execution must not replace another block's active witness"
        );
        assert!(
            drained
                .fastpq_transcripts
                .iter()
                .all(|bundle| bundle.entry_hash != suppressed_hash)
        );

        synchronize_fastpq_transcripts(&suppressed_finalized);
        assert!(
            drain_exec_witness().fastpq_transcripts.is_empty(),
            "finalized transcripts must not be installed outside an active witness window"
        );
    }
    #[test]
    fn records_fastpq_transcripts() {
        use iroha_data_model::{
            asset::id::AssetDefinitionId,
            fastpq::{TransferDeltaTranscript, TransferTranscript},
        };
        use iroha_test_samples::{ALICE_ID, BOB_ID};
        let _guard = exec_witness_guard();
        start_block();
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(5u32),
            from_balance_before: Quantity::from(100u32),
            from_balance_after: Quantity::from(95u32),
            to_balance_before: Quantity::from(0u32),
            to_balance_after: Quantity::from(5u32),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let batch_hash = Hash::prehashed([0x11; Hash::LENGTH]);
        let transcript = TransferTranscript {
            batch_hash,
            deltas: vec![delta.clone()],
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
            poseidon_preimage_digest: None,
        };
        let expected_digest = crate::fastpq::poseidon_preimage_digest(&delta, &batch_hash);
        record_fastpq_transcript(&transcript);
        let witness = drain_exec_witness();
        let stored = witness
            .fastpq_transcripts
            .iter()
            .find(|bundle| bundle.entry_hash == batch_hash)
            .expect("transcript recorded");
        assert_eq!(stored.transcripts.len(), 1);
        let mut expected = transcript;
        expected.poseidon_preimage_digest = Some(expected_digest);
        assert_eq!(stored.transcripts[0], expected);
        assert!(witness.fastpq_batches.is_empty());
        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
    }
    #[test]
    fn synchronize_fastpq_transcripts_updates_recorded_witness_copy() {
        use iroha_data_model::{
            asset::id::AssetDefinitionId,
            fastpq::{TransferDeltaTranscript, TransferTranscript},
        };
        use iroha_test_samples::{ALICE_ID, BOB_ID};
        let _guard = exec_witness_guard();
        start_block();
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(5u32),
            from_balance_before: Quantity::from(100u32),
            from_balance_after: Quantity::from(95u32),
            to_balance_before: Quantity::from(0u32),
            to_balance_after: Quantity::from(5u32),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let batch_hash = Hash::prehashed([0x33; Hash::LENGTH]);
        let transcript = TransferTranscript {
            batch_hash,
            deltas: vec![delta.clone()],
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
            poseidon_preimage_digest: None,
        };
        let expected_digest = crate::fastpq::poseidon_preimage_digest(&delta, &batch_hash);
        record_fastpq_transcript(&transcript);
        let mut finalized = std::collections::BTreeMap::new();
        let mut finalized_transcript = transcript;
        finalized_transcript.poseidon_preimage_digest = Some(expected_digest);
        finalized.insert(batch_hash, vec![finalized_transcript]);
        synchronize_fastpq_transcripts(&finalized);
        let g = lock_slot();
        let stored = g
            .fastpq_transcripts
            .get(&batch_hash)
            .expect("transcript recorded");
        assert_eq!(stored[0].poseidon_preimage_digest, Some(expected_digest));
        drop(g);
        let _ = drain_exec_witness();
    }
    #[test]
    fn snapshot_finalizes_single_fastpq_transcript_without_clearing() {
        use iroha_data_model::{
            asset::id::AssetDefinitionId,
            fastpq::{TransferDeltaTranscript, TransferTranscript},
        };
        use iroha_test_samples::{ALICE_ID, BOB_ID};
        let _guard = exec_witness_guard();
        start_block();
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let delta = TransferDeltaTranscript {
            from_account: (*ALICE_ID).clone(),
            to_account: (*BOB_ID).clone(),
            asset_definition: asset,
            amount: Quantity::from(5u32),
            from_balance_before: Quantity::from(100u32),
            from_balance_after: Quantity::from(95u32),
            to_balance_before: Quantity::from(0u32),
            to_balance_after: Quantity::from(5u32),
            from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
            to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        };
        let batch_hash = Hash::prehashed([0x22; Hash::LENGTH]);
        let transcript = TransferTranscript {
            batch_hash,
            deltas: vec![delta.clone()],
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
            poseidon_preimage_digest: None,
        };
        let expected_digest = crate::fastpq::poseidon_preimage_digest(&delta, &batch_hash);
        record_fastpq_transcript(&transcript);
        let snapshot = snapshot_exec_witness();
        let stored = snapshot
            .fastpq_transcripts
            .iter()
            .find(|bundle| bundle.entry_hash == batch_hash)
            .expect("snapshot transcript recorded");
        assert_eq!(
            stored.transcripts[0].poseidon_preimage_digest,
            Some(expected_digest)
        );
        let drained = drain_exec_witness();
        assert_eq!(drained.fastpq_transcripts.len(), 1);
    }
    #[test]
    fn inactive_recorder_ignores_out_of_block_records() {
        use iroha_data_model::{asset::id::AssetDefinitionId, fastpq::TransferTranscript};
        let _guard = exec_witness_guard();
        let _ = drain_exec_witness();
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset = AssetId::new(asset_definition, (*ALICE_ID).clone());
        record_read_asset(&asset, Some(&Quantity::from(7u32)));
        record_fastpq_transcript(&TransferTranscript {
            batch_hash: Hash::prehashed([0x22; Hash::LENGTH]),
            deltas: Vec::new(),
            authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
            poseidon_preimage_digest: None,
        });
        let witness = drain_exec_witness();
        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
        assert!(witness.fastpq_batches.is_empty());
    }
    #[test]
    fn guard_drop_clears_unfinished_capture() {
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset = AssetId::new(asset_definition, (*ALICE_ID).clone());
        let guard = exec_witness_guard();
        start_block();
        record_read_asset(&asset, Some(&Quantity::from(11u32)));
        drop(guard);
        let _guard = exec_witness_guard();
        let witness = drain_exec_witness();
        assert!(witness.reads.is_empty());
        assert!(witness.writes.is_empty());
        assert!(witness.fastpq_transcripts.is_empty());
        assert!(witness.fastpq_batches.is_empty());
    }
    #[test]
    fn begin_capture_refuses_nested_owner_without_resetting_generation() {
        let guard = begin_exec_witness_capture().unwrap();
        let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset = AssetId::new(asset_definition, (*ALICE_ID).clone());
        record_read_asset(&asset, Some(&Quantity::from(11u32)));
        let held = begin_exec_witness_overlay();
        record_write_asset(&asset, &Quantity::from(12u32));
        assert!(
            begin_exec_witness_capture()
                .err()
                .unwrap()
                .contains("already belongs")
        );
        held.commit();
        let captured = drain_exec_witness_checked(|_| Ok(())).unwrap();
        assert_eq!(captured.reads.len(), 1);
        assert_eq!(captured.writes.len(), 1);
        drop(guard);
    }

    #[test]
    fn state_access_refuses_owned_recorder_even_when_suppressed() {
        ensure_state_access_without_exec_witness().unwrap();
        let suppression = suppress_recording_for_current_thread();
        ensure_state_access_without_exec_witness().unwrap();
        drop(suppression);
        let guard = begin_exec_witness_capture().unwrap();
        let held = begin_exec_witness_overlay();
        assert!(ensure_state_access_without_exec_witness().is_err());
        let suppression = suppress_recording_for_current_thread();
        assert!(ensure_state_access_without_exec_witness().is_err());
        drop(suppression);
        held.commit();
        drain_exec_witness_checked(|_| Ok(())).unwrap();
        drop(guard);
        ensure_state_access_without_exec_witness().unwrap();
    }

    #[test]
    fn begin_capture_refuses_suppression_and_stale_overlay_then_releases_owner() {
        let suppression = suppress_recording_for_current_thread();
        assert!(
            begin_exec_witness_capture()
                .err()
                .unwrap()
                .contains("suppressed")
        );
        drop(suppression);
        let guard = begin_exec_witness_capture().unwrap();
        let held = begin_exec_witness_overlay();
        drop(guard);
        assert!(
            begin_exec_witness_capture()
                .err()
                .unwrap()
                .contains("pending overlay")
        );
        drop(held);
        let guard = begin_exec_witness_capture().unwrap();
        let captured = drain_exec_witness_checked(|_| Ok(())).unwrap();
        assert!(captured.reads.is_empty());
        assert!(captured.writes.is_empty());
        drop(guard);
    }

    #[test]
    fn capture_identity_requires_original_owned_unsuppressed_generation() {
        assert!(current_exec_witness_capture_identity().is_none());
        let guard = begin_exec_witness_capture().unwrap();
        let identity = current_exec_witness_capture_identity().unwrap();
        identity.require_current().unwrap();
        let suppression = suppress_recording_for_current_thread();
        assert!(current_exec_witness_capture_identity().is_none());
        assert!(identity.require_current().is_err());
        drop(suppression);
        identity.require_current().unwrap();
        start_block();
        assert!(identity.require_current().is_err());
        let replacement = current_exec_witness_capture_identity().unwrap();
        replacement.require_current().unwrap();
        drop(guard);
        assert!(replacement.require_current().is_err());
        assert!(current_exec_witness_capture_identity().is_none());
        let _next = begin_exec_witness_capture().unwrap();
        assert!(identity.require_current().is_err());
        assert!(replacement.require_current().is_err());
        current_exec_witness_capture_identity()
            .unwrap()
            .require_current()
            .unwrap();
    }

    #[test]
    fn exec_witness_guard_serializes_block_access() {
        std::thread::scope(|scope| {
            let guard = exec_witness_guard();
            let (probe_tx, probe_rx) = std::sync::mpsc::sync_channel(0);
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = scope.spawn(move || {
                // Probe the actual recorder mutex while its original guard is
                // held; the rendezvous confirms that the worker reached it.
                let blocked = matches!(
                    exec_witness_lock().try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                probe_tx.send(blocked).expect("send exclusion probe");
                let _guard = exec_witness_guard();
                tx.send(()).expect("send guard signal");
            });
            assert!(
                probe_rx.recv().expect("worker probes original mutex")
                    && matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
                "guard should prevent concurrent access"
            );
            drop(guard);
            // Other block captures may acquire this global mutex first. The
            // contract is exclusion and release, without a handoff deadline.
            rx.recv().expect("guard should release");
            handle.join().expect("thread joins");
        });
    }
}
