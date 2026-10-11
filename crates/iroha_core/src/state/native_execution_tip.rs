//! Original native execution identity, outside World to avoid an R self-reference.
//!
//! Decoded snapshot values are claims. Only the original execution owner or a
//! fully verified native prefix can install the opaque value in its funded Cell.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    sumeragi::certified_chain::{CertifiedChain, ChainReadError, CommittedBlock},
};
use iroha_allocation::{AllocationBudget, AllocationCharge};
use iroha_sumeragi::types::Hash32;

/// Fixed execution identity retained by the original publication generation.
/// This type deliberately has no decoder or public constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeExecutionTip(NativeExecutionTipRecord);

/// Snapshot claim; decoding this record grants no execution authority.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, norito::json::JsonSerialize, norito::json::JsonDeserialize,
)]
pub(crate) struct NativeExecutionTipRecord {
    pub(crate) height: u64,
    pub(crate) creation_time_ms: u64,
    pub(crate) iroha_hash: HashOf<BlockHeader>,
    pub(crate) core_hash: [u8; 32],
    pub(crate) result: [u8; 32],
}

impl norito::json::JsonSerialize for NativeExecutionTip {
    fn json_serialize(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
}

impl NativeExecutionTip {
    /// One-based original executed height.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.0.height
    }
    /// Ledger time from the exact original authenticated carrier.
    #[must_use]
    pub const fn creation_time_ms(self) -> u64 {
        self.0.creation_time_ms
    }
    /// Exact Iroha header identity whose outputs were sealed.
    #[must_use]
    pub const fn iroha_hash(self) -> HashOf<BlockHeader> {
        self.0.iroha_hash
    }
    /// Exact native header identity admitted by the original owner.
    #[must_use]
    pub const fn core_hash(self) -> Hash32 {
        Hash32(self.0.core_hash)
    }
    /// Exact certified result of the original execution.
    #[must_use]
    pub const fn result(self) -> Hash32 {
        Hash32(self.0.result)
    }
}

/// Complete fixed current/undo snapshot projection, still unauthenticated.
#[derive(norito::json::JsonSerialize, norito::json::JsonDeserialize)]
pub(crate) struct NativeExecutionTipSnapshot {
    revert: Option<NativeExecutionTipUndo>,
    blocks: Option<NativeExecutionTipRecord>,
}

/// Explicit undo wrapper preserves `Some(None)` for the genesis predecessor.
#[derive(norito::json::JsonSerialize, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct NativeExecutionTipUndo {
    value: Option<NativeExecutionTipRecord>,
}

pub(crate) type TipCell = Cell<Option<NativeExecutionTip>, AllocationCharge>;

/// Reserve actual initial payload/control allocations before moving fixed values.
pub(in crate::state) fn empty_cell(
    budget: &AllocationBudget,
) -> Result<TipCell, MergeLedgerCommitError> {
    initialize(budget, None, None).map_err(Into::into)
}

fn initialize(
    budget: &AllocationBudget,
    current: Option<NativeExecutionTip>,
    undo: Option<Option<NativeExecutionTip>>,
) -> Result<TipCell, StateStorageAdmissionError> {
    let original = mv::cell::CellInitialization::try_reserve(budget).map_err(|error| {
        StateStorageAdmissionError::World(match error {
            mv::cell::CellInitializationError::Admission(error) => {
                mv::storage::AdmittedStorageError::Allocation(error)
            }
            mv::cell::CellInitializationError::Allocator { layout } => {
                mv::storage::AdmittedStorageError::Allocator { layout }
            }
        })
    })?;
    Ok(original.initialize(current, undo))
}

/// Resource refusal remains distinct from an invalid snapshot claim.
#[derive(Debug)]
pub(in crate::state) enum TipRestoreError {
    /// Only the original fresh-State genesis execution can authenticate this result.
    GenesisReplayRequired,
    /// Authenticated history contradicts or cannot establish the decoded claim.
    History(String),
    /// The exact local pool cannot fund the original Cell.
    Admission(StateStorageAdmissionError),
    /// Original native history resources refused this unfinished local attempt.
    Deferred(crate::execution_attempt::ExecutionDeferred),
}
impl From<ExecutionAttemptError<ChainReadError>> for TipRestoreError {
    fn from(error: ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            ExecutionAttemptError::Rejected(error) => Self::History(error.to_string()),
            #[cfg(all(test, sumeragi_core_mutation = "HC216"))]
            ExecutionAttemptError::Deferred(original) => Self::History(
                ExecutionAttemptError::<ChainReadError>::Deferred(original).to_string(),
            ),
            #[cfg(not(all(test, sumeragi_core_mutation = "HC216")))]
            ExecutionAttemptError::Deferred(original) => Self::Deferred(original),
        }
    }
}
impl From<String> for TipRestoreError {
    fn from(message: String) -> Self {
        Self::History(message)
    }
}
impl From<&str> for TipRestoreError {
    fn from(message: &str) -> Self {
        Self::History(message.into())
    }
}

impl NativeExecutionTipSnapshot {
    /// Capture the exact original current and undo values without losing nested absence.
    pub(crate) fn from_original(
        current: Option<NativeExecutionTip>,
        previous: Option<Option<NativeExecutionTip>>,
    ) -> Self {
        Self {
            blocks: current.map(|tip| tip.0),
            revert: previous.map(|tip| NativeExecutionTipUndo {
                value: tip.map(|tip| tip.0),
            }),
        }
    }

    /// Compare serialized claims with the exact originals captured alongside the World.
    /// This grants no restore authority and never constructs an execution owner.
    pub(crate) fn matches_original(
        &self,
        current: Option<NativeExecutionTip>,
        previous: Option<Option<NativeExecutionTip>>,
    ) -> bool {
        self.blocks == current.map(|tip| tip.0)
            && self.revert.as_ref().map(|undo| undo.value)
                == previous.map(|tip| tip.map(|tip| tip.0))
    }

    /// Restore authority by checking original native history, never by trusting
    /// the decoded Cell or World. H1-only restart must replay signed genesis.
    pub(in crate::state) fn restore(
        self,
        budget: &AllocationBudget,
        chain_id: &iroha_model_base::chain::ChainId,
        network: &iroha_data_model::NetworkId,
        hashes: &[HashOf<BlockHeader>],
        kura: &Kura,
    ) -> Result<TipCell, TipRestoreError> {
        let height = u64::try_from(hashes.len()).map_err(|error| error.to_string())?;
        if height == 0 {
            if self.blocks.is_some() || self.revert.is_some() {
                return Err("empty history cannot carry native execution tip or undo".into());
            }
            return initialize(budget, None, None).map_err(TipRestoreError::Admission);
        }
        if height == 1 {
            // Strict daemon startup classifies this separately and constructs
            // fresh State before node::prepare replays the stored signed genesis.
            // A decoded H1 result never authorizes World or bypasses original replay.
            // Nonempty export recovery remains disabled until S9 authenticates full World.
            return Err(TipRestoreError::GenesisReplayRequired);
        }
        let chain = CertifiedChain::from_pinned(chain_id, network, hashes, kura, budget)
            .map_err(TipRestoreError::from)?;
        // One verified walk over the native prefix authenticates the tip and its
        // predecessor and records history checkpoints for off-chain readers.
        let checkpoints = kura.history_checkpoints();
        let mut previous = if height == 2 {
            Some(record(
                chain
                    .authenticated_execution(1)
                    .map_err(TipRestoreError::from)?
                    .committed(),
            ))
        } else {
            None
        };
        let mut current = None;
        for certified in chain.walk(2, height) {
            let block = certified
                .map_err(TipRestoreError::from)?
                .into_authenticated_execution()
                .map_err(|error| error.to_string())?;
            let block = record(block.committed());
            checkpoints.record_sparse(block.height, checkpoint_of(block));
            previous = current.replace(block).or(previous);
        }
        let (Some(current), Some(previous)) = (current, previous) else {
            return Err("verified native prefix ended before the snapshot tip".into());
        };
        if self.blocks != Some(current)
            || self.revert.as_ref().map(|undo| undo.value) != Some(Some(previous))
        {
            return Err(
                "snapshot native execution tip/undo differs from verified native prefix".into(),
            );
        }
        initialize(
            budget,
            Some(NativeExecutionTip(current)),
            Some(Some(NativeExecutionTip(previous))),
        )
        .map_err(TipRestoreError::Admission)
    }
}

/// The history checkpoint of an authenticated native execution identity.
fn checkpoint_of(
    record: NativeExecutionTipRecord,
) -> crate::kura::history_checkpoints::HistoryCheckpoint {
    crate::kura::history_checkpoints::HistoryCheckpoint {
        iroha_hash: record.iroha_hash,
        core_hash: Hash32(record.core_hash),
        result: Hash32(record.result),
    }
}
fn record(block: &CommittedBlock) -> NativeExecutionTipRecord {
    NativeExecutionTipRecord {
        height: block.height(),
        creation_time_ms: u64::try_from(block.block().header().creation_time().as_millis())
            .expect("block creation time is a u64 millisecond value"),
        iroha_hash: block.block_hash(),
        core_hash: block.core_hash().0,
        result: block.result().0,
    }
}

impl StateBlock<'_> {
    /// Check the opaque owner before consuming its original output seal.
    pub(in crate::state) fn validate_native_execution_authorization(
        &self,
        authorization: &crate::sumeragi::executor::NativeExecutionAuthorization,
        block: &crate::block::CommittedBlock,
        certificate: &iroha_data_model::block::CommitCertificate,
    ) -> Result<NativeExecutionTipRecord, String> {
        let (next, parent) = authorization.for_state(self.state_ref)?;
        let iroha = block.as_ref();
        if next.height != iroha.header().height().get()
            || u128::from(next.creation_time_ms) != iroha.header().creation_time().as_millis()
            || next.iroha_hash != iroha.hash()
            || next.result
                != crate::sumeragi::commitment::result_of_preimage(certificate.result_preimage()).0
        {
            return Err("native execution owner differs from the original sealed carrier".into());
        }
        let certified_core = if parent.is_none() {
            crate::sumeragi::startup::core_hash_of(iroha)
        } else {
            let header: iroha_sumeragi::message::BlockHeader =
                norito::decode_canonical(certificate.consensus_header())
                    .map_err(|error| error.to_string())?;
            if Some((header.parent_hash, header.parent_result)) != parent
                || header.height != next.height
            {
                return Err("native certificate changed the original execution parent".into());
            }
            header.hash(&crate::sumeragi::crypto::BlsCrypto::new())
        };
        if certified_core.0 != next.core_hash {
            return Err("native certificate changed the original executed header".into());
        }
        match (*self.native_execution_tip.get(), parent) {
            (None, None)
                if next.height == 1
                    && iroha.header().prev_block_hash().is_none()
                    && self.block_hashes.is_empty()
                    && certificate.consensus_header().is_empty()
                    && certificate.commit_qc().is_empty() => {}
            (Some(previous), Some((parent_hash, parent_result)))
                if previous.height().checked_add(1) == Some(next.height)
                    && usize::try_from(previous.height()).ok() == Some(self.block_hashes.len())
                    && self.block_hashes.last().copied() == Some(previous.iroha_hash())
                    && iroha.header().prev_block_hash() == Some(previous.iroha_hash())
                    && parent_hash == previous.core_hash()
                    && parent_result == previous.result() => {}
            _ => {
                return Err(
                    "native execution owner does not extend this original State tip".into(),
                );
            }
        }
        Ok(next)
    }

    /// Stage only after the immutable witness surface has been revalidated.
    pub(in crate::state) fn advance_native_execution_tip(
        &mut self,
        authorization: &crate::sumeragi::executor::NativeExecutionAuthorization,
        block: &crate::block::CommittedBlock,
    ) -> Result<(), String> {
        let (next, _) = authorization.for_state(self.state_ref)?;
        if next.iroha_hash != block.as_ref().hash()
            || next.height != self._curr_block.height().get()
        {
            return Err("native execution tip changed during metadata preparation".into());
        }
        *self.native_execution_tip.get_mut() = Some(NativeExecutionTip(next));
        // An abandoned block's checkpoint is harmless: readers trust a checkpoint
        // only while it matches their committed hash journal.
        self.kura
            .history_checkpoints()
            .record_sparse(next.height, checkpoint_of(next));
        Ok(())
    }
}

/// Fund both exact future EBR generations and the original successor before a writer exists.
pub(in crate::state) fn original_cell<'a>(
    target: &'a TipCell,
    budget: &AllocationBudget,
    parent: &mut iroha_allocation::AllocationReservation,
) -> Result<
    mv::cell::BlockAcquisitionSlot<'a, Option<NativeExecutionTip>, AllocationCharge>,
    mv::storage::AdmittedStorageError,
> {
    use mv::storage::AdmittedStorageError as Error;
    let layouts = TipCell::allocation_layouts();
    let mut generations = budget
        .try_reserve_layouts(layouts)
        .map_err(Error::Allocation)?;
    let current = generations
        .try_split(layouts[0])
        .expect("original native tip current layout");
    let undo = generations
        .try_split(layouts[1])
        .expect("original native tip undo layout");
    let backing = mv::cell::CellGenerationBacking::try_from_charges(
        budget,
        mv::cell::CellAllocationCharges::new(current, undo),
    )
    .map_err(|(_charges, error)| match error {
        mv::cell::CellGenerationBackingError::Allocator { layout } => Error::Allocator { layout },
        _ => Error::PolicyIdentity,
    })?;
    let charge = parent
        .try_split(mv::cell::CellPublicationSuccessor::allocation_layout())
        .map_err(|error| Error::PolicyDemand {
            expected_bytes: error.requested_bytes,
            remaining_bytes: error.remaining_bytes,
        })?;
    let successor = mv::cell::CellPublicationSuccessor::try_from_charge(budget, charge).map_err(
        |(_charge, error)| match error {
            mv::cell::CellPublicationSuccessorError::Allocator { layout } => {
                Error::Allocator { layout }
            }
            _ => Error::PolicyIdentity,
        },
    )?;
    target
        .try_block_acquisition_with_backing(backing, successor, budget)
        .map_err(|_| Error::PolicyIdentity)
}

impl StateView<'_> {
    pub(in crate::state) fn native_execution_tip_value(&self) -> Option<NativeExecutionTip> {
        *self.native_execution_tip.get()
    }
}
impl StateBlock<'_> {
    pub(in crate::state) fn native_execution_tip_value(&self) -> Option<NativeExecutionTip> {
        *self.native_execution_tip.get()
    }
}
impl StateQueryView<'_> {
    pub(in crate::state) fn native_execution_tip_value(&self) -> Option<NativeExecutionTip> {
        *self.native_execution_tip.get()
    }
}
impl StateTransaction<'_, '_> {
    pub(in crate::state) fn native_execution_tip_value(&self) -> Option<NativeExecutionTip> {
        self.native_execution_tip
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: complete State capture work and custody before consuming the World-only prerequisite"
    )
)]
mod finalized_world;

#[cfg(test)]
mod tests;
