//! Fallible, world-state-anchored access to canonical block history.

mod read_budget;
pub use read_budget::CanonicalHistoryReadBudget;

use iroha_allocation::AllocationBudget;
use iroha_data_model::block::SharedSignedBlock;
use std::num::NonZeroUsize;

use iroha_crypto::HashOf;
use iroha_data_model::{
    block::BlockHeader,
    query::error::{CanonicalHistoryError, QueryExecutionFail},
};

use crate::{
    execution_attempt::{ExecutionAttemptError, kura_read_attempt_error},
    kura::{Kura, history_checkpoints::HistoryCheckpoint},
};

/// Original local capture refusal, separate from execution and canonical history errors.
/// This non-wire event boundary retains the actual physical State release owner;
/// a busy publication never becomes a transaction rejection or allocation demand.
#[derive(Debug, thiserror::Error)]
pub enum FinalizedEventReadError {
    /// Exact original State reader/publication custody or malformed source observation.
    #[error(transparent)]
    StateView(#[from] super::StateViewError),
    /// Unchanged deterministic rejection or original local decoder/allocation refusal.
    #[error(transparent)]
    Execution(#[from] ExecutionAttemptError<QueryExecutionFail>),
}

impl From<QueryExecutionFail> for FinalizedEventReadError {
    fn from(error: QueryExecutionFail) -> Self {
        Self::Execution(ExecutionAttemptError::Rejected(error))
    }
}

fn canonical_source_error(
    error: norito::core::DecodeAttemptError,
) -> ExecutionAttemptError<QueryExecutionFail> {
    crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
        QueryExecutionFail::Conversion(error.to_string())
    })
}

pub(super) fn authenticate_canonical_block(
    height: NonZeroUsize,
    expected: HashOf<BlockHeader>,
    block: Option<iroha_data_model::block::SharedSignedBlock>,
) -> Result<iroha_data_model::block::SharedSignedBlock, CanonicalHistoryError> {
    let height_u64 = u64::try_from(height.get())
        .expect("supported target pointer widths always fit a block height into u64");
    let block = block.ok_or(CanonicalHistoryError::BodyUnavailable {
        height: height_u64,
        expected_hash: expected,
    })?;
    let actual = block.hash();
    if actual != expected {
        return Err(CanonicalHistoryError::BlockHashMismatch {
            height: height_u64,
            expected_hash: expected,
            actual_hash: actual,
        });
    }
    if block.header().height().get() != height_u64 {
        return Err(CanonicalHistoryError::BlockHeightMismatch {
            height: height_u64,
            actual_height: block.header().height().get(),
        });
    }
    Ok(block)
}

pub(super) fn committed_block_from_kura(
    kura: &Kura,
    height: NonZeroUsize,
    expected: HashOf<BlockHeader>,
    budget: &AllocationBudget,
) -> Result<
    Option<iroha_data_model::block::SharedSignedBlock>,
    ExecutionAttemptError<CanonicalHistoryError>,
> {
    let block = kura.get_block(height, budget).map_err(|error| {
        error.map_rejection(|_| CanonicalHistoryError::BodyUnavailable {
            height: height.get() as u64,
            expected_hash: expected,
        })
    })?;
    block
        .map(|block| {
            authenticate_canonical_block(height, expected, Some(block)).map_err(Into::into)
        })
        .transpose()
}

/// Immutable, WSV-anchored source of canonical committed block bodies.
///
/// Every load authenticates both the header hash and one-based header height.
/// An authenticated hash-only snapshot entry is reported as an explicit body
/// availability failure and is never omitted from iteration.
#[derive(Clone)]
pub struct CanonicalHistorySource<'a> {
    kura: &'a Kura,
    block_hashes: &'a dyn super::BlockHashRead,
    tip: Option<super::NativeExecutionTip>,
    budget: AllocationBudget,
}

/// Where a descending walk starts: the original tip or a verified checkpoint.
#[derive(Clone, Copy)]
struct WalkStart {
    height: u64,
    iroha: HashOf<BlockHeader>,
    core: iroha_sumeragi::types::Hash32,
    result: iroha_sumeragi::types::Hash32,
}

impl WalkStart {
    fn tip(tip: super::NativeExecutionTip) -> Self {
        Self {
            height: tip.height(),
            iroha: tip.iroha_hash(),
            core: tip.core_hash(),
            result: tip.result(),
        }
    }
}

impl<'a> CanonicalHistorySource<'a> {
    /// Borrow this exact captured source's physical allocation owner.
    /// No pool is created, replaced or inferred from a later State view.
    pub(crate) fn allocation_budget(&self) -> &AllocationBudget {
        &self.budget
    }

    /// Bind an off-chain walk to the actual caller's original source backing.
    /// The caller keeps this same budget's synchronous codec scope installed.
    pub(crate) fn with_read_budget(mut self, budget: &CanonicalHistoryReadBudget) -> Self {
        self.budget = budget.frames().clone();
        self
    }
    pub(super) fn new(
        kura: &'a Kura,
        block_hashes: &'a dyn super::BlockHashRead,
        tip: Option<super::NativeExecutionTip>,
        budget: AllocationBudget,
    ) -> Self {
        Self {
            kura,
            block_hashes,
            tip,
            budget,
        }
    }

    /// Return the committed height captured by this immutable source.
    #[must_use]
    pub fn height(&self) -> usize {
        self.block_hashes.len()
    }

    /// Resolve a committed header hash from the immutable WSV journal.
    #[must_use]
    pub fn block_height_by_hash(&self, hash: HashOf<BlockHeader>) -> Option<NonZeroUsize> {
        self.block_hashes
            .iter()
            .position(|candidate| *candidate == hash)
            .and_then(|index| index.checked_add(1))
            .and_then(NonZeroUsize::new)
    }

    fn expected_hash(
        &self,
        height: NonZeroUsize,
    ) -> Result<HashOf<BlockHeader>, CanonicalHistoryError> {
        self.block_hashes
            .get(height.get() - 1)
            .copied()
            .ok_or_else(|| CanonicalHistoryError::HeightOutsideSnapshot {
                height: u64::try_from(height.get())
                    .expect("supported target pointer widths fit a block height into u64"),
                committed_height: u64::try_from(self.height())
                    .expect("supported target pointer widths fit a block height into u64"),
            })
    }

    fn load(
        &self,
        height: NonZeroUsize,
    ) -> Result<
        iroha_data_model::block::SharedSignedBlock,
        ExecutionAttemptError<CanonicalHistoryError>,
    > {
        let expected_hash = self.expected_hash(height)?;
        if self.kura.is_canonical_body_missing(height) {
            return Err(CanonicalHistoryError::BodyUnavailable {
                height: u64::try_from(height.get())
                    .expect("supported target pointer widths fit a block height into u64"),
                expected_hash,
            }
            .into());
        }
        let block = self.kura.get_block(height, &self.budget).map_err(|error| {
            error.map_rejection(|_| CanonicalHistoryError::BodyUnavailable {
                height: height.get() as u64,
                expected_hash,
            })
        })?;
        authenticate_canonical_block(height, expected_hash, block).map_err(Into::into)
    }

    /// Load a body whose header hash and height agree with this snapshot.
    ///
    /// Output readers must use `executed_block` to bind attached outputs to
    /// exact finalized bytes; the proposal header does not commit those bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed availability error for a missing or authenticated
    /// hash-only body, and a typed corruption error when the Kura body
    /// contradicts the committed WSV hash journal or slot.
    pub fn block(
        &self,
        height: NonZeroUsize,
    ) -> Result<
        iroha_data_model::block::SharedSignedBlock,
        ExecutionAttemptError<CanonicalHistoryError>,
    > {
        self.load(height)
    }

    /// Load one canonical body after the caller admits its exact durable frame.
    /// Metadata and cache presence cannot authorize unpaid body I/O or decoding.
    /// The caller retains one allocation scope across this and subsequent reads.
    pub(crate) fn block_with_admission(
        &self,
        height: NonZeroUsize,
        mut before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<QueryExecutionFail>>
    {
        self.block_with_original_admission(height, None, &mut before_read)
    }

    /// One shared canonical loader, optionally retaining the consumer's actual
    /// preflight descriptor. A length scalar cannot replace its original slot.
    fn block_with_original_admission(
        &self,
        height: NonZeroUsize,
        original: Option<&crate::kura::NativeFrameRead<'_>>,
        mut before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<QueryExecutionFail>>
    {
        let expected = self
            .expected_hash(height)
            .map_err(QueryExecutionFail::CanonicalHistory)?;
        let height_u64 = height.get() as u64;
        let missing = || {
            ExecutionAttemptError::Rejected(QueryExecutionFail::CanonicalHistory(
                CanonicalHistoryError::BodyUnavailable {
                    height: height_u64,
                    expected_hash: expected,
                },
            ))
        };
        if self.kura.is_canonical_body_missing(height) {
            return Err(missing());
        }
        let storage_error = |error| {
            if !cfg!(all(test, sumeragi_core_mutation = "HC253"))
                && matches!(&error, crate::kura::Error::NativeJournalUnavailable(_, _))
            {
                return missing();
            }
            kura_read_attempt_error(error, |error| {
                // Preserve the existing deterministic diagnostics after classification.
                let reason = match error {
                    crate::kura::Error::NoritoFrame(error) => error.to_string(),
                    crate::kura::Error::CodecAttempt(error) => error.to_string(),
                    error => error.to_string(),
                };
                QueryExecutionFail::Conversion(reason)
            })
        };
        let source = self
            .kura
            .native_frame_read(height_u64, expected)
            .map_err(storage_error)?
            .ok_or_else(missing)?;
        let source = match original {
            Some(original) if original.same_original_slot(&source) => original,
            Some(_) => {
                return Err(QueryExecutionFail::Conversion(
                    "native event target differs from its original admitted slot".into(),
                )
                .into());
            }
            None => &source,
        };
        let wire_len = source.wire_len();
        before_read(1, wire_len)?;
        let shell = SharedSignedBlock::reserve(&self.budget)
            .map_err(|error| ExecutionAttemptError::Deferred(error.into()))?;
        let bytes = source
            .read_original(wire_len, &self.budget)
            .map_err(storage_error)?
            .ok_or_else(missing)?;
        let block = iroha_data_model::block::decode_framed_signed_block(&bytes)
            .map_err(canonical_source_error)?;
        authenticate_canonical_block(height, expected, Some(shell.initialize(block))).map_err(
            |error| ExecutionAttemptError::Rejected(QueryExecutionFail::CanonicalHistory(error)),
        )
    }

    /// Read execution identity through the original State tip, without inspecting
    /// any local QC. Every source frame is admitted before its bytes are read.
    /// Callbacks retain their original typed local refusal; semantic query errors
    /// stay rejected even when their transport representation is a budget error.
    /// Parent core hash, parent R and Iroha parent hash jointly authenticate the
    /// reverse walk. The finite captured tip bounds its number of source frames.
    pub(crate) fn executed_receipt(
        &self,
        height: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<
        crate::sumeragi::certified_chain::CommittedBlock,
        ExecutionAttemptError<QueryExecutionFail>,
    > {
        let mut receipt = None;
        self.visit_executed_backwards(height, height, before_read, |value| {
            receipt = Some(value);
            Ok(())
        })?;
        receipt.ok_or_else(|| {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(
                "requested execution was absent from its authenticated interval".into(),
            ))
        })
    }

    /// Visit one inclusive execution interval in descending height order after a single
    /// authenticated walk from this source's original native tip. Every physical source
    /// is charged before reading; only authenticated receipts in the selected interval
    /// reach the visitor. No local certificate is parsed or trusted.
    pub(crate) fn visit_executed_backwards(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        mut visit: impl FnMut(
            crate::sumeragi::certified_chain::CommittedBlock,
        ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> {
        self.visit_executed_backwards_until(first, last, before_read, |value| {
            visit(value).map(|()| core::ops::ControlFlow::Continue(()))
        })
        .map(drop)
    }

    /// Authenticate one ancestry walk, stopping before older source I/O when requested.
    ///
    /// Returns whether the selected interval was exhausted. Skipped ancestors still
    /// consume admitted source work and bytes before reading; every visited receipt
    /// is bound to this original State tip through its exact parent identities.
    pub(crate) fn visit_executed_backwards_until(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        mut visit: impl FnMut(
            crate::sumeragi::certified_chain::CommittedBlock,
        ) -> Result<
            core::ops::ControlFlow<()>,
            ExecutionAttemptError<QueryExecutionFail>,
        >,
    ) -> Result<bool, ExecutionAttemptError<QueryExecutionFail>> {
        self.visit_executed_backwards_admitted_until(first, last, before_read, |receipt| {
            visit(receipt.into_owned())
        })
    }

    /// The same original-tip walk, retaining exact receipt slots from this source's pool.
    /// Only the selected consumer may retain slots; each skipped ancestor retires in place.
    /// Source, ancestry, checkpoints and complete result validation use the common kernel.
    pub(crate) fn visit_executed_backwards_admitted_until(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        visit: impl FnMut(
            crate::sumeragi::certified_chain::AdmittedCommittedBlock,
        ) -> Result<
            core::ops::ControlFlow<()>,
            ExecutionAttemptError<QueryExecutionFail>,
        >,
    ) -> Result<bool, ExecutionAttemptError<QueryExecutionFail>> {
        let tip = self.walk_tip(first, last)?;
        self.walk_backwards(WalkStart::tip(tip), first, last, None, before_read, visit)
    }

    /// The same authenticated walk, with the target's original native descriptor.
    /// The original slot is rechecked before target admission or body I/O; unrelated
    /// ancestors use the existing loader and exact source/refusal rules unchanged.
    pub(crate) fn visit_executed_backwards_with_original_target(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
        original_target: &crate::kura::NativeFrameRead<'_>,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        mut visit: impl FnMut(
            crate::sumeragi::certified_chain::CommittedBlock,
        ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> {
        let tip = self.walk_tip(first, last)?;
        self.walk_backwards(
            WalkStart::tip(tip),
            first,
            last,
            Some(original_target),
            before_read,
            |value| visit(value.into_owned()).map(|()| core::ops::ControlFlow::Continue(())),
        )
        .map(drop)
    }

    /// [`Self::visit_executed_backwards_until`] for off-chain readers: the walk
    /// starts at the nearest verified checkpoint at or above `last` instead of
    /// the tip, so it reads at most
    /// [`HISTORY_CHECKPOINT_INTERVAL`](crate::kura::history_checkpoints::HISTORY_CHECKPOINT_INTERVAL)
    /// blocks above the interval. Source work then depends on node-local
    /// checkpoints, so this must never feed on-chain metering.
    pub(crate) fn visit_executed_backwards_from_checkpoints(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        mut visit: impl FnMut(
            crate::sumeragi::certified_chain::CommittedBlock,
        ) -> Result<
            core::ops::ControlFlow<()>,
            ExecutionAttemptError<QueryExecutionFail>,
        >,
    ) -> Result<bool, ExecutionAttemptError<QueryExecutionFail>> {
        let tip = self.walk_tip(first, last)?;
        let selected_last =
            u64::try_from(last.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
        let start = self
            .checkpoint_start(selected_last, tip.height())
            .unwrap_or_else(|| WalkStart::tip(tip));
        self.walk_backwards(start, first, last, None, before_read, |receipt| {
            visit(receipt.into_owned())
        })
    }

    /// The authenticated tip of this captured history, after checking the interval.
    fn walk_tip(
        &self,
        first: NonZeroUsize,
        last: NonZeroUsize,
    ) -> Result<super::NativeExecutionTip, ExecutionAttemptError<QueryExecutionFail>> {
        if first > last {
            return Err(QueryExecutionFail::Conversion(
                "native execution interval is reversed".into(),
            )
            .into());
        }
        self.expected_hash(first)
            .and_then(|_| self.expected_hash(last))
            .map_err(QueryExecutionFail::CanonicalHistory)?;
        let invalid = |message: &str| {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message.into()))
        };
        let tip = self
            .tip
            .ok_or_else(|| invalid("State has no authenticated native execution tip"))?;
        if usize::try_from(tip.height()).ok() != Some(self.height()) {
            return Err(invalid(
                "native execution tip differs from the captured State history cut",
            ));
        }
        Ok(tip)
    }

    /// The nearest checkpoint at or above `target` that this history's hash
    /// journal confirms; contradicted checkpoints are dropped.
    fn checkpoint_start(&self, target: u64, ceiling: u64) -> Option<WalkStart> {
        let checkpoints = self.kura.history_checkpoints();
        for (height, checkpoint) in checkpoints.candidates(target, ceiling) {
            let journal = usize::try_from(height)
                .ok()
                .and_then(NonZeroUsize::new)
                .and_then(|index| self.expected_hash(index).ok());
            if journal == Some(checkpoint.iroha_hash) {
                return Some(WalkStart {
                    height,
                    iroha: checkpoint.iroha_hash,
                    core: checkpoint.core_hash,
                    result: checkpoint.result,
                });
            }
            checkpoints.forget(height, &checkpoint);
        }
        None
    }

    fn walk_backwards(
        &self,
        start: WalkStart,
        first: NonZeroUsize,
        last: NonZeroUsize,
        original_target: Option<&crate::kura::NativeFrameRead<'_>>,
        mut before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        mut visit: impl FnMut(
            crate::sumeragi::certified_chain::AdmittedCommittedBlock,
        ) -> Result<
            core::ops::ControlFlow<()>,
            ExecutionAttemptError<QueryExecutionFail>,
        >,
    ) -> Result<bool, ExecutionAttemptError<QueryExecutionFail>> {
        let invalid = |message: String| {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message))
        };
        let scope = self
            .tip
            .as_ref()
            .ok_or_else(|| {
                invalid("canonical history lacks its authenticated native root scope".into())
            })?
            .root_scope();
        let mut expected_iroha = start.iroha;
        let mut expected_core = start.core;
        let mut expected_result = start.result;
        let target =
            u64::try_from(first.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
        let selected_last =
            u64::try_from(last.get()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
        if start.height < selected_last {
            return Err(invalid(
                "requested execution lies beyond the walk's starting height".into(),
            ));
        }
        let checkpoints = self.kura.history_checkpoints();
        // This scope retains at most two fully validated exact context values.
        // It owns no source, certificate, freshness or ancestry verdict and dies
        // with this walk. Every durable frame and parent binding is still read
        // and checked below, including on a warmed or subsequent State view.
        let mut validation = iroha_data_model::sumeragi_finality::EpochValidationScope::new();
        for source_height in (target..=start.height).rev() {
            let index = usize::try_from(source_height)
                .ok()
                .and_then(NonZeroUsize::new)
                .ok_or(QueryExecutionFail::GasBudgetExceeded)?;
            let journal_hash = self
                .expected_hash(index)
                .map_err(QueryExecutionFail::CanonicalHistory)?;
            if journal_hash != expected_iroha {
                return Err(invalid(format!(
                    "native execution parent contradicts State hash at {source_height}"
                )));
            }
            let original = if source_height == selected_last {
                original_target
            } else {
                None
            };
            let block = self.block_with_original_admission(index, original, &mut before_read)?;
            let receipt = crate::sumeragi::certified_chain::AdmittedCommittedBlock::read(
                block,
                source_height,
                scope,
                &mut validation,
                &self.budget,
            )
            .map_err(|error| {
                error.map_rejection(|error| QueryExecutionFail::Conversion(error.to_string()))
            })?;
            Self::require_native_execution_link(&receipt, expected_core, expected_result)?;
            checkpoints.record(
                source_height,
                HistoryCheckpoint {
                    iroha_hash: journal_hash,
                    core_hash: expected_core,
                    result: expected_result,
                },
            );
            if source_height > target {
                let header = receipt
                    .header()
                    .ok_or_else(|| invalid("genesis cannot precede the requested height".into()))?;
                expected_core = header.parent_hash;
                expected_result = header.parent_result;
                expected_iroha =
                    receipt.block().header().prev_block_hash().ok_or_else(|| {
                        invalid("native successor omits Iroha parent hash".into())
                    })?;
            }
            if source_height <= selected_last {
                if visit(receipt)?.is_break() {
                    return Ok(false);
                }
            }
            if source_height == target {
                return Ok(true);
            }
        }
        Err(invalid(
            "requested execution lies beyond the original native tip".into(),
        ))
    }

    /// Load exact original execution bytes; the callback admits actual source
    /// count and bytes, including intermediate parents and a subsequently failed read.
    pub(crate) fn executed_block(
        &self,
        height: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<iroha_data_model::block::SharedSignedBlock, ExecutionAttemptError<QueryExecutionFail>>
    {
        self.executed_receipt(height, before_read)
            .map(|receipt| receipt.block().clone())
    }

    /// Iterate every committed slot from `start` through this source's tip.
    ///
    /// The cursor stops after its first error so callers cannot accidentally
    /// resume beyond an unavailable or corrupt canonical slot.
    #[must_use]
    pub fn cursor(self, start: NonZeroUsize) -> CanonicalHistoryCursor<'a> {
        let height = self.height();
        CanonicalHistoryCursor {
            source: self,
            front: start.get(),
            back_inclusive: height,
            done: start.get() > height,
        }
    }
}

/// Fallible double-ended cursor over canonical committed block bodies.
pub struct CanonicalHistoryCursor<'a> {
    source: CanonicalHistorySource<'a>,
    front: usize,
    back_inclusive: usize,
    done: bool,
}

impl CanonicalHistoryCursor<'_> {
    fn stop_on_error(
        &mut self,
        result: Result<
            iroha_data_model::block::SharedSignedBlock,
            ExecutionAttemptError<CanonicalHistoryError>,
        >,
    ) -> Result<
        iroha_data_model::block::SharedSignedBlock,
        ExecutionAttemptError<CanonicalHistoryError>,
    > {
        if result.is_err() {
            self.done = true;
        }
        result
    }
}

impl Iterator for CanonicalHistoryCursor<'_> {
    type Item = Result<
        iroha_data_model::block::SharedSignedBlock,
        ExecutionAttemptError<CanonicalHistoryError>,
    >;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let height = NonZeroUsize::new(self.front)
            .expect("a canonical history cursor starts at a non-zero height");
        if self.front == self.back_inclusive {
            self.done = true;
        } else {
            self.front += 1;
        }
        let result = self.source.block(height);
        Some(self.stop_on_error(result))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.done {
            0
        } else {
            self.back_inclusive
                .saturating_sub(self.front)
                .saturating_add(1)
        };
        (0, Some(remaining))
    }
}

impl DoubleEndedIterator for CanonicalHistoryCursor<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let height = NonZeroUsize::new(self.back_inclusive)
            .expect("a canonical history cursor ends at a non-zero height");
        if self.front == self.back_inclusive {
            self.done = true;
        } else {
            self.back_inclusive -= 1;
        }
        let result = self.source.block(height);
        Some(self.stop_on_error(result))
    }
}

impl std::iter::FusedIterator for CanonicalHistoryCursor<'_> {}

#[cfg(test)]
mod admission_tests;

impl CanonicalHistorySource<'_> {
    /// The shared receipt-to-original-ancestry relation, after canonical hash/height admission.
    /// These expected values come only from an opaque native tip or its verified child header.
    pub(crate) fn require_native_execution_link(
        receipt: &crate::sumeragi::certified_chain::CommittedBlock,
        expected_core: iroha_sumeragi::types::Hash32,
        expected_result: iroha_sumeragi::types::Hash32,
    ) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> {
        if receipt.core_hash() != expected_core || receipt.result() != expected_result {
            return Err(QueryExecutionFail::Conversion(format!(
                "native header or R differs from authenticated execution ancestry at {}",
                receipt.height()
            ))
            .into());
        }
        Ok(())
    }
}
