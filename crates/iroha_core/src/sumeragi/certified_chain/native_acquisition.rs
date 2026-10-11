//! Original native slot/body acquisition shared by ordinary reads and terminal AMX selection.
//!
//! Retained bytes are an acquired snapshot; source-object and geometry checks never replace
//! the full native verifier or claim continued equality with mutable disk contents. Complete
//! body decoding survives later refusal. Incomplete decoder graphs retire under the caller's
//! unchanged cumulative decoder context. Nested body/result graph funding remains open.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::block::{ReservedSharedSignedBlock, SharedSignedBlock};

// The completed body occupies its original prepaid shared shell, never an inline block.
// Field order destroys that body/control before raw bytes, source and the original pool.
// No additional control allocation or nested DTO graph clone is introduced here.
pub(super) struct NativeCarrierAcquisition<'kura> {
    decoded: Option<SharedSignedBlock>,
    bytes: Option<crate::kura::NativeFrameBytes>,
    shell: Option<ReservedSharedSignedBlock>,
    source: Option<crate::kura::NativeFrameRead<'kura>>,
    kura: &'kura Kura,
    index: NonZeroUsize,
    expected: HashOf<IrohaHeader>,
    maximum: usize,
    budget: AllocationBudget,
    delivered: bool,
}
impl<'kura> NativeCarrierAcquisition<'kura> {
    pub(super) fn new(
        kura: &'kura Kura,
        index: NonZeroUsize,
        expected: HashOf<IrohaHeader>,
        budget: AllocationBudget,
        maximum: usize,
    ) -> Self {
        Self {
            decoded: None,
            bytes: None,
            shell: None,
            source: None,
            kura,
            index,
            expected,
            maximum,
            budget,
            delivered: false,
        }
    }

    #[cfg(test)]
    pub(super) fn bytes_for_test(&self) -> Option<&crate::kura::NativeFrameBytes> {
        self.bytes.as_ref()
    }

    fn unavailable(&self) -> ChainReadError {
        ChainReadError::NotInView {
            height: self.index.get() as u64,
        }
    }

    pub(super) fn original_source(&mut self) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        let height = self.index.get() as u64;
        let current = self.current_source()?;
        if let Some(original) = &self.source {
            if !original.same_original_slot(&current) {
                return Err(self.unavailable().into());
            }
        } else {
            self.source = Some(current);
        }
        let wire_len = self
            .source
            .as_ref()
            .expect("original selected slot")
            .wire_len();
        if usize::try_from(wire_len).map_or(true, |length| length > self.maximum) {
            return Err(ChainReadError::Malformed {
                height,
                reason: "native finality carrier exceeds its bounded extent".into(),
            }
            .into());
        }
        Ok(())
    }

    fn current_source(
        &self,
    ) -> Result<crate::kura::NativeFrameRead<'kura>, ExecutionAttemptError<ChainReadError>> {
        let height = self.index.get() as u64;
        self.kura
            .native_frame_read(height, self.expected)
            .map_err(|error| native_read_error(height, error))?
            .ok_or_else(|| self.unavailable().into())
    }

    // A delivered body still owns its exact original raw acquisition. This checks only
    // current slot/object membership; it neither calls complete again nor rereads bytes.
    pub(super) fn recheck_original_source(
        &self,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        let original = self.source.as_ref().ok_or_else(|| self.unavailable())?;
        if !original.same_original_slot(&self.current_source()?) {
            return Err(self.unavailable().into());
        }
        Ok(())
    }

    pub(super) fn complete(
        &mut self,
    ) -> Result<SharedSignedBlock, ExecutionAttemptError<ChainReadError>> {
        let budget = self.budget.clone();
        budget.with_deferred_refund_notifications(|_| {
            self.prepare()?;
            Ok(self.deliver())
        })
    }
    fn prepare(&mut self) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        if self.delivered {
            return Err(self.unavailable().into());
        }
        self.original_source()?;
        let height = self.index.get() as u64;
        if self.bytes.is_none() {
            let source = self.source.as_ref().expect("original selected slot");
            self.bytes = Some(
                source
                    .read_original(source.wire_len(), &self.budget)
                    .map_err(|error| native_read_error(height, error))?
                    .ok_or_else(|| self.unavailable())?,
            );
        }
        self.decode_original_body()?;
        Ok(())
    }
    // Reserve the original shell before the sole canonical body decoder. This phase
    // is shared by retained and one-shot reads; incomplete decoder graphs still retire.
    fn decode_original_body(&mut self) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        if self.decoded.is_some() {
            return Ok(());
        }
        let height = self.index.get() as u64;
        if self.shell.is_none() {
            self.shell = Some(match SharedSignedBlock::reserve(&self.budget) {
                Ok(shell) => shell,
                Err(cause) => {
                    #[cfg(all(test, sumeragi_core_mutation = "HC186"))]
                    {
                        self.bytes = None;
                    }
                    return Err(ExecutionAttemptError::Deferred(cause.into()));
                }
            });
        }
        let block = iroha_data_model::block::decode_framed_signed_block(
            self.bytes.as_ref().expect("original complete native frame"),
        )
        .map_err(|error| {
            crate::execution_attempt::canonical_decode_attempt_error(error, |_| self.unavailable())
        })?;
        if block.hash() != self.expected || block.header().height().get() != height {
            return Err(self.unavailable().into());
        }
        // The original shell was admitted before decoding. Initialization cannot allocate,
        // fail or invoke callbacks, and no fallible work separates this move from delivery.
        // Keeping its small handle avoids embedding a complete SignedBlock in every moved
        // target/gap acquisition while preserving the exact original graph and charge.
        self.decoded = Some(
            self.shell
                .take()
                .expect("original admitted control")
                .initialize(block),
        );
        Ok(())
    }
    fn deliver(&mut self) -> SharedSignedBlock {
        self.delivered = true;
        self.decoded
            .take()
            .expect("original initialized native graph")
    }
}

// Preserve the shared reader's original classification before any diagnostic projection.
fn native_read_error(
    height: u64,
    error: crate::kura::Error,
) -> ExecutionAttemptError<ChainReadError> {
    let unavailable = || ChainReadError::NotInView { height };
    match error {
        crate::kura::Error::NoritoFrame(error) => read_decode_error(height, error),
        crate::kura::Error::BlockDecode(error) => {
            crate::execution_attempt::canonical_decode_attempt_error(error, |_| unavailable())
        }
        crate::kura::Error::NativeFrameAllocation(error) => {
            let deferred = match error {
                iroha_allocation::ChargedBufferError::Admission(original) => original.into(),
                iroha_allocation::ChargedBufferError::Allocator { .. } => {
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                }
            };
            ExecutionAttemptError::Deferred(deferred)
        }
        _ => unavailable().into(),
    }
}

#[cfg(test)]
mod tests;
