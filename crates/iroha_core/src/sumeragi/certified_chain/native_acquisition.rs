//! Original native slot/body acquisition shared by ordinary reads and terminal AMX selection.
//!
//! Retained bytes are an acquired snapshot; source-object and geometry checks never replace
//! the full native verifier or claim continued equality with mutable disk contents. Complete
//! body decoding and the existing prepared model children survive later refusal under
//! the same original source, counter controls and finite pool. Transactions, results,
//! evidence and other ordinary nested owning leaves still require dedicated custody.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationCharge, SharedFromChargeError};
use iroha_data_model::block::{
    PreparedSignedBlockSignaturesDecode, ReservedSharedSignedBlock, SharedSignedBlock,
};

// The completed body occupies its original prepaid shared shell, never an inline block.
// Field order destroys that body/control before raw bytes, source and the original pool.
// No additional control allocation or nested DTO graph clone is introduced here.
pub(crate) struct NativeCarrierAcquisition<'kura> {
    decoded: Option<SharedSignedBlock>,
    decoder: Option<PreparedSignedBlockSignaturesDecode>,
    shell: Option<ReservedSharedSignedBlock>,
    shell_charge: Option<AllocationCharge>,
    bytes: Option<crate::kura::NativeFrameBytes>,
    source: Option<OriginalFrameSource<'kura>>,
    kura: KuraOwner<'kura>,
    index: NonZeroUsize,
    expected: HashOf<IrohaHeader>,
    maximum: usize,
    budget: AllocationBudget,
    delivered: bool,
}
enum KuraOwner<'kura> {
    Borrowed(&'kura Kura),
    Owned(Arc<Kura>),
}
enum OriginalFrameSource<'kura> {
    Borrowed(crate::kura::NativeFrameRead<'kura>),
    Owned(crate::kura::OwnedNativeFrameRead),
}
impl OriginalFrameSource<'_> {
    fn wire_len(&self) -> u64 {
        match self {
            Self::Borrowed(source) => source.wire_len(),
            Self::Owned(source) => source.wire_len(),
        }
    }
    fn same_original_slot(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Borrowed(left), Self::Borrowed(right)) => left.same_original_slot(right),
            (Self::Owned(left), Self::Owned(right)) => left.same_original_slot(right),
            _ => false,
        }
    }
    fn read_original(
        &mut self,
        length: u64,
        budget: &AllocationBudget,
    ) -> std::result::Result<Option<crate::kura::NativeFrameBytes>, crate::kura::Error> {
        match self {
            Self::Borrowed(source) => source.read_original(length, budget),
            Self::Owned(source) => source.read_original(length, budget),
        }
    }
}
impl NativeCarrierAcquisition<'static> {
    /// Retain the actual shared storage owner, lending the same acquisition kernel.
    pub(crate) fn new_owned(
        kura: Arc<Kura>,
        index: NonZeroUsize,
        expected: HashOf<IrohaHeader>,
        budget: AllocationBudget,
        maximum: usize,
    ) -> Self {
        Self {
            decoded: None,
            decoder: None,
            shell: None,
            shell_charge: None,
            bytes: None,
            source: None,
            kura: KuraOwner::Owned(kura),
            index,
            expected,
            maximum,
            budget,
            delivered: false,
        }
    }
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
            decoder: None,
            shell: None,
            shell_charge: None,
            bytes: None,
            source: None,
            kura: KuraOwner::Borrowed(kura),
            index,
            expected,
            maximum,
            budget,
            delivered: false,
        }
    }

    /// Adopt the actual frame selected before the execution consumer admitted its extent.
    /// The ordinary acquisition kernel still rechecks its backend and occupied slot.
    pub(super) fn from_admitted_source(
        kura: &'kura Kura,
        source: crate::kura::NativeFrameRead<'kura>,
        index: NonZeroUsize,
        expected: HashOf<IrohaHeader>,
        budget: AllocationBudget,
        maximum: usize,
    ) -> Self {
        let mut original = Self::new(kura, index, expected, budget, maximum);
        original.source = Some(OriginalFrameSource::Borrowed(source));
        original
    }

    /// Borrow the actual acquired frame for the execution reader's canonical check.
    pub(super) fn original_bytes(&self) -> Option<&crate::kura::NativeFrameBytes> {
        self.bytes.as_ref()
    }

    /// Move the same original frame only after its body has been delivered.
    pub(super) fn take_delivered_bytes(&mut self) -> Option<crate::kura::NativeFrameBytes> {
        if self.delivered {
            self.bytes.take()
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(super) fn bytes_for_test(&self) -> Option<&crate::kura::NativeFrameBytes> {
        self.bytes.as_ref()
    }

    /// Retry must name the same original backend, slot, expected hash and caller pool.
    pub(crate) fn matches_owner(
        &self,
        kura: &Kura,
        height: u64,
        expected: HashOf<IrohaHeader>,
        budget: &AllocationBudget,
    ) -> bool {
        let original = match &self.kura {
            KuraOwner::Borrowed(owner) => *owner,
            KuraOwner::Owned(owner) => owner.as_ref(),
        };
        core::ptr::eq(original, kura)
            && self.index.get() as u64 == height
            && self.expected == expected
            && self.budget.same_pool(budget)
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
    ) -> Result<OriginalFrameSource<'kura>, ExecutionAttemptError<ChainReadError>> {
        let height = self.index.get() as u64;
        match &self.kura {
            KuraOwner::Borrowed(kura) => (*kura)
                .native_frame_read(height, self.expected)
                .map(|source| source.map(OriginalFrameSource::Borrowed)),
            KuraOwner::Owned(kura) => kura
                .native_frame_read_owned(height, self.expected)
                .map(|source| source.map(OriginalFrameSource::Owned)),
        }
        .map_err(|error| native_read_error(height, error))?
        .ok_or_else(|| self.unavailable().into())
    }

    // A delivered body still owns its exact original raw acquisition. This checks only
    // current slot/object membership; it neither calls complete again nor rereads bytes.
    pub(crate) fn recheck_original_source(
        &self,
    ) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        let original = self.source.as_ref().ok_or_else(|| self.unavailable())?;
        if !original.same_original_slot(&self.current_source()?) {
            return Err(self.unavailable().into());
        }
        Ok(())
    }

    pub(crate) fn complete(
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
            let source = self.source.as_mut().expect("original selected slot");
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
    // is shared by retained and initial reads. Store the original model decoder before
    // entering it, so all persistent callers retain its partial prepared children.
    // TODO: Ordinary nested body/result/evidence leaves still require their own
    // retained funding; raw destination custody is not full-graph custody.
    fn decode_original_body(&mut self) -> Result<(), ExecutionAttemptError<ChainReadError>> {
        if self.decoded.is_some() {
            return Ok(());
        }
        let height = self.index.get() as u64;
        if self.shell.is_none() {
            if self.shell_charge.is_none() {
                let mut reservation = self
                    .budget
                    .try_reserve(SharedSignedBlock::allocation_layout())
                    .map_err(|cause| {
                        #[cfg(all(test, sumeragi_core_mutation = "HC186"))]
                        {
                            self.bytes = None;
                        }
                        ExecutionAttemptError::Deferred(cause.into())
                    })?;
                self.shell_charge = Some(
                    reservation
                        .try_split(SharedSignedBlock::allocation_layout())
                        .expect("exact original shared body charge"),
                );
            }
            match SharedSignedBlock::reserve_from_charge(
                self.shell_charge.take().expect("original shell charge"),
            ) {
                Ok(shell) => self.shell = Some(shell),
                Err((charge, error)) => {
                    if !cfg!(all(test, sumeragi_core_mutation = "HC468")) {
                        self.shell_charge = Some(charge);
                    }
                    return Err(match error {
                        original @ SharedFromChargeError::Allocator { .. } => {
                            ExecutionAttemptError::Deferred(
                                iroha_allocation::AllocatorRefusal::try_from(original)
                                    .expect("actual native shell allocator cause")
                                    .into(),
                            )
                        }
                        _ => self.unavailable().into(),
                    });
                }
            }
        }
        if self.decoder.is_none() {
            self.decoder = Some(
                PreparedSignedBlockSignaturesDecode::new(&self.budget).map_err(|error| {
                    crate::execution_attempt::prepared_signature_block_attempt_error(error, |_| {
                        ChainReadError::NotInView { height }
                    })
                })?,
            );
        }
        let source = self
            .bytes
            .as_ref()
            .expect("original complete native frame")
            .charged_source();
        let result = self
            .decoder
            .as_mut()
            .expect("original retained model decoder")
            .decode(
                source,
                norito::core::SequenceSpan {
                    start: 0,
                    end: source.as_slice().len(),
                },
                norito::canonical_decode_limits(source.as_slice().len()),
            );
        #[cfg(all(test, sumeragi_core_mutation = "HC467"))]
        if result.is_err() {
            self.decoder = None;
        }
        let block = result.map_err(|error| {
            crate::execution_attempt::prepared_signature_block_attempt_error(error, |_| {
                ChainReadError::NotInView { height }
            })
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
        // Keep the existing completed raw-frame diagnostic and mutation boundary.
        crate::kura::Error::NoritoFrame(error) => read_decode_error(height, error),
        original => {
            crate::execution_attempt::kura_read_attempt_error(original, |error| match error {
                crate::kura::Error::CodecAttempt(error) => ChainReadError::Malformed {
                    height,
                    reason: error.to_string(),
                },
                _ => unavailable(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
