//! Caller-prepared spans using the same canonical element-sequence parser.

use super::*;

/// Original byte failure or an unchanged caller-owned scratch planning mismatch.
#[derive(Debug, thiserror::Error)]
pub enum SequenceDestinationError {
    /// Original canonical parsing or active logical-budget failure.
    #[error(transparent)]
    Codec(#[from] Error),
    /// The prepared bank is smaller than the already-admitted input shape.
    /// This is local destination geometry, never intrinsic protocol invalidity.
    #[error("prepared sequence holds {available} slots but needs {required}")]
    Storage {
        /// Number of initialized slots selected before the attempt.
        available: usize,
        /// Original declared count, after canonical sequence-limit admission.
        required: usize,
    },
}

/// Complete element spans borrowed from the original input and prepared scratch.
///
/// The entire original sequence framing is checked before an element is decoded,
/// preserving the ordinary owned planner's late-framing-error precedence. No
/// span Vec is allocated and no scratch escapes its exclusive preparation borrow.
pub struct PreparedElementSequence<'input, 'scratch> {
    bytes: &'input [u8],
    spans: &'scratch [SequenceSpan],
    used: usize,
}
impl PreparedElementSequence<'_, '_> {
    /// Original number of canonically framed elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }
    /// Whether the admitted sequence is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
    /// Exact original sequence prefix length; outer boundaries reject trailing bytes.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used
    }

    /// Visit canonical element fields using the same owning leaf relationship.
    ///
    /// This is the generic element layout even for `u8`, as used by `ConstVec`;
    /// `Vec<u8>`'s raw layout uses [`decode_raw_byte_sequence_into`]. Each caller
    /// uses [`CanonicalField::with_payload`] and prepared leaf/record storage.
    /// Nominal sequence storage remains charged to the active logical wire-work
    /// limits exactly as in the owning Vec decoder. This is not physical pool
    /// admission: the original owner must already hold all element destinations.
    ///
    /// # Errors
    /// Returns the original codec or caller-owned destination cause. A prefix may
    /// have been written on error; the enclosing retained owner resets validity
    /// without replacing any destination backing before reuse.
    pub fn decode_elements<T, E>(
        &self,
        mut visit: impl FnMut(usize, CanonicalField<'_, T>) -> Result<(), DecodeIntoError<E>>,
    ) -> Result<(), DecodeIntoError<E>>
    where
        T: for<'de> DeserializePayload<'de> + SerializePayload,
    {
        reserve_decode_sequence_storage::<T>(self.spans.len())?;
        for (index, span) in self.spans.iter().enumerate() {
            let element = span.get(self.bytes)?;
            record_slice_access(element, span.len());
            visit(
                index,
                field_destination::canonical_field_from_slice(element),
            )?;
        }
        Ok(())
    }
}

/// Original sequence failure or exact original-pool backing refusal.
///
/// Successful logical work is never refunded, including when physical admission
/// or later framing fails. Formatting either cause requires no diagnostic String.
#[derive(Debug, thiserror::Error)]
pub enum SequenceAdmissionError {
    /// Original canonical framing or active cumulative decode-work failure.
    #[error(transparent)]
    Codec(#[from] Error),
    /// Original finite pool refusal or failure to allocate its admitted layout.
    #[error(transparent)]
    Allocation(#[from] iroha_allocation::ChargedBufferError),
}

/// Canonical spans in exact original-pool backing, borrowing their original input.
///
/// No preliminary shape traversal, uncharged span Vec or maximum-sized scratch
/// bank is needed. The private spans cannot be rebound to different source bytes.
/// The owner funds only its span allocation; enclosing source, decode controls
/// and element destinations remain the integrating caller's obligations.
pub struct ChargedElementSequence<'input> {
    bytes: &'input [u8],
    spans: iroha_allocation::ChargedBuffer<SequenceSpan>,
    used: usize,
}

impl<'input> ChargedElementSequence<'input> {
    /// Admit exact span backing at the ordinary sequence planner's allocation point.
    ///
    /// The caller provides the original advertised flags and bounded decode
    /// context. Count, minimum framing and logical span admission precede the
    /// physical request; the sole scalar walker then checks all element framing
    /// once, before any element can be decoded. A failed attempt drops partial
    /// physical storage before returning its credit, while cumulative decode work
    /// remains consumed. No prepared backing escapes a refusal.
    ///
    /// # Errors
    /// Preserves the original codec cause or exact physical admission refusal.
    /// An outer field must separately require `as_prepared().used() == bytes.len()`.
    pub fn try_from_payload(
        bytes: &'input [u8],
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, SequenceAdmissionError> {
        let (count, flags) = admit_charged_sequence_spans(bytes)?;
        let mut spans = iroha_allocation::ChargedBuffer::new(count, budget)?;
        let used = fill_charged_sequence_spans(bytes, flags, count, &mut spans)?;
        Ok(Self { bytes, spans, used })
    }

    /// Borrow the same spans for canonical element decoding without planning again.
    ///
    /// The caller retains the original field context and advertised flags while
    /// decoding. Each call to `decode_elements` consumes the original element-work
    /// quota; borrowing this view never resets or replenishes decode counters.
    #[must_use]
    pub fn as_prepared(&self) -> PreparedElementSequence<'input, '_> {
        PreparedElementSequence {
            bytes: self.bytes,
            spans: self.spans.as_slice(),
            used: self.used,
        }
    }

    /// Whether the actual span backing retains this exact original finite pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.spans.belongs_to(budget)
    }
}

// Both one-shot and retained owners enter the same admission and framing kernels.
// Replaying a retained owner still consumes the current cumulative decode scope.
fn admit_charged_sequence_spans(bytes: &[u8]) -> Result<(usize, u8), Error> {
    let (count, _) = read_seq_len_slice(bytes)?;
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    validate_binary_sequence_reservation(bytes, flags, count)?;
    reserve_decode_sequence_storage::<SequenceSpan>(count)?;
    Ok((count, flags))
}

fn fill_charged_sequence_spans(
    bytes: &[u8],
    flags: u8,
    count: usize,
    spans: &mut iroha_allocation::ChargedBuffer<SequenceSpan>,
) -> Result<usize, Error> {
    // SequenceSpan has no nested allocation. Clearing initialized entries cannot
    // release backing credit or notify a waiter blocked by this same pool.
    spans.truncate(0);
    let used = byte_sequence::visit_binary_sequence_with_count(bytes, flags, count, |span| {
        spans.push_reserved(span);
        Ok(())
    })?;
    note_payload_access(bytes, used);
    Ok(used)
}

/// Original sequence refusal or invalid reuse of retained sequence storage.
#[derive(Debug, thiserror::Error)]
pub enum RetainedSequenceError {
    /// Unchanged canonical or physical allocation refusal.
    #[error(transparent)]
    Admission(#[from] SequenceAdmissionError),
    /// The supplied slice, contents, or advertised flags differ from admission.
    #[error("retained sequence source or advertised flags changed")]
    SourceMismatch,
    /// The last preparation did not complete; partial spans grant no decoded view.
    #[error("retained sequence preparation is incomplete")]
    Incomplete,
}

struct SequenceSource {
    address: usize,
    length: usize,
    digest: blake3::Hash,
    flags: u8,
}
impl SequenceSource {
    fn new(bytes: &[u8], flags: u8) -> Self {
        Self {
            address: bytes.as_ptr().addr(),
            length: bytes.len(),
            digest: blake3::hash(bytes),
            flags,
        }
    }

    fn matches(&self, bytes: &[u8], flags: u8) -> bool {
        self.address == bytes.as_ptr().addr()
            && self.length == bytes.len()
            && self.flags == flags
            && self.digest == blake3::hash(bytes)
    }
}

/// Span storage retained across refusals without borrowing or copying the input.
///
/// The caller retains the original bounded immutable input, decode controls and
/// element destinations. This owner admits only the exact span layout from its
/// original pool. Once admitted, backing survives later framing failures and
/// retries. A stored slice address is compared only, never dereferenced; a digest
/// additionally rejects content changes even when an allocation stays in place.
/// This binding grants no protocol authority and creates no self-reference.
pub struct RetainedElementSequence {
    budget: iroha_allocation::AllocationBudget,
    source: Option<SequenceSource>,
    spans: Option<iroha_allocation::ChargedBuffer<SequenceSpan>>,
    used: Option<usize>,
}

impl RetainedElementSequence {
    /// Retain the original pool handle without allocating or inspecting an input.
    #[must_use]
    pub fn new(budget: &iroha_allocation::AllocationBudget) -> Self {
        Self {
            budget: budget.clone(),
            source: None,
            spans: None,
            used: None,
        }
    }

    /// Prepare the original sequence while retaining every admitted span allocation.
    ///
    /// Count, flags, minimum framing and logical span charges precede physical
    /// admission, exactly as in [`ChargedElementSequence::try_from_payload`].
    /// The admitted slice and flags are bound before the sole canonical walker
    /// runs. Every retry replays this work in the current cumulative scope; no
    /// quota is reset or refunded. Failed preparation invalidates the decoded
    /// view without dropping backing or waking original-pool capacity waiters.
    ///
    /// # Errors
    /// Returns the original codec/allocation cause or rejects changed source data.
    /// A containing field must still enforce `as_prepared(bytes)?.used() == bytes.len()`.
    pub fn prepare(&mut self, bytes: &[u8]) -> Result<(), RetainedSequenceError> {
        self.used = None;
        let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
        if self
            .source
            .as_ref()
            .is_some_and(|source| !source.matches(bytes, flags))
        {
            return Err(RetainedSequenceError::SourceMismatch);
        }
        let (count, flags) =
            admit_charged_sequence_spans(bytes).map_err(SequenceAdmissionError::Codec)?;
        if self.spans.is_none() {
            self.spans = Some(
                iroha_allocation::ChargedBuffer::new(count, &self.budget)
                    .map_err(SequenceAdmissionError::Allocation)?,
            );
            self.source = Some(SequenceSource::new(bytes, flags));
        }
        let spans = self.spans.as_mut().expect("span storage admitted above");
        let used = fill_charged_sequence_spans(bytes, flags, count, spans)
            .map_err(SequenceAdmissionError::Codec)?;
        self.used = Some(used);
        Ok(())
    }

    /// Lend completed spans and the same checked input through separate lifetimes.
    ///
    /// Borrowing performs no allocation or new preparation. Element decoding
    /// still charges its ordinary work through [`PreparedElementSequence::decode_elements`].
    ///
    /// # Errors
    /// Rejects incomplete preparation, substituted input, changed bytes or flags.
    pub fn as_prepared<'input>(
        &self,
        bytes: &'input [u8],
    ) -> Result<PreparedElementSequence<'input, '_>, RetainedSequenceError> {
        let used = self.used.ok_or(RetainedSequenceError::Incomplete)?;
        let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
        if !self
            .source
            .as_ref()
            .is_some_and(|source| source.matches(bytes, flags))
        {
            return Err(RetainedSequenceError::SourceMismatch);
        }
        let spans = self
            .spans
            .as_ref()
            .ok_or(RetainedSequenceError::Incomplete)?;
        Ok(PreparedElementSequence {
            bytes,
            spans: spans.as_slice(),
            used,
        })
    }

    /// Whether this owner and any admitted span backing retain the original pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self
                .spans
                .as_ref()
                .is_none_or(|spans| spans.belongs_to(budget))
    }

    /// Observe the exact retained span layout, including after a failed preparation.
    /// `None` represents unrepresentable layout geometry; no storage means zero.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.spans.as_ref().map_or(Some(0), |spans| {
            std::alloc::Layout::array::<SequenceSpan>(spans.capacity())
                .ok()
                .map(|layout| layout.size())
        })
    }
}

/// Inspect the complete element framing before admitting its actual planning arrays.
///
/// The sole advertised-layout scalar walker checks every original element span.
/// No span Vec, element body, aligned copy or destination is created. The sequence
/// ceiling and original element-length logical byte charges remain active; nominal
/// sequence count/span/element storage accounting occurs when the unchanged source is prepared and filled. The returned
/// shape grants only physical preparation, never a decoded value or protocol authority.
/// An enclosing field still requires `used == bytes.len()`.
///
/// # Errors
/// Returns the original advertised-layout, span, sequence/field-bound or overflow cause.
pub fn inspect_element_sequence(bytes: &[u8]) -> Result<(usize, usize), Error> {
    let (count, _) = inspect_seq_len_slice(bytes)?;
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    let used = byte_sequence::visit_binary_sequence_with_count(bytes, flags, count, |_| Ok(()))?;
    note_payload_access(bytes, used);
    Ok((count, used))
}

/// Plan an element sequence into initialized scratch using its sole scalar walker.
///
/// This uses the same count admission, advertised flags, minimum framing check,
/// logical span-storage charge, span order and complete-prefix consumption as
/// [`plan_binary_sequence`]. The initialized scratch may be larger than the
/// actual count; unused slots are never read or included in the resulting view.
/// No allocation, resize, raw lifetime conversion or heap fallback occurs.
///
/// # Errors
/// Preserves the original codec/resource failure. A short prepared destination
/// is a distinct local planning error. Partial span writes do not create a plan;
/// the unchanged scratch can be reused after any error.
pub fn prepare_element_sequence<'input, 'scratch>(
    bytes: &'input [u8],
    scratch: &'scratch mut [SequenceSpan],
) -> Result<PreparedElementSequence<'input, 'scratch>, SequenceDestinationError> {
    let (count, _) = read_seq_len_slice(bytes)?;
    let flags = effective_decode_flags().unwrap_or_else(default_encode_flags);
    validate_header_flags(flags)?;
    validate_binary_sequence_reservation(bytes, flags, count)?;
    if count > scratch.len() {
        return Err(SequenceDestinationError::Storage {
            available: scratch.len(),
            required: count,
        });
    }
    reserve_decode_sequence_storage::<SequenceSpan>(count)?;
    let mut index = 0;
    let used = byte_sequence::visit_binary_sequence_with_count(bytes, flags, count, |span| {
        scratch[index] = span;
        index += 1;
        Ok(())
    })?;
    note_payload_access(bytes, used);
    Ok(PreparedElementSequence {
        bytes,
        spans: &scratch[..count],
        used,
    })
}

/// Fill initialized storage from the canonical raw `Vec<u8>` payload layout.
///
/// Count/field/resource ordering and nominal retained-byte accounting match the
/// owning raw-byte specialization. The same borrowed slice decoder owns framing;
/// no element-sequence interpretation or alternate codec is attempted.
///
/// # Errors
/// Returns original codec/resource failure or distinct local destination geometry.
/// Failure retains all backing. Successful output is exactly `destination[..count]`.
pub fn decode_raw_byte_sequence_into(
    bytes: &[u8],
    destination: &mut [u8],
) -> Result<(usize, usize), SequenceDestinationError> {
    let (source, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(bytes)?;
    if source.len() > destination.len() {
        return Err(SequenceDestinationError::Storage {
            available: destination.len(),
            required: source.len(),
        });
    }
    reserve_decode_sequence_storage::<u8>(source.len())?;
    destination[..source.len()].copy_from_slice(source);
    Ok((source.len(), used))
}
