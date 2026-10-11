//! Original-pool sequence and leaf backing reused by the canonical destination walk.

use super::*;

/// Original prepared leaf/storage refusal; no protocol invalidity is implied.
#[derive(Debug, thiserror::Error)]
pub enum GlobalThresholdBeaconInputDestinationErrorV1 {
    /// Original canonical crypto leaf or fixed destination refusal.
    #[error(transparent)]
    Crypto(#[from] PreparedCryptoDecodeError),
    /// Original fixed sequence destination refusal.
    #[error(transparent)]
    Sequence(#[from] SequenceDestinationError),
    /// The original authenticated destination plan changed.
    #[error("prepared DKG destination no longer matches its original plan")]
    PlanChanged,
}
pub(super) type DestinationError = GlobalThresholdBeaconInputDestinationErrorV1;
pub(super) type DecodeResult<T> = Result<T, DecodeIntoError<DestinationError>>;

pub(super) fn buffer<T>(
    count: usize,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<T>, SessionGraphError> {
    let layout = Layout::array::<T>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
    let mut reservation = budget.try_reserve(layout)?;
    Ok(ChargedBuffer::from_reservation(count, &mut reservation)?)
}
pub(super) fn spans(
    count: usize,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<SequenceSpan>, SessionGraphError> {
    let mut spans = buffer(count, budget)?;
    for _ in 0..count {
        spans.push_reserved(SequenceSpan { start: 0, end: 0 });
    }
    Ok(spans)
}

pub(super) fn sequence_error(error: SequenceDestinationError) -> DecodeIntoError<DestinationError> {
    match error {
        SequenceDestinationError::Codec(original) => DecodeIntoError::Codec(original),
        original => DecodeIntoError::Destination(DestinationError::Sequence(original)),
    }
}
pub(super) fn crypto_error(
    error: PreparedCryptoDecodeError,
    width: usize,
) -> DecodeIntoError<DestinationError> {
    match error {
        PreparedCryptoDecodeError::Codec(original) => DecodeIntoError::Codec(original),
        // This owner was prepared to the authenticated protocol width. A
        // different offered width is intrinsic invalid input. A disagreement
        // with that original prepared width remains a distinct local invariant.
        PreparedCryptoDecodeError::Geometry { expected, offered }
            if expected == width && offered != width =>
        {
            DecodeIntoError::Codec(norito::Error::LengthMismatch)
        }
        original => DecodeIntoError::Destination(DestinationError::Crypto(original)),
    }
}
pub(super) fn exact_count(bytes: &[u8], expected: usize) -> DecodeResult<()> {
    // Inspect is noncharging; the sole canonical planner below charges once.
    let (offered, _) = norito::core::inspect_seq_len_slice(bytes)?;
    if offered != expected {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(())
}
pub(super) fn complete(used: usize, bytes: &[u8]) -> DecodeResult<()> {
    if used != bytes.len() {
        return Err(norito::Error::LengthMismatch.into());
    }
    Ok(())
}

/// A complete fixed-width canonical byte sequence, with no late growth.
pub(super) struct Bytes {
    pub(super) bytes: ChargedBuffer<u8>,
    ready: bool,
}
impl Bytes {
    pub(super) fn new(count: usize, budget: &AllocationBudget) -> Result<Self, SessionGraphError> {
        let mut bytes = buffer(count, budget)?;
        for _ in 0..count {
            bytes.push_reserved(0);
        }
        Ok(Self {
            bytes,
            ready: false,
        })
    }
    pub(super) fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.ready = false;
        exact_count(bytes, self.bytes.capacity())?;
        let (count, used) = decode_raw_byte_sequence_into(bytes, self.bytes.as_mut_slice())
            .map_err(sequence_error)?;
        complete(used, bytes)?;
        if count != self.bytes.capacity() {
            return Err(DecodeIntoError::Destination(DestinationError::PlanChanged));
        }
        self.ready = true;
        Ok(())
    }
    pub(super) fn reset(&mut self) {
        self.ready = false;
    }
}
impl SerializePayload for Bytes {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG bytes",
            });
        }
        self.bytes.as_slice().serialize(writer)
    }
}

/// Inline element values in physically funded array and canonical span backing.
/// Instantiated only for Copy DTOs containing no nested heap fields.
pub(super) struct CopySequence<T> {
    pub(super) values: ChargedBuffer<T>,
    spans: ChargedBuffer<SequenceSpan>,
    ready: bool,
}
impl<T: inline::InlineValue + SerializePayload + for<'de> norito::DeserializePayload<'de>>
    CopySequence<T>
{
    pub(super) fn new(
        count: usize,
        initial: T,
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        let mut values = buffer(count, budget)?;
        for _ in 0..count {
            values.push_reserved(initial);
        }
        Ok(Self {
            values,
            spans: spans(count, budget)?,
            ready: false,
        })
    }
    #[cfg(test)]
    pub(super) fn extraction_scaffolding_bytes(&self) -> usize {
        self.spans.capacity() * std::mem::size_of::<SequenceSpan>()
    }
    pub(super) fn decode(&mut self, bytes: &[u8]) -> DecodeResult<()> {
        self.ready = false;
        exact_count(bytes, self.values.capacity())?;
        let plan =
            prepare_element_sequence(bytes, self.spans.as_mut_slice()).map_err(sequence_error)?;
        complete(plan.used(), bytes)?;
        plan.decode_elements::<T, DestinationError>(|index, field| {
            self.values.as_mut_slice()[index] =
                field.with_payload(<T as inline::InlineValue>::decode_payload)?;
            Ok(())
        })?;
        self.ready = true;
        Ok(())
    }
    pub(super) fn reset(&mut self) {
        self.ready = false;
    }
    pub(super) fn ready(&self) -> bool {
        self.ready
    }
}
impl<T: SerializePayload> SerializePayload for CopySequence<T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        if !self.ready {
            return Err(norito::Error::InvalidValue {
                context: "unfinished prepared DKG inline sequence",
            });
        }
        norito::core::write_element_sequence::<PayloadRef<'_, T>, _>(
            writer,
            self.values.as_slice().iter().map(PayloadRef),
        )
    }
}

pub(super) fn signature(
    budget: &AllocationBudget,
) -> Result<PreparedSignatureDecode, SessionGraphError> {
    let width = iroha_crypto::Algorithm::BlsNormal.signature_payload_len();
    let layout = Layout::array::<u8>(width).map_err(|_| AllocationRefusal::DemandOverflow)?;
    let mut reservation = budget.try_reserve(layout)?;
    let charge = reservation.try_split(layout)?;
    PreparedSignatureDecode::try_from_charge(width, budget, charge)
        .map_err(|(_charge, error)| error.into())
}
pub(super) fn public_key(
    source: &PublicKey,
    budget: &AllocationBudget,
) -> Result<PreparedPublicKeyDecode, SessionGraphError> {
    if source.algorithm() != iroha_crypto::Algorithm::BlsNormal {
        return Err(SessionGraphError::PlanChanged);
    }
    let layout = source.retained_allocation_layout();
    let width = layout.size();
    let mut reservation = budget.try_reserve(layout)?;
    let charge = reservation.try_split(layout)?;
    PreparedPublicKeyDecode::try_from_charge(width, budget, charge)
        .map_err(|(_charge, error)| error.into())
}
