//! Original-pool custody for closed canonical verifier inputs and their local refusals.

mod verify;
pub use verify::{PreparedLcEvidencePairV1, SccpAdmittedInitialV1, SccpAdmittedProofV1};

use std::fmt;

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, AllocationReservation, ChargedBufferError,
    PrepaidSharedError,
};
use norito::core::{DecodeAttemptError, DecodeBudgetContext};

use super::{
    SccpLcError,
    proof::{
        SccpLcAdvanceV1, SccpLcBootstrapDataV1, SccpLcEvidenceV1, SccpLcSetDataV1,
        SccpSourceProofV1,
    },
    state::admitted::SccpLcDeltaAdmissionErrorV1,
};

/// A verifier rejection or the original local physical refusal that interrupted it.
/// Keeping these cases distinct prevents local allocation pressure becoming a consensus vote.
#[derive(Debug)]
pub enum SccpLcAttemptErrorV1 {
    /// Deterministic protocol or source-data rejection.
    Protocol(SccpLcError),
    /// Original finite pool refused the requested native allocation.
    Admission(AllocationRefusal),
    /// Actual admitted native buffer could not be constructed.
    Buffer(ChargedBufferError),
    /// An original prepaid counter control could not be constructed.
    Control(PrepaidSharedError),
    /// Canonical decode retained its original scope classification.
    Decode(DecodeAttemptError),
    /// Originally admitted output could not be constructed.
    Output(SccpLcDeltaAdmissionErrorV1),
    /// An internal physical ownership invariant failed before publication.
    Invariant(&'static str),
}
impl fmt::Display for SccpLcAttemptErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Admission(error) => error.fmt(formatter),
            Self::Buffer(error) => error.fmt(formatter),
            Self::Control(error) => error.fmt(formatter),
            Self::Decode(error) => error.error().fmt(formatter),
            Self::Output(error) => error.fmt(formatter),
            Self::Invariant(reason) => formatter.write_str(reason),
        }
    }
}
impl std::error::Error for SccpLcAttemptErrorV1 {}
impl From<SccpLcError> for SccpLcAttemptErrorV1 {
    fn from(error: SccpLcError) -> Self {
        Self::Protocol(error)
    }
}
impl From<super::ethereum::EthereumLcError> for SccpLcAttemptErrorV1 {
    fn from(error: super::ethereum::EthereumLcError) -> Self {
        Self::Protocol(error.into())
    }
}
impl From<super::bsc::BscLcError> for SccpLcAttemptErrorV1 {
    fn from(error: super::bsc::BscLcError) -> Self {
        Self::Protocol(error.into())
    }
}
impl From<AllocationRefusal> for SccpLcAttemptErrorV1 {
    fn from(error: AllocationRefusal) -> Self {
        Self::Admission(error)
    }
}
impl From<ChargedBufferError> for SccpLcAttemptErrorV1 {
    fn from(error: ChargedBufferError) -> Self {
        Self::Buffer(error)
    }
}
impl From<PrepaidSharedError> for SccpLcAttemptErrorV1 {
    fn from(error: PrepaidSharedError) -> Self {
        Self::Control(error)
    }
}
impl From<DecodeAttemptError> for SccpLcAttemptErrorV1 {
    fn from(error: DecodeAttemptError) -> Self {
        Self::Decode(error)
    }
}
impl From<SccpLcDeltaAdmissionErrorV1> for SccpLcAttemptErrorV1 {
    fn from(error: SccpLcDeltaAdmissionErrorV1) -> Self {
        Self::Output(error)
    }
}

/// Explicit resource source shared by every chain's verification kernel.
pub(crate) struct LcMemory<'a> {
    max_frame_bytes: usize,
    budget: Option<&'a AllocationBudget>,
    native: crate::native_memory::Memory<'a>,
}

impl<'a> LcMemory<'a> {
    pub(crate) fn detached() -> Self {
        Self {
            budget: None,
            max_frame_bytes: usize::MAX,
            native: crate::native_memory::Memory::detached(),
        }
    }

    pub(crate) fn admitted(budget: &'a AllocationBudget, max_frame_bytes: usize) -> Self {
        Self {
            budget: Some(budget),
            max_frame_bytes,
            native: crate::native_memory::Memory::admitted(budget),
        }
    }

    pub(crate) const fn native(&self) -> &crate::native_memory::Memory<'a> {
        &self.native
    }

    pub(crate) fn decode_set(
        &self,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<LcSetOwner, SccpLcAttemptErrorV1> {
        let maximum = maximum.min(self.max_frame_bytes);
        if bytes.len() > maximum {
            return Err(SccpLcError::FrameTooLarge {
                kind: "consensus set",
                len: bytes.len(),
                max: maximum,
            }
            .into());
        }
        self.budget.map_or_else(
            || {
                SccpLcSetDataV1::from_frame(bytes)
                    .map(LcSetOwner::Detached)
                    .map_err(Into::into)
            },
            |budget| {
                PreparedLcFrameV1::consensus_set(bytes, maximum, budget)
                    .map(LcSetOwner::Admitted)
                    .map_err(|error| match error {
                        SccpLcAttemptErrorV1::Decode(ref decode)
                            if decode.kind() == norito::core::DecodeAttemptErrorKind::Invalid =>
                        {
                            SccpLcError::MalformedFrame("consensus set").into()
                        }
                        other => other,
                    })
            },
        )
    }
}

/// A stored canonical set whose graph never escapes its decode custody.
pub(crate) enum LcSetOwner {
    Detached(SccpLcSetDataV1),
    Admitted(PreparedLcFrameV1<SccpLcSetDataV1>),
}

impl LcSetOwner {
    pub(crate) const fn get(&self) -> &SccpLcSetDataV1 {
        match self {
            Self::Detached(value) => value,
            Self::Admitted(value) => value.get(),
        }
    }
}

impl<E: Into<SccpLcError>> From<crate::native_memory::AttemptError<E>> for SccpLcAttemptErrorV1 {
    fn from(error: crate::native_memory::AttemptError<E>) -> Self {
        match error {
            crate::native_memory::AttemptError::Protocol(error) => Self::Protocol(error.into()),
            crate::native_memory::AttemptError::Allocation(error) => Self::Buffer(error),
        }
    }
}

/// Closed external sender representations carried by authenticated SCCP source events.
/// Their fixed backing needs no heap allocation or detached payload owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SccpSourceSenderV1 {
    /// Canonical Ethereum or BSC account.
    Evm([u8; 20]),
    /// Canonical TON workchain and account bytes.
    Ton([u8; 36]),
}

impl SccpSourceSenderV1 {
    /// The original payload sender codec.
    #[must_use]
    pub const fn codec(&self) -> u8 {
        match self {
            Self::Evm(_) => crate::v1::constants::CODEC_EVM_ADDRESS20,
            Self::Ton(_) => crate::v1::constants::CODEC_TON_ACCOUNT36,
        }
    }

    /// Borrow the authenticated sender without allocating a payload account graph.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        match self {
            Self::Evm(bytes) => bytes,
            Self::Ton(bytes) => bytes,
        }
    }
}

/// Heap-free authenticated event fields, shared by admitted and off-chain verifier kernels.
pub type SccpNativeEventV1 = super::proof::SccpNormalizedEventV1<SccpSourceSenderV1>;

impl SccpNativeEventV1 {
    /// Build the detached convenience response after verification has finished.
    /// Native admission retains this fixed representation and never calls this adapter.
    #[must_use]
    pub fn into_detached(self) -> super::proof::SccpNormalizedEventV1 {
        use super::proof::SccpNormalizedEventV1 as Event;
        match self {
            Event::Finalized {
                emitter,
                message_id,
                nonce,
                amount,
                locator,
            } => Event::Finalized {
                emitter,
                message_id,
                nonce,
                amount,
                locator,
            },
            Event::TransferToTaira {
                emitter,
                message_id,
                sender,
                nonce,
                payload_hash,
                locator,
            } => Event::TransferToTaira {
                emitter,
                message_id,
                sender: crate::v1::payload::PayloadAccountV1 {
                    codec: sender.codec(),
                    bytes: sender.bytes().to_vec(),
                },
                nonce,
                payload_hash,
                locator,
            },
            Event::Void {
                emitter,
                kind,
                first_nonce,
                count,
                message_id_or_zero,
                locator,
            } => Event::Void {
                emitter,
                kind,
                first_nonce,
                count,
                message_id_or_zero,
                locator,
            },
        }
    }
}

/// One immutable decoded closed frame, retaining the original pre-decode physical grant.
///
/// Its private graph has no cloning or extraction API. Rust drops fields in declaration order:
/// the actual graph retires before its original reservation is refunded. Verification borrows
/// this graph; any native conversion or scratch must acquire its own original owner first.
#[derive(Debug)]
pub struct PreparedLcFrameV1<T> {
    value: T,
    graph: AllocationReservation,
    budget: AllocationBudget,
    encoded_len: usize,
    maximum: usize,
}
impl<T> PreparedLcFrameV1<T> {
    /// Borrow the decoded input without moving it away from its original physical grant.
    #[must_use]
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// Original cumulative allocation allowance retained by this immutable decoded graph.
    /// This can conservatively include temporary decoder backing already retired.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.graph.remaining_bytes()
    }
}

// Only these closed, derived wire types use this constructor. Their leaf serializers
// stream scalar/array/vector fields; no user serializer or nested frame callback can
// allocate an unobserved graph or mint another unprepared protocol counter context.
fn prepare<T>(
    bytes: &[u8],
    kind: &'static str,
    maximum: usize,
    budget: &AllocationBudget,
) -> Result<PreparedLcFrameV1<T>, SccpLcAttemptErrorV1>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.len() > maximum {
        return Err(SccpLcError::FrameTooLarge {
            kind,
            len: bytes.len(),
            max: maximum,
        }
        .into());
    }
    let mut layouts = [DecodeBudgetContext::allocation_layout(); 3];
    layouts[1..].copy_from_slice(&norito::PreparedCanonicalDecode::allocation_layouts());
    let mut controls = budget.try_reserve_layouts(layouts)?;
    let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
    // Admission precedes the first decoded graph allocation. The cumulative
    // decoder counter enforces this actual original grant, not a byte multiplier.
    let mut allowance = budget.try_reserve_bytes(available)?;
    let defaults = norito::canonical_decode_limits(bytes.len());
    let limits = norito::DecodeLimits::new(
        defaults.max_sequence_elements(),
        defaults.max_field_bytes(),
        defaults.max_total_elements(),
        available,
        defaults.max_nesting_depth(),
    );
    let physical = DecodeBudgetContext::from_reservation(limits, &mut controls)?;
    let decoder =
        norito::PreparedCanonicalDecode::from_reservation(bytes.len(), defaults, &mut controls)?;
    let value = physical.with(|| decoder.decode::<T>(bytes))?;
    let consumed = usize::try_from(physical.consumed_allocated_bytes())
        .map_err(|_| SccpLcAttemptErrorV1::Invariant("decoded native allocation overflow"))?;
    let graph = allowance
        .try_partition_bytes(consumed)
        .map_err(|_| SccpLcAttemptErrorV1::Invariant("decode exceeded its physical grant"))?;
    Ok(PreparedLcFrameV1 {
        value,
        graph,
        budget: budget.clone(),
        encoded_len: bytes.len(),
        maximum,
    })
}

impl PreparedLcFrameV1<SccpLcAdvanceV1> {
    /// Admit and decode one canonical advance from an already owned source byte slice.
    /// `maximum` is the caller's configured per-proof byte ceiling.
    ///
    /// # Errors
    /// Returns canonical/source-size rejection or the original physical refusal.
    pub fn advance(
        bytes: &[u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        prepare(bytes, "advance", maximum, budget)
    }
}
impl PreparedLcFrameV1<SccpSourceProofV1> {
    /// Admit and decode one canonical proof under the configured per-proof byte ceiling.
    ///
    /// # Errors
    /// Returns canonical/source-size rejection or the original physical refusal.
    pub fn proof(
        bytes: &[u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        prepare(bytes, "proof", maximum, budget)
    }
}
impl PreparedLcFrameV1<SccpLcSetDataV1> {
    /// Admit and decode a stored or earlier-admitted canonical consensus-set frame.
    ///
    /// # Errors
    /// Returns canonical/source-size rejection or the original physical refusal.
    pub fn consensus_set(
        bytes: &[u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        prepare(bytes, "consensus set", maximum, budget)
    }
}

impl PreparedLcFrameV1<SccpLcBootstrapDataV1> {
    /// Admit a canonical governance bootstrap under the original configured proof ceiling.
    ///
    /// # Errors
    /// Preserves canonical rejection and the original physical refusal separately.
    pub fn bootstrap(
        bytes: &[u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        prepare(bytes, "bootstrap", maximum, budget)
    }
}

impl PreparedLcFrameV1<SccpLcEvidenceV1> {
    /// Admit one canonical equivocation record from the original signed evidence.
    ///
    /// # Errors
    /// Preserves canonical rejection and the original physical refusal separately.
    pub fn evidence(
        bytes: &[u8],
        maximum: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        prepare(bytes, "evidence", maximum, budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light_client::{ethereum::EthereumHeaderSegmentV1, proof::SccpLcSegmentV1};

    fn fixture() -> SccpLcAdvanceV1 {
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: vec![vec![3; 4096], vec![4; 4096]],
            }),
        }
    }

    #[test]
    fn prepared_frame_original_grant_precedes_graph_and_refusal_retry_preserves_source() {
        let value = fixture();
        let frame = value.to_frame().unwrap();
        let original_bytes = frame.as_ptr();
        let empty = AllocationBudget::new(0);
        assert!(matches!(
            PreparedLcFrameV1::advance(&frame, frame.len(), &empty),
            Err(SccpLcAttemptErrorV1::Admission(_))
        ));
        let controls = 3 * DecodeBudgetContext::allocation_layout().size();
        let original = AllocationBudget::new(controls + 65536);
        let competing = original.try_reserve_bytes(65536).unwrap();
        let refused = PreparedLcFrameV1::advance(&frame, frame.len(), &original).unwrap_err();
        assert!(matches!(&refused, SccpLcAttemptErrorV1::Decode(error)
            if error.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit));
        drop(refused);
        assert_eq!(original.reserved_bytes(), 65536);
        let unrelated = AllocationBudget::new(65536);
        drop(unrelated.try_reserve_bytes(65536).unwrap());
        assert!(PreparedLcFrameV1::advance(&frame, frame.len(), &original).is_err());
        drop(competing);
        let prepared = PreparedLcFrameV1::advance(&frame, frame.len(), &original).unwrap();
        assert_eq!(prepared.get(), &value);
        assert!(prepared.retained_bytes() >= 8192);
        assert_eq!(original.reserved_bytes(), prepared.retained_bytes());
        assert_eq!(frame.as_ptr(), original_bytes);
        assert_eq!(SccpLcAdvanceV1::from_frame(&frame).unwrap(), value);
        drop(prepared);
        assert_eq!(original.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_frame_rejects_bounds_and_bad_bytes_without_retaining_a_partial_graph() {
        let frame = fixture().to_frame().unwrap();
        let original = AllocationBudget::new(65536);
        assert!(matches!(
            PreparedLcFrameV1::advance(&frame, frame.len() - 1, &original),
            Err(SccpLcAttemptErrorV1::Protocol(
                SccpLcError::FrameTooLarge { .. }
            ))
        ));
        assert_eq!(original.peak_reserved_bytes(), 0);
        let malformed = &frame[..frame.len() - 1];
        let error = PreparedLcFrameV1::advance(malformed, frame.len(), &original).unwrap_err();
        assert!(matches!(&error, SccpLcAttemptErrorV1::Decode(error)
            if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid));
        drop(error);
        assert_eq!(original.reserved_bytes(), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _prepared = PreparedLcFrameV1::advance(&frame, frame.len(), &original).unwrap();
            panic!("injected after prepared frame construction")
        }));
        assert!(result.is_err());
        assert_eq!(original.reserved_bytes(), 0);
    }
}
