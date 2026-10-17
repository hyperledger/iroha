//! One original-pool immutable beacon graph, validated once and shared without deep copies.

use super::*;
use crate::beacon::{
    self, GlobalThresholdBeaconError, GlobalThresholdBeaconSessionBindingV1,
    GlobalThresholdBeaconVerificationError,
    validation::{DkgSignaturePreimage, DkgSignatureVerifier},
};
use iroha_allocation::{ChargedShared, PrepaidSharedError};
use iroha_crypto::threshold_bls::{
    AdaptiveThresholdBlsPublicTranscript, BeaconPurpose, ThresholdBlsError,
    ValidatedDealerCommitment,
};
use norito::{codec::Encode as _, core::SerializePayload};
use std::{fmt, ops::Deref};

/// Invalid protocol state is distinct from refusal by the caller's original resources.
#[derive(Debug, thiserror::Error)]
pub enum GlobalThresholdBeaconSessionError {
    /// A canonical binding, proof, transcript or lifecycle check failed.
    #[error(transparent)]
    Invalid(#[from] GlobalThresholdBeaconError),
    /// The actual finite original pool declined the complete demand.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// An actual fixed-buffer construction failed after original admission.
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    /// A child layout differed from its original checked reservation.
    #[error(transparent)]
    Reservation(#[from] InsufficientReservation),
    /// An exact canonical compact-key copy failed.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyAllocationError),
    /// An exact canonical signature copy failed.
    #[error(transparent)]
    Signature(#[from] SignatureAllocationError),
    /// A complete allocation ledger belongs to another pool.
    #[error(transparent)]
    Retention(#[from] RetainedPayloadError),
    /// An original prepaid shared-control construction failed.
    #[error(transparent)]
    Shared(#[from] PrepaidSharedError),
    /// The exact canonical message encoder failed; no signature was accepted.
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    /// An actual inherited decoder scope or physical decoder allocator refused.
    /// This owns the original Norito error, never a fabricated allocation-pool source.
    #[error(transparent)]
    DecodeResource(norito::Error),
    /// The prepaid operation owner belongs to a different physical pool.
    #[error("beacon session reservation belongs to another original pool")]
    ForeignReservation,
    /// Original source geometry and its checked allocation plan disagreed.
    #[error("canonical beacon session allocation plan changed")]
    PlanChanged,
}
impl GlobalThresholdBeaconSessionError {
    /// Convert at the instruction boundary while preserving original local custody.
    /// Invalid signed relations alone become completed rejection. Physical refusal
    /// has no invented release; impossible ownership/plan errors trigger recovery.
    pub(crate) fn into_execution_attempt(
        self,
    ) -> crate::execution_attempt::ExecutionAttemptError<GlobalThresholdBeaconError> {
        use crate::execution_attempt::ExecutionAttemptError as Attempt;
        use iroha_allocation::{ChargedBufferError, ChargedBufferFromChargeError};
        use ivm::error::ExecutionDeferral;
        match self {
            Self::Invalid(error) => Attempt::Rejected(error),
            Self::Admission(original)
            | Self::Buffer(PrepaidBufferError::Allocation(ChargedBufferError::Admission(
                original,
            ))) => Attempt::Deferred(original.into()),
            Self::DecodeResource(_)
            | Self::Buffer(PrepaidBufferError::Allocation(ChargedBufferError::Allocator {
                ..
            }))
            | Self::Shared(PrepaidSharedError::Allocator { .. })
            | Self::PublicKey(PublicKeyAllocationError::Allocation(
                ChargedBufferFromChargeError::Allocator { .. },
            ))
            | Self::Signature(SignatureAllocationError::Allocation(
                ChargedBufferFromChargeError::Allocator { .. },
            )) => Attempt::Deferred(ExecutionDeferral::AllocationUnavailable.into()),
            Self::Encoding(_) => {
                Attempt::Deferred(ExecutionDeferral::LocalInvariantViolation.into())
            }
            Self::Buffer(PrepaidBufferError::Reservation(_))
            | Self::Reservation(_)
            | Self::PublicKey(_)
            | Self::Signature(_)
            | Self::Retention(_)
            | Self::Shared(PrepaidSharedError::Reservation(_))
            | Self::ForeignReservation
            | Self::PlanChanged => {
                Attempt::Deferred(ExecutionDeferral::LocalInvariantViolation.into())
            }
        }
    }
}
impl From<SessionGraphError> for GlobalThresholdBeaconSessionError {
    fn from(error: SessionGraphError) -> Self {
        match error {
            SessionGraphError::Admission(error) => Self::Admission(error),
            SessionGraphError::Buffer(error) => Self::Buffer(error),
            SessionGraphError::Reservation(error) => Self::Reservation(error),
            SessionGraphError::PublicKey(error) => Self::PublicKey(error),
            SessionGraphError::Signature(error) => Self::Signature(error),
            SessionGraphError::Retention(error) => Self::Retention(error),
            SessionGraphError::Shared(error) => Self::Shared(error),
            SessionGraphError::Encoding(error) => Self::Encoding(error),
            SessionGraphError::PlanChanged => Self::PlanChanged,
        }
    }
}
impl From<ThresholdBlsError> for GlobalThresholdBeaconSessionError {
    fn from(error: ThresholdBlsError) -> Self {
        Self::Invalid(error.into())
    }
}
impl From<GlobalThresholdBeaconVerificationError<SessionGraphError>>
    for GlobalThresholdBeaconSessionError
{
    fn from(error: GlobalThresholdBeaconVerificationError<SessionGraphError>) -> Self {
        match error {
            GlobalThresholdBeaconVerificationError::Invalid(error) => Self::Invalid(error),
            GlobalThresholdBeaconVerificationError::Resource(error) => error.into(),
        }
    }
}

struct Payload {
    record: GlobalThresholdBeaconKeySessionV1,
    transcript: AdaptiveThresholdBlsPublicTranscript<BeaconPurpose>,
    retained_bytes: usize,
}

/// Completely verified beacon session retaining every original canonical allocation.
///
/// Clones share the identical charged graph/control. Only borrowing and canonical
/// serialization are available; no decoder, mutable access or DTO extraction can
/// manufacture or separate a verified graph from its original allocation ledger.
#[derive(Clone)]
pub struct ValidatedGlobalThresholdBeaconSessionV1 {
    owner: ChargedShared<RetainedPayload<Payload>>,
}
impl ValidatedGlobalThresholdBeaconSessionV1 {
    /// Borrow the immutable canonical record without allocating or transferring custody.
    pub fn record(&self) -> &GlobalThresholdBeaconKeySessionV1 {
        &self.owner.get().record
    }
    /// Recheck the sealed typed protocol's cryptographic release gate.
    ///
    /// # Errors
    /// Returns the underlying threshold-BLS refusal when the sealed protocol is not ready.
    pub fn ensure_adaptive_protocol_ready(&self) -> Result<(), ThresholdBlsError> {
        self.transcript().ensure_adaptive_protocol_ready()
    }
    pub(in crate::beacon) fn transcript(
        &self,
    ) -> &AdaptiveThresholdBlsPublicTranscript<BeaconPurpose> {
        &self.owner.get().transcript
    }
    /// Exact retained graph/ledger/control bytes, excluding released verification scratch.
    pub fn retained_allocation_bytes(&self) -> usize {
        self.owner.get().retained_bytes
    }
    /// Check current external identity against this immutable authenticated graph.
    ///
    /// # Errors
    /// Rejects a different network, session, ordered roster or transcript identity.
    pub fn check_binding(
        &self,
        expected: &GlobalThresholdBeaconSessionBindingV1,
    ) -> Result<(), GlobalThresholdBeaconError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC85"))]
        {
            let _ = expected;
            return Ok(());
        }
        validate_binding(self.record(), expected)
    }
    /// Whether two readers retain the identical original graph and shared control.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        ChargedShared::ptr_eq(&self.owner, &other.owner)
    }
    /// Whether every original nested allocation and control belongs to this exact pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.owner.belongs_to(budget) && RetainedPayload::belongs_to(&*self.owner, budget)
    }
    pub(in crate::beacon) fn allocation_bytes(
        source: &GlobalThresholdBeaconKeySessionV1,
        expected: &GlobalThresholdBeaconSessionBindingV1,
    ) -> Result<usize, GlobalThresholdBeaconSessionError> {
        Ok(SessionDemand::new(source, expected)?.total)
    }
    pub(in crate::beacon) fn admit(
        source: &GlobalThresholdBeaconKeySessionV1,
        expected: &GlobalThresholdBeaconSessionBindingV1,
        budget: &AllocationBudget,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        let plan = SessionDemand::new(source, expected)?;
        let mut reservation = budget.try_reserve_bytes(plan.total)?;
        Self::construct(source, plan, budget, &mut reservation)
    }
    pub(in crate::beacon) fn admit_prepaid(
        source: &GlobalThresholdBeaconKeySessionV1,
        expected: &GlobalThresholdBeaconSessionBindingV1,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        if !reservation.belongs_to(budget) {
            return Err(GlobalThresholdBeaconSessionError::ForeignReservation);
        }
        let plan = SessionDemand::new(source, expected)?;
        Self::construct(source, plan, budget, reservation)
    }
    fn construct(
        source: &GlobalThresholdBeaconKeySessionV1,
        plan: SessionDemand,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        // Check the complete original remainder before constructing even the shell.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC12")))]
        let remainder = reservation
            .remaining_bytes()
            .checked_sub(plan.total)
            .ok_or_else(|| InsufficientReservation {
                requested_bytes: plan.total,
                remaining_bytes: reservation.remaining_bytes(),
            })?;
        #[cfg(all(test, sumeragi_core_mutation = "HC12"))]
        let remainder = reservation.remaining_bytes().saturating_sub(plan.total);
        let SessionDemand {
            graph_bytes,
            scratch,
            ..
        } = plan;
        let shell = ChargedShared::<RetainedPayload<Payload>>::reserve_from(reservation)?;
        let mut workspace = Workspace::new(scratch, reservation)?;
        let transcript = verify_prepaid(source, &mut workspace)?;
        let original = retain_prepaid_session(source, budget, reservation)?;
        if reservation.remaining_bytes() != remainder {
            return Err(GlobalThresholdBeaconSessionError::PlanChanged);
        }
        // SAFETY: all original nested allocations move unchanged into the private
        // immutable payload. The additional transcript owns only initialized inline
        // values; its shared shell was allocated from this same aggregate beforehand.
        #[allow(unsafe_code)]
        let payload = unsafe {
            original.map_payload(|record| Payload {
                record,
                transcript,
                retained_bytes: graph_bytes
                    + ChargedShared::<RetainedPayload<Payload>>::allocation_layout().size(),
            })
        };
        Ok(Self {
            owner: shell.initialize(payload),
        })
    }
}
impl Deref for ValidatedGlobalThresholdBeaconSessionV1 {
    type Target = GlobalThresholdBeaconKeySessionV1;
    fn deref(&self) -> &Self::Target {
        self.record()
    }
}
impl fmt::Debug for ValidatedGlobalThresholdBeaconSessionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.record().fmt(f)
    }
}
impl PartialEq for ValidatedGlobalThresholdBeaconSessionV1 {
    fn eq(&self, other: &Self) -> bool {
        Self::ptr_eq(self, other) || self.record() == other.record()
    }
}
impl Eq for ValidatedGlobalThresholdBeaconSessionV1 {}
impl norito::NoritoSchema for ValidatedGlobalThresholdBeaconSessionV1 {
    fn nominal_name() -> String {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <GlobalThresholdBeaconKeySessionV1 as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for ValidatedGlobalThresholdBeaconSessionV1 {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.record().serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.record().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.record().encoded_len_exact()
    }
}
impl norito::json::JsonSerialize for ValidatedGlobalThresholdBeaconSessionV1 {
    fn json_serialize(&self, out: &mut String) {
        self.record().json_serialize(out)
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.record().json_serialize_to(out)
    }
}

fn validate_binding(
    source: &GlobalThresholdBeaconKeySessionV1,
    expected: &GlobalThresholdBeaconSessionBindingV1,
) -> Result<(), GlobalThresholdBeaconError> {
    if source.version != iroha_data_model::consensus::GLOBAL_THRESHOLD_BEACON_VERSION_V1 {
        return Err(GlobalThresholdBeaconError::UnsupportedVersion {
            actual: source.version,
        });
    }
    if source.network_id != expected.network_id {
        return Err(GlobalThresholdBeaconError::NetworkMismatch);
    }
    if source.session_id != expected.session_id {
        return Err(GlobalThresholdBeaconError::SessionMismatch);
    }
    if source.roster_hash != expected.roster_hash {
        return Err(GlobalThresholdBeaconError::RosterMismatch);
    }
    if source.transcript_hash != expected.transcript_hash {
        return Err(GlobalThresholdBeaconError::TranscriptMismatch);
    }
    // Reject impossible public geometry before walking encoded lengths or reserving storage.
    beacon::validate_adaptive_dkg_geometry(source)?;
    Ok(())
}

struct SessionDemand {
    graph_bytes: usize,
    scratch: ScratchDemand,
    total: usize,
}
impl SessionDemand {
    fn new(
        source: &GlobalThresholdBeaconKeySessionV1,
        expected: &GlobalThresholdBeaconSessionBindingV1,
    ) -> Result<Self, GlobalThresholdBeaconSessionError> {
        validate_binding(source, expected)?;
        let graph_bytes = Demand::for_session(source)?.total_bytes()?;
        let scratch = Workspace::demand(source)?;
        let total = graph_bytes
            .checked_add(scratch.bytes)
            .and_then(|n| {
                n.checked_add(ChargedShared::<RetainedPayload<Payload>>::allocation_layout().size())
            })
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(Self {
            graph_bytes,
            scratch,
            total,
        })
    }
}
struct ScratchDemand {
    bytes: usize,
    preimage: usize,
    dealers: usize,
}
struct Workspace {
    preimage: ChargedBuffer<u8>,
    dealers: ChargedBuffer<ValidatedDealerCommitment<BeaconPurpose>>,
}
impl Workspace {
    fn demand(
        source: &GlobalThresholdBeaconKeySessionV1,
    ) -> Result<ScratchDemand, SessionGraphError> {
        let dkg = &source.adaptive_dkg;
        let mut preimage = 0;
        for key in &dkg.recipient_keys {
            preimage =
                preimage.max(DkgSignaturePreimage::RecipientKey(&dkg.session, key).encoded_len());
        }
        for dealer in &dkg.dealer_commitments {
            preimage = preimage
                .max(DkgSignaturePreimage::DealerCommitment(&dkg.session, dealer).encoded_len());
        }
        for edge in &dkg.encrypted_shares {
            preimage = preimage
                .max(DkgSignaturePreimage::EncryptedShare(&dkg.session, edge).encoded_len());
        }
        for acceptance in &dkg.share_acceptances {
            preimage = preimage
                .max(DkgSignaturePreimage::ShareAcceptance(&dkg.session, acceptance).encoded_len());
        }
        let dealers = dkg.dealer_commitments.len();
        let bytes = Layout::array::<u8>(preimage)
            .map_err(|_| AllocationRefusal::DemandOverflow)?
            .size()
            .checked_add(
                Layout::array::<ValidatedDealerCommitment<BeaconPurpose>>(dealers)
                    .map_err(|_| AllocationRefusal::DemandOverflow)?
                    .size(),
            )
            .ok_or(AllocationRefusal::DemandOverflow)?;
        Ok(ScratchDemand {
            bytes,
            preimage,
            dealers,
        })
    }
    fn new(
        demand: ScratchDemand,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, SessionGraphError> {
        let mut preimage = ChargedBuffer::from_reservation(demand.preimage, reservation)?;
        for _ in 0..demand.preimage {
            preimage.push_reserved(0);
        }
        let dealers = ChargedBuffer::from_reservation(demand.dealers, reservation)?;
        Ok(Self { preimage, dealers })
    }
}
impl DkgSignatureVerifier for Workspace {
    type Resource = SessionGraphError;
    fn verify(
        &mut self,
        preimage: DkgSignaturePreimage<'_>,
        signature: &Signature,
        key: &PublicKey,
    ) -> Result<bool, SessionGraphError> {
        let len = preimage.encoded_len();
        let bytes = self
            .preimage
            .as_mut_slice()
            .get_mut(..len)
            .ok_or(SessionGraphError::PlanChanged)?;
        let mut writer = &mut bytes[..];
        let written = norito::codec::encode_adaptive_into(&preimage, &mut writer)?;
        if written != len || !writer.is_empty() {
            return Err(SessionGraphError::PlanChanged);
        }
        Ok(iroha_crypto::verify_signature_borrowed(signature, key, bytes).is_ok())
    }
}
fn verify_prepaid(
    source: &GlobalThresholdBeaconKeySessionV1,
    workspace: &mut Workspace,
) -> Result<AdaptiveThresholdBlsPublicTranscript<BeaconPurpose>, GlobalThresholdBeaconSessionError>
{
    beacon::validate_adaptive_dkg_shape(source, workspace)?;
    Ok(beacon::reconstruct_adaptive_beacon_transcript(
        source,
        &mut workspace.dealers,
    )?)
}

/// Verify a raw signed/snapshot DTO without retaining a second public graph.
/// All actual verifier backing is prepaid from the caller's explicit operation pool.
pub(in crate::beacon) fn verify_borrowed_session(
    source: &GlobalThresholdBeaconKeySessionV1,
    expected: &GlobalThresholdBeaconSessionBindingV1,
    budget: &AllocationBudget,
) -> Result<(), GlobalThresholdBeaconSessionError> {
    validate_binding(source, expected)?;
    let demand = Workspace::demand(source)?;
    let mut reservation = budget.try_reserve_bytes(demand.bytes)?;
    let mut workspace = Workspace::new(demand, &mut reservation)?;
    verify_prepaid(source, &mut workspace)?;
    Ok(())
}

#[cfg(test)]
mod tests;

mod prepared;
pub use prepared::PreparedGlobalThresholdBeaconSessionVerificationV1;
