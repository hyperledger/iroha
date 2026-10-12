//! Immutable original-pool custody of the native A1 open anchor chunk (§4.2.1).
//!
//! Canonical serialization is exactly `Vec<SccpAnchorV1>`. Claims are bounded before copying,
//! never decoded into authority here. Parent-tip authentication, chunk roots and transaction
//! publication are separate owners. No mutable borrow or owned payload extraction is exposed.
//! The enclosing State cell and snapshot decode scratch retain their separate admission duties.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedShared, PrepaidBufferError, PrepaidSharedError, RetainedPayload,
};
use iroha_data_model::sccp::committee::SccpAnchorV1;
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};
use std::{alloc::Layout, fmt, ops::Deref};

/// Maximum native parent anchors in one open chunk (§4.2.1).
pub const MAX_OPEN_ANCHORS: usize = 4_096;

const _: () = assert!(std::mem::size_of::<SccpAnchorV1>() == 64);
static EMPTY_CLAIM: Vec<SccpAnchorV1> = Vec::new();

/// Structural claim refusal or original local resource failure; never a finality verdict.
#[derive(Debug, thiserror::Error)]
pub enum AnchorOwnerError {
    /// The supplied count cannot describe a bounded open chunk.
    #[error("invalid SCCP open anchor claim: {0}")]
    Invalid(&'static str),
    /// Exact original finite-pool refusal, including its release observation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Physical allocation refused the already prepaid byte count.
    #[error("SCCP anchor allocator refused {requested_bytes} prepaid bytes")]
    Allocator {
        /// Exact size of the refused concrete allocation.
        requested_bytes: usize,
    },
    /// Original pool identity or exact materialization plan did not match.
    #[error("SCCP anchor ownership invariant: {0}")]
    Invariant(&'static str),
}

impl AnchorOwnerError {
    fn buffer(error: PrepaidBufferError) -> Self {
        match error {
            PrepaidBufferError::Allocation(ChargedBufferError::Admission(original)) => {
                Self::Admission(original)
            }
            PrepaidBufferError::Allocation(ChargedBufferError::Allocator { requested_bytes }) => {
                Self::Allocator { requested_bytes }
            }
            PrepaidBufferError::Reservation(_) => Self::Invariant("anchor buffer reservation"),
        }
    }
}

/// Shared immutable anchors with the original pool retained even when the chunk is empty.
///
/// Empty chunks allocate nothing. Nonempty chunks retain exact vector, ledger and shared-shell
/// credits until their final clone is dropped. A clone never copies or reprices the vector.
#[derive(Clone)]
pub struct RetainedSccpAnchorOpen {
    budget: AllocationBudget,
    owner: Option<ChargedShared<RetainedPayload<Vec<SccpAnchorV1>>>>,
}

impl RetainedSccpAnchorOpen {
    /// Retain an empty chunk's exact original pool without acquiring or allocating capacity.
    #[must_use]
    pub fn empty(budget: &AllocationBudget) -> Self {
        Self {
            budget: budget.clone(),
            owner: None,
        }
    }

    /// Borrow bounded anchors without detaching their allocation custody.
    #[must_use]
    pub fn anchors(&self) -> &[SccpAnchorV1] {
        self.claim()
    }

    fn claim(&self) -> &Vec<SccpAnchorV1> {
        self.owner
            .as_ref()
            .map_or(&EMPTY_CLAIM, |owner| owner.get())
    }

    /// Check the original identity, shell and every retained payload charge.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self
                .owner
                .as_ref()
                .is_none_or(|owner| owner.belongs_to(budget) && owner.deref().belongs_to(budget))
    }

    /// Whether both handles retain the identical allocation (or empty original-pool identity).
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.owner, &other.owner) {
            (Some(left), Some(right)) => ChargedShared::ptr_eq(left, right),
            (None, None) => self.budget.same_pool(&other.budget),
            _ => false,
        }
    }

    /// Exact retained payload, ledger and shell bytes; an empty chunk retains zero bytes.
    #[must_use]
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.owner.as_ref().map_or(Some(0), |owner| {
            owner
                .allocation_bytes()?
                .checked_add(Self::shared_layout().size())
        })
    }

    fn shared_layout() -> Layout {
        ChargedShared::<RetainedPayload<Vec<SccpAnchorV1>>>::allocation_layout()
    }

    /// Admit a bounded decoded claim from borrowed bytes; no provenance is authenticated.
    ///
    /// # Errors
    /// Rejects an oversized claim before admission/copy or preserves the original local error.
    pub fn admit_claim(
        source: &[SccpAnchorV1],
        budget: &AllocationBudget,
    ) -> Result<Self, AnchorOwnerError> {
        Self::copy_with_append(source, None, budget)
    }

    /// Admit a separate immutable version with one additional parent anchor.
    /// The original owner is unchanged on success or refusal; a full chunk must be sealed first.
    ///
    /// # Errors
    /// Refuses a foreign pool or full chunk before copying, or returns the original local error.
    pub fn appended(
        &self,
        anchor: SccpAnchorV1,
        budget: &AllocationBudget,
    ) -> Result<Self, AnchorOwnerError> {
        if !self.belongs_to(budget) {
            return Err(AnchorOwnerError::Invariant("foreign anchor pool"));
        }
        Self::copy_with_append(self.anchors(), Some(anchor), budget)
    }

    #[allow(
        unsafe_code,
        reason = "exact prepaid fixed-size anchor vector moves into immutable original-pool custody"
    )]
    fn copy_with_append(
        source: &[SccpAnchorV1],
        appended: Option<SccpAnchorV1>,
        budget: &AllocationBudget,
    ) -> Result<Self, AnchorOwnerError> {
        if source.len() > MAX_OPEN_ANCHORS
            || (source.len() == MAX_OPEN_ANCHORS && appended.is_some())
        {
            return Err(AnchorOwnerError::Invalid("open chunk exceeds 4096 anchors"));
        }
        let count = source.len() + usize::from(appended.is_some());
        if count == 0 {
            return Ok(Self::empty(budget));
        }
        let payload_layout =
            Layout::array::<SccpAnchorV1>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
        let ledger_layout =
            Layout::array::<AllocationCharge>(1).map_err(|_| AllocationRefusal::DemandOverflow)?;
        let total = payload_layout
            .size()
            .checked_add(ledger_layout.size())
            .and_then(|bytes| bytes.checked_add(Self::shared_layout().size()))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(total)?;
        let mut charges = ChargedBuffer::from_reservation(1, &mut reservation)
            .map_err(AnchorOwnerError::buffer)?;
        let mut values = ChargedBuffer::from_reservation(count, &mut reservation)
            .map_err(AnchorOwnerError::buffer)?;
        for anchor in source.iter().copied().chain(appended) {
            values
                .try_push(anchor)
                .map_err(|_| AnchorOwnerError::Invariant("anchor count"))?;
        }
        // SAFETY: every anchor is fixed-size Copy data with no nested allocation. The vector
        // never grows after this exact-capacity allocation and cannot escape the private owner.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        if let Err(charge) = charges.try_push(charge) {
            // Fixed-size Copy anchors have no user destructor. Reclaim payload before credit.
            drop(values);
            drop(charge);
            return Err(AnchorOwnerError::Invariant("anchor ledger count"));
        }
        // SAFETY: the only owned payload allocation is exactly the vector backing above, with
        // exactly one ledger entry from the original reservation. No extraction/mutation exists.
        let retained = match unsafe { RetainedPayload::try_new(values, charges, budget) } {
            Ok(retained) => retained,
            Err((values, charges, _)) => {
                drop(values);
                drop(charges);
                return Err(AnchorOwnerError::Invariant("original anchor graph pool"));
            }
        };
        match ChargedShared::from_reservation(retained, &mut reservation) {
            Ok(owner) => Ok(Self {
                budget: budget.clone(),
                owner: Some(owner),
            }),
            Err((retained, error)) => {
                drop(retained);
                Err(match error {
                    PrepaidSharedError::Allocator { requested_bytes } => {
                        AnchorOwnerError::Allocator { requested_bytes }
                    }
                    PrepaidSharedError::Reservation(_) => {
                        AnchorOwnerError::Invariant("anchor shared-shell reservation")
                    }
                })
            }
        }
    }
}

impl fmt::Debug for RetainedSccpAnchorOpen {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.anchors().fmt(out)
    }
}
impl PartialEq for RetainedSccpAnchorOpen {
    fn eq(&self, other: &Self) -> bool {
        self.anchors() == other.anchors()
    }
}
impl Eq for RetainedSccpAnchorOpen {}

impl norito::NoritoSchema for RetainedSccpAnchorOpen {
    fn nominal_name() -> String {
        <Vec<SccpAnchorV1> as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <Vec<SccpAnchorV1> as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedSccpAnchorOpen {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.claim().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.claim().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.claim().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedSccpAnchorOpen {
    fn json_serialize(&self, out: &mut String) {
        self.claim().json_serialize(out)
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.claim().json_serialize_to(out)
    }
}

#[cfg(test)]
#[path = "anchor_owner/tests.rs"]
mod tests;
