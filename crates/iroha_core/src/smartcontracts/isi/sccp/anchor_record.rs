//! Funded immutable open anchors retained through current, undo and snapshot readers.
//!
//! Snapshot DTOs require explicit original-pool admission. Clones never allocate, and an
//! append admits the complete new graph before changing its caller's current version.

use std::{alloc::Layout, fmt};

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, AllocationReservation, ChargedBuffer, ChargedBufferError,
    ChargedShared, PrepaidBufferError, PrepaidSharedError,
};
use iroha_data_model::sccp::generation::{SCCP_ANCHOR_CHUNK_SIZE_V1, SccpAnchorV1};
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonSerialize},
};

/// Structural rejection remains distinct from refusal by the original execution pool.
#[derive(Debug, thiserror::Error)]
pub enum AnchorRecordError {
    /// Invalid length or original-pool relation.
    #[error("invalid SCCP anchor record: {0}")]
    Invalid(&'static str),
    /// Original configured execution pool refused admission.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// The physical allocator refused an already admitted allocation.
    #[error("SCCP anchor allocation unavailable ({bytes} bytes)")]
    Allocator {
        /// Exact requested allocation size.
        bytes: usize,
    },
}

/// Immutable anchors whose final reader retains both data and control allocation charges.
#[derive(Clone, Default)]
pub struct RetainedSccpAnchors(Option<ChargedShared<ChargedBuffer<SccpAnchorV1>>>);

impl RetainedSccpAnchors {
    /// Read the original immutable anchors without copying their backing allocation.
    #[must_use]
    pub fn as_slice(&self) -> &[SccpAnchorV1] {
        self.0.as_ref().map_or(&[], |owner| owner.as_slice())
    }

    /// Admit an incomplete snapshot chunk as a new graph in the original execution pool.
    ///
    /// # Errors
    /// Rejects complete/overfull stored chunks, original capacity refusal or physical failure.
    pub(crate) fn admit(
        source: &[SccpAnchorV1],
        budget: &AllocationBudget,
    ) -> Result<Self, AnchorRecordError> {
        let mut reservation = budget.try_reserve_bytes(Self::admission_demand(source)?)?;
        Self::admit_prepaid(source, budget, &mut reservation)
    }

    /// Complete data/control demand of a stored incomplete chunk without allocating.
    ///
    /// # Errors
    /// Rejects a complete stored chunk before requesting any original-pool credit.
    pub(crate) fn admission_demand(source: &[SccpAnchorV1]) -> Result<usize, AnchorRecordError> {
        if source.len() >= SCCP_ANCHOR_CHUNK_SIZE_V1 {
            return Err(AnchorRecordError::Invalid(
                "stored chunk must be incomplete",
            ));
        }
        Self::demand(source.len())
    }

    /// Restore from one original reservation covering the complete snapshot graph.
    ///
    /// # Errors
    /// Rejects invalid stored shape or original reservation and preserves physical failure.
    pub(crate) fn admit_prepaid(
        source: &[SccpAnchorV1],
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, AnchorRecordError> {
        Self::admission_demand(source)?;
        Self::from_parts_prepaid(source, None, budget, reservation)
    }

    /// Append under the same original pool, without changing any current or undo reader.
    /// A complete returned chunk is transient: the caller publishes its root and an empty open
    /// chunk. The complete graph remains funded until its final reader closes.
    ///
    /// # Errors
    /// Rejects a foreign pool or overfull chunk; preserves original allocation refusal.
    pub(crate) fn try_appended(
        &self,
        anchor: SccpAnchorV1,
        budget: &AllocationBudget,
    ) -> Result<Self, AnchorRecordError> {
        let mut reservation = budget.try_reserve_bytes(self.append_demand(budget)?)?;
        self.try_appended_prepaid(anchor, budget, &mut reservation)
    }

    /// Complete data and control demand for the next anchor version, without allocation.
    ///
    /// # Errors
    /// Rejects foreign original custody or an already complete chunk.
    pub(crate) fn append_demand(
        &self,
        budget: &AllocationBudget,
    ) -> Result<usize, AnchorRecordError> {
        if self
            .0
            .as_ref()
            .is_some_and(|owner| !owner.belongs_to(budget))
        {
            return Err(AnchorRecordError::Invalid(
                "append changed the original pool",
            ));
        }
        if self.as_slice().len() >= SCCP_ANCHOR_CHUNK_SIZE_V1 {
            return Err(AnchorRecordError::Invalid("chunk is already complete"));
        }
        Self::demand(self.as_slice().len() + 1)
    }

    /// Consume this anchor's exact part of one already admitted complete transition.
    /// The parent's remainder stays available for its other original retained records.
    ///
    /// # Errors
    /// Rejects mismatched original custody or insufficient reserved bytes before allocation;
    /// preserves physical allocation failure separately from invalid input.
    pub(crate) fn try_appended_prepaid(
        &self,
        anchor: SccpAnchorV1,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, AnchorRecordError> {
        self.append_demand(budget)?;
        Self::from_parts_prepaid(self.as_slice(), Some(anchor), budget, reservation)
    }

    fn demand(count: usize) -> Result<usize, AnchorRecordError> {
        if count == 0 {
            return Ok(0);
        }
        let data =
            Layout::array::<SccpAnchorV1>(count).map_err(|_| AllocationRefusal::DemandOverflow)?;
        let shell = ChargedShared::<ChargedBuffer<SccpAnchorV1>>::allocation_layout();
        data.size()
            .checked_add(shell.size())
            .ok_or_else(|| AllocationRefusal::DemandOverflow.into())
    }

    fn from_parts_prepaid(
        source: &[SccpAnchorV1],
        appended: Option<SccpAnchorV1>,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self, AnchorRecordError> {
        let count = source
            .len()
            .checked_add(usize::from(appended.is_some()))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let bytes = Self::demand(count)?;
        if !reservation.belongs_to(budget) || reservation.remaining_bytes() < bytes {
            return Err(AnchorRecordError::Invalid(
                "original complete reservation mismatch",
            ));
        }
        if count == 0 {
            return Ok(Self::default());
        }
        let remainder = reservation.remaining_bytes() - bytes;
        let shell = ChargedShared::reserve_from(reservation).map_err(|error| match error {
            PrepaidSharedError::Allocator { requested_bytes } => AnchorRecordError::Allocator {
                bytes: requested_bytes,
            },
            PrepaidSharedError::Reservation(_) => {
                AnchorRecordError::Invalid("shell demand mismatch")
            }
        })?;
        let mut buffer =
            ChargedBuffer::from_reservation(count, reservation).map_err(|error| match error {
                PrepaidBufferError::Allocation(ChargedBufferError::Allocator {
                    requested_bytes,
                }) => AnchorRecordError::Allocator {
                    bytes: requested_bytes,
                },
                PrepaidBufferError::Allocation(ChargedBufferError::Admission(original)) => {
                    original.into()
                }
                PrepaidBufferError::Reservation(_) => {
                    AnchorRecordError::Invalid("data demand mismatch")
                }
            })?;
        for value in source.iter().copied().chain(appended) {
            buffer
                .try_push(value)
                .map_err(|_| AnchorRecordError::Invalid("anchor count changed"))?;
        }
        debug_assert_eq!(reservation.remaining_bytes(), remainder);
        Ok(Self(Some(shell.initialize(buffer))))
    }
}

impl fmt::Debug for RetainedSccpAnchors {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(out)
    }
}
impl PartialEq for RetainedSccpAnchors {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for RetainedSccpAnchors {}
impl norito::NoritoSchema for RetainedSccpAnchors {
    fn nominal_name() -> String {
        <Vec<SccpAnchorV1> as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <Vec<SccpAnchorV1> as norito::NoritoSchema>::frame_name()
    }
}
impl SerializePayload for RetainedSccpAnchors {
    fn serialize(&self, out: &mut Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<SccpAnchorV1, _>(out, self.as_slice().iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_hint(self.as_slice().iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_exact(self.as_slice().iter())
    }
}
impl JsonSerialize for RetainedSccpAnchors {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, value) in self.as_slice().iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, value) in self.as_slice().iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }
}

#[cfg(test)]
mod tests {
    //! Exact encoding, original-pool refusal and final-reader retirement controls.
    use super::*;
    use norito::codec::{DecodeAll, Encode};

    fn anchor(value: u8) -> SccpAnchorV1 {
        SccpAnchorV1 {
            core_hash: [value; 32],
            result: [value.wrapping_add(1); 32],
        }
    }

    #[test]
    fn empty_and_retained_current_undo_encodings_equal_canonical_dtos() {
        let budget = AllocationBudget::new(1024 * 1024);
        for dto in [vec![], vec![anchor(1), anchor(2)]] {
            let retained = RetainedSccpAnchors::admit(&dto, &budget).unwrap();
            assert_eq!(retained.as_slice(), dto);
            assert_eq!(retained.encode(), dto.encode());
            assert_eq!(retained.encoded_len_hint(), dto.encoded_len_hint());
            assert_eq!(retained.encoded_len_exact(), dto.encoded_len_exact());
            assert_eq!(
                Vec::<SccpAnchorV1>::decode_all(&mut retained.encode().as_slice()).unwrap(),
                dto
            );
            assert_eq!(
                json::to_json(&retained).unwrap(),
                json::to_json(&dto).unwrap()
            );
            assert_eq!(format!("{retained:?}"), format!("{dto:?}"));
            assert_eq!(retained, retained.clone());
        }
        assert_eq!(budget.reserved_bytes(), 0);
        let empty = RetainedSccpAnchors::admit(&[], &AllocationBudget::new(0)).unwrap();
        assert!(empty.as_slice().is_empty());
    }

    #[test]
    fn append_keeps_original_backing_and_refunds_only_final_readers() {
        let budget = AllocationBudget::new(1024 * 1024);
        let current = RetainedSccpAnchors::admit(&[anchor(1)], &budget).unwrap();
        let first = budget.reserved_bytes();
        let undo = current.clone();
        assert_eq!(current.as_slice().as_ptr(), undo.as_slice().as_ptr());
        assert_eq!(budget.reserved_bytes(), first);
        let next = current.try_appended(anchor(2), &budget).unwrap();
        let both = budget.reserved_bytes();
        assert!(both > first);
        assert_eq!(undo.as_slice(), [anchor(1)]);
        assert_eq!(next.as_slice(), [anchor(1), anchor(2)]);
        assert_ne!(next.as_slice().as_ptr(), undo.as_slice().as_ptr());
        drop(current);
        assert_eq!(budget.reserved_bytes(), both);
        drop(undo);
        assert_eq!(budget.reserved_bytes(), both - first);
        drop(next);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn original_capacity_refusal_preserves_current_then_exact_retry_succeeds() {
        let budget = AllocationBudget::new(1024 * 1024);
        let source = RetainedSccpAnchors::admit(&[anchor(1)], &budget).unwrap();
        let first = budget.reserved_bytes();
        let measure = source.try_appended(anchor(2), &budget).unwrap();
        let both = budget.reserved_bytes();
        drop(measure);
        budget.set_limit_bytes(both - 1);
        assert!(matches!(
            source.try_appended(anchor(2), &budget),
            Err(AnchorRecordError::Admission(
                AllocationRefusal::ExceedsLimit { .. } | AllocationRefusal::Capacity { .. }
            ))
        ));
        assert_eq!(budget.reserved_bytes(), first);
        assert_eq!(source.as_slice(), [anchor(1)]);
        budget.set_limit_bytes(both);
        let retried = source.try_appended(anchor(2), &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), both);
        assert_eq!(retried.as_slice(), [anchor(1), anchor(2)]);
        drop((source, retried));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn foreign_pool_and_complete_stored_chunks_fail_before_admission() {
        let budget = AllocationBudget::new(1024 * 1024);
        let foreign = AllocationBudget::new(1024 * 1024);
        let source = RetainedSccpAnchors::admit(&[anchor(1)], &budget).unwrap();
        let before = budget.reserved_bytes();
        assert!(matches!(
            source.try_appended(anchor(2), &foreign),
            Err(AnchorRecordError::Invalid(_))
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), before);
        let dto = vec![anchor(3); SCCP_ANCHOR_CHUNK_SIZE_V1];
        assert!(matches!(
            RetainedSccpAnchors::admit(&dto, &foreign),
            Err(AnchorRecordError::Invalid(_))
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
    }

    #[test]
    fn complete_transient_chunk_retains_original_custody_through_merkle_publication() {
        let budget = AllocationBudget::new(1024 * 1024);
        let dto = vec![anchor(4); SCCP_ANCHOR_CHUNK_SIZE_V1 - 1];
        let open = RetainedSccpAnchors::admit(&dto, &budget).unwrap();
        let complete = open.try_appended(anchor(5), &budget).unwrap();
        let root = iroha_data_model::sccp::generation::anchor_chunk_root_v1(0, complete.as_slice())
            .unwrap();
        let reader = complete.clone();
        let bytes = budget.reserved_bytes();
        assert!(matches!(
            complete.try_appended(anchor(6), &budget),
            Err(AnchorRecordError::Invalid(_))
        ));
        assert_eq!(budget.reserved_bytes(), bytes);
        drop((open, complete));
        assert!(budget.reserved_bytes() > 0);
        assert_eq!(
            iroha_data_model::sccp::generation::anchor_chunk_root_v1(0, reader.as_slice()),
            Some(root)
        );
        drop(reader);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn complete_prepaid_transition_preserves_original_remainder_and_rejects_foreign_or_short() {
        let budget = AllocationBudget::new(1024 * 1024);
        let source = RetainedSccpAnchors::admit(&[anchor(1)], &budget).unwrap();
        let source_bytes = budget.reserved_bytes();
        let bytes = source.append_demand(&budget).unwrap();
        let mut short = budget.try_reserve_bytes(bytes - 1).unwrap();
        assert!(
            source
                .try_appended_prepaid(anchor(2), &budget, &mut short)
                .is_err()
        );
        assert_eq!(short.remaining_bytes(), bytes - 1);
        assert_eq!(budget.reserved_bytes(), source_bytes + bytes - 1);
        drop(short);
        let foreign = AllocationBudget::new(1024 * 1024);
        let mut wrong = foreign.try_reserve_bytes(bytes).unwrap();
        assert!(
            source
                .try_appended_prepaid(anchor(2), &budget, &mut wrong)
                .is_err()
        );
        assert_eq!(wrong.remaining_bytes(), bytes);
        assert_eq!(budget.reserved_bytes(), source_bytes);
        drop(wrong);
        let mut complete = budget.try_reserve_bytes(bytes + 31).unwrap();
        let retained = source
            .try_appended_prepaid(anchor(2), &budget, &mut complete)
            .unwrap();
        assert_eq!(complete.remaining_bytes(), 31);
        assert_eq!(retained.as_slice(), [anchor(1), anchor(2)]);
        assert_eq!(budget.reserved_bytes(), source_bytes + bytes + 31);
        drop(complete);
        assert_eq!(budget.reserved_bytes(), source_bytes + bytes);
        drop((source, retained));
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(RetainedSccpAnchors::demand(usize::MAX).is_err());
    }

    #[test]
    fn bounded_json_uses_exact_canonical_length_and_rejects_short_output() {
        let budget = AllocationBudget::new(1024 * 1024);
        let dto = vec![anchor(1), anchor(2)];
        let retained = RetainedSccpAnchors::admit(&dto, &budget).unwrap();
        let expected = json::to_json(&dto).unwrap();
        assert_eq!(
            json::to_json_bounded(&retained, expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            json::to_json_bounded(&retained, expected.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        ));
        assert_eq!(retained.as_slice(), dto);
    }
}
