//! Original allocation custody for stored light-client validator bytes and their MV copies.

use iroha_allocation::{AllocationBudget, AllocationReservation, ChargedBuffer, ChargedShared};
use iroha_data_model::{bridge::SccpNetworkV1, sccp::light_client::SccpLcConsensusSetV1};
use iroha_sccp::light_client::{prepared::SccpLcAttemptErrorV1, state::SccpLcConsensusSetRefV1};
use norito::core::{Encoder, SerializePayload, write_len_prefixed};
use std::{alloc::Layout, fmt};

// Field order retires the decoded byte allocation before returning its original allowance.
struct Decoded {
    value: SccpLcConsensusSetV1,
    _allowance: AllocationReservation,
}
enum Bytes {
    Constructed(ChargedBuffer<u8>),
    Decoded(Decoded),
}
impl Bytes {
    fn get(&self) -> &[u8] {
        match self {
            Self::Constructed(bytes) => bytes.as_slice(),
            Self::Decoded(decoded) => &decoded.value.set_bytes,
        }
    }
}

/// Immutable original validator bytes with independently versioned lifecycle scalars.
#[derive(Clone)]
pub struct RetainedSccpLcSet {
    bytes: ChargedShared<Bytes>,
    /// Authenticated chain-specific validator set id.
    pub set_id: u64,
    /// First source height covered by these validators.
    pub valid_from_source_height: u64,
    /// Source time at which a successor superseded this MV version.
    pub superseded_at_source_ms: Option<u64>,
}
impl RetainedSccpLcSet {
    /// Copy borrowed authenticated bytes only after admitting their actual backing and shell.
    ///
    /// # Errors
    /// Preserves the original finite-pool or physical allocator refusal.
    pub fn admit(
        source: SccpLcConsensusSetRefV1<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        let layout = Layout::array::<u8>(source.set_bytes.len())
            .map_err(|_| iroha_allocation::AllocationRefusal::DemandOverflow)?;
        let mut grant =
            budget.try_reserve_layouts([layout, ChargedShared::<Bytes>::allocation_layout()])?;
        let shell = ChargedShared::<Bytes>::reserve_from(&mut grant)?;
        let mut bytes = ChargedBuffer::from_reservation(source.set_bytes.len(), &mut grant)
            .map_err(|error| match error {
                iroha_allocation::PrepaidBufferError::Allocation(error) => {
                    SccpLcAttemptErrorV1::Buffer(error)
                }
                _ => SccpLcAttemptErrorV1::Invariant("light-client set original reservation"),
            })?;
        for byte in source.set_bytes {
            bytes.push_reserved(*byte);
        }
        Ok(Self {
            bytes: shell.initialize(Bytes::Constructed(bytes)),
            set_id: source.set_id,
            valid_from_source_height: source.valid_from_source_height,
            superseded_at_source_ms: source.superseded_at_source_ms,
        })
    }

    /// Borrow the immutable original canonical validator frame.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get()
    }

    /// Borrow scalar metadata and the original validator frame without allocating.
    pub fn as_ref(&self) -> SccpLcConsensusSetRefV1<'_> {
        SccpLcConsensusSetRefV1 {
            set_id: self.set_id,
            valid_from_source_height: self.valid_from_source_height,
            superseded_at_source_ms: self.superseded_at_source_ms,
            set_bytes: self.bytes(),
        }
    }

    /// Decode one canonical bare snapshot record while retaining its original decode grant.
    pub(crate) fn decode_snapshot_hex(
        source: &str,
        budget: &AllocationBudget,
    ) -> Result<Self, SccpLcAttemptErrorV1> {
        use norito::codec::DecodeAll as _;
        fn malformed() -> SccpLcAttemptErrorV1 {
            SccpLcAttemptErrorV1::Protocol(iroha_sccp::light_client::SccpLcError::MalformedFrame(
                "invalid stored validator snapshot",
            ))
        }
        if !source.len().is_multiple_of(2)
            || source
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(malformed());
        }
        let mut encoded = ChargedBuffer::new(source.len() / 2, budget)?;
        for _ in 0..source.len() / 2 {
            encoded.push_reserved(0);
        }
        hex::decode_to_slice(source, encoded.as_mut_slice()).map_err(|_| malformed())?;
        let mut control = budget.try_reserve_layouts([
            ChargedShared::<Bytes>::allocation_layout(),
            norito::core::DecodeBudgetContext::allocation_layout(),
        ])?;
        let shell = ChargedShared::<Bytes>::reserve_from(&mut control)?;
        let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
        let mut allowance = budget.try_reserve_bytes(available)?;
        let context = norito::core::DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, available, usize::MAX),
            &mut control,
        )?;
        let value = context.with(|| {
            norito::core::classify_decode_attempt(|| {
                SccpLcConsensusSetV1::decode_all(&mut encoded.as_slice())
            })
        })?;
        context.with(|| {
            norito::core::classify_decode_attempt(|| {
                norito::codec::verify_exact_payload(&value, encoded.as_slice())
            })
        })?;
        let used = usize::try_from(context.consumed_allocated_bytes())
            .map_err(|_| iroha_allocation::AllocationRefusal::DemandOverflow)?;
        let retained = allowance
            .try_partition_bytes(used)
            .map_err(|_| SccpLcAttemptErrorV1::Invariant("stored validator decode grant"))?;
        let set_id = value.set_id;
        let valid_from_source_height = value.valid_from_source_height;
        let superseded_at_source_ms = value.superseded_at_source_ms;
        Ok(Self {
            bytes: shell.initialize(Bytes::Decoded(Decoded {
                value,
                _allowance: retained,
            })),
            set_id,
            valid_from_source_height,
            superseded_at_source_ms,
        })
    }
}
impl fmt::Debug for RetainedSccpLcSet {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(out)
    }
}
impl PartialEq for RetainedSccpLcSet {
    fn eq(&self, other: &Self) -> bool {
        self.set_id == other.set_id
            && self.valid_from_source_height == other.valid_from_source_height
            && self.superseded_at_source_ms == other.superseded_at_source_ms
            && self.bytes() == other.bytes()
    }
}
impl Eq for RetainedSccpLcSet {}
impl SerializePayload for RetainedSccpLcSet {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        write_len_prefixed(writer, &self.set_id)?;
        write_len_prefixed(writer, &self.valid_from_source_height)?;
        write_len_prefixed(writer, &self.superseded_at_source_ms)?;
        write_len_prefixed(writer, &self.bytes())
    }
}
impl norito::NoritoSchema for RetainedSccpLcSet {
    fn nominal_name() -> String {
        SccpLcConsensusSetV1::nominal_name()
    }
    fn frame_name() -> String {
        SccpLcConsensusSetV1::frame_name()
    }
}
mod base64_bytes {
    pub(super) use norito::json::{
        write_base64_json as serialize, write_base64_json_to as serialize_bounded,
    };
}

#[derive(norito::json::JsonSerialize)]
struct JsonView<'a> {
    set_id: u64,
    valid_from_source_height: u64,
    superseded_at_source_ms: Option<u64>,
    #[norito(
        with = "base64_bytes",
        bounded_with = "base64_bytes::serialize_bounded"
    )]
    set_bytes: &'a [u8],
}
impl norito::json::JsonSerialize for RetainedSccpLcSet {
    fn json_serialize(&self, out: &mut String) {
        JsonView {
            set_id: self.set_id,
            valid_from_source_height: self.valid_from_source_height,
            superseded_at_source_ms: self.superseded_at_source_ms,
            set_bytes: self.bytes(),
        }
        .json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        JsonView {
            set_id: self.set_id,
            valid_from_source_height: self.valid_from_source_height,
            superseded_at_source_ms: self.superseded_at_source_ms,
            set_bytes: self.bytes(),
        }
        .json_serialize_to(out)
    }
}

/// Canonical source-network and validator-set key.
pub type Key = (SccpNetworkV1, u64);
/// Closed original-pool current/undo node-copy policy.
pub struct Policy(AllocationReservation);
impl concread::bptree::NodeFunding for Policy {
    type Charge = iroha_allocation::AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("admitted light-client map node")
    }
}
macro_rules! retained_copy {
    ($value:ty) => {
        impl concread::bptree::NodeCloning<Key, $value> for Policy {
            fn clone_key(&mut self, key: &Key) -> Key {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                value.clone()
            }
        }
        impl concread::bptree::ClonePlanning<Key, $value> for Policy {
            fn plan_key(
                _: &Key,
                _: &mut concread::bptree::AllocationDemand,
            ) -> Result<(), concread::bptree::PlanningError> {
                Ok(())
            }
            fn plan_value(
                _: &$value,
                _: &mut concread::bptree::AllocationDemand,
            ) -> Result<(), concread::bptree::PlanningError> {
                Ok(())
            }
        }
    };
}
retained_copy!(RetainedSccpLcSet);
retained_copy!(Option<RetainedSccpLcSet>);
impl mv::storage::AdmittedStoragePolicy for Policy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
/// Current and undo storage using the original execution pool for every map allocation.
pub type Storage = mv::storage::Storage<Key, RetainedSccpLcSet, Mode>;
/// Closed storage mode; cloned records share their original validator bytes.
pub type Mode = concread::bptree::Prepaid<Policy>;

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::Encode as _;
    #[test]
    fn retained_set_wire_snapshot_and_copies_keep_original_custody() {
        let mut dto = SccpLcConsensusSetV1 {
            set_id: 7,
            valid_from_source_height: 42,
            superseded_at_source_ms: None,
            set_bytes: vec![3; 1024],
        };
        let budget = AllocationBudget::new(65536);
        assert!(RetainedSccpLcSet::admit((&dto).into(), &AllocationBudget::new(1)).is_err());
        let owner = RetainedSccpLcSet::admit((&dto).into(), &budget).unwrap();
        assert_eq!(owner.encode(), dto.encode());
        assert_eq!(
            norito::json::to_json(&owner).unwrap(),
            norito::json::to_json(&dto).unwrap()
        );
        let original = budget.reserved_bytes();
        let mut next = owner.clone();
        next.superseded_at_source_ms = Some(100);
        dto.superseded_at_source_ms = Some(100);
        assert_eq!(budget.reserved_bytes(), original);
        assert_eq!(next.encode(), dto.encode());
        assert_eq!(owner.superseded_at_source_ms, None);
        let restored =
            RetainedSccpLcSet::decode_snapshot_hex(&hex::encode(next.encode()), &budget).unwrap();
        assert_eq!(restored, next);
        assert!(RetainedSccpLcSet::decode_snapshot_hex("GG", &budget).is_err());
        assert!(
            RetainedSccpLcSet::decode_snapshot_hex(
                &hex::encode(next.encode()),
                &AllocationBudget::new(1)
            )
            .is_err()
        );
        drop(restored);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), original);
        drop(next);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
