//! Allocation-free fixed leaves through the existing canonical positional record walker.
use super::*;
use crate::{NetworkId, block::BlockHeader, fastpq::*, nexus::AxtAssetIncarnationV1};
use iroha_crypto::HashOf;
use iroha_model_base::topology::{DataSpaceId, LaneId};

pub(super) trait Fixed:
    norito::SerializePayload + for<'de> norito::DeserializePayload<'de>
{
    fn decode(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}
struct Fields;
impl ncore::FieldDestination for Fields {
    type Error = Error;
}
impl<const I: usize, T: Fixed> ncore::DecodeField<I, T> for Fields {
    type Value = T;
    fn decode_field(
        &mut self,
        field: ncore::CanonicalField<'_, T>,
    ) -> Result<T, ncore::DecodeIntoError<Error>> {
        field.with_payload(|bytes| T::decode(bytes).map_err(destination))
    }
}
macro_rules! scalar {
    ($($type:ty),* $(,)?) => {$ (
        impl Fixed for $type {
            fn decode(bytes: &[u8]) -> Result<Self, Error> {
                let (value, used) = <Self as ncore::DecodeFromSlice<'_>>::decode_from_slice(bytes)?;
                finish(bytes,used)?; Ok(value)
            }
        }
    )*};
}
scalar!(u8, u16, u32, u64, Hash, HashOf<BlockHeader>, NetworkId);
impl<const N: usize> Fixed for [u8; N] {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        // Canonical raw-array fields have no child payload context. The generated
        // record walker already checked this field's exact width and owns the
        // enclosing record's completion; finishing from this pointer would instead
        // require every following field in that record to be absent.
        bytes
            .try_into()
            .map_err(|_| norito::Error::LengthMismatch.into())
    }
}
// These two transparent model owners contain only byte-aligned fixed leaves.
// Their canonical owning decoder never allocates a DTO or realignment buffer.
macro_rules! byte_aligned {
    ($($type:ty),* $(,)?) => {$ (
        impl Fixed for $type {
            fn decode(bytes: &[u8]) -> Result<Self, Error> {
                const { assert!(std::mem::align_of::<Self>() == 1); }
                let (value,used) = ncore::decode_field_canonical::<Self>(bytes)?;
                finish(bytes,used)?; Ok(value)
            }
        }
    )*};
}
byte_aligned!(AssetDefinitionId, AxtAssetIncarnationV1);
macro_rules! record {
    ($type:ty { $($field:ident),* $(,)? }) => {
        impl Fixed for $type {
            fn decode(bytes: &[u8]) -> Result<Self, Error> {
                let (($($field,)*),used) = <Self as ncore::DecodeRecordFields<Fields>>::decode_fields(bytes,&mut Fields)?;
                finish(bytes,used)?; Ok(Self { $($field,)* })
            }
        }
    };
}
record!(FastpqExecutionAssetV1 {
    definition,
    incarnation
});
record!(FastpqSourceStatementContextV1 { network_id, height });
record!(FastpqSourceLaneV1 {
    lane_id,
    lane_incarnation
});
record!(FastpqSourceExecutionEntryV1 {
    entry_hash,
    execution_kind,
    route,
    dataspace_id
});
record!(FastpqExecutionEffectContextV1 { source, entry });
record!(FastpqOrdinarySourceStatementLeafV1 {
    source,
    statement_index,
    entry_index,
    effect_count,
    entry_hash,
    execution_kind,
    route,
    dataspace_id,
    effects_digest,
    slot,
    perm_root,
    tx_set_hash
});
record!(FastpqOrdinarySourceStatementManifestV1 {
    source,
    executed_entry_count,
    source_entries_digest,
    coverage,
    statement_count,
    statement_root
});
impl Fixed for LaneId {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let ((id,), used) = Self::decode_fields(bytes, &mut Fields)?;
        finish(bytes, used)?;
        Ok(Self::new(id))
    }
}
impl Fixed for DataSpaceId {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let ((id,), used) = Self::decode_fields(bytes, &mut Fields)?;
        finish(bytes, used)?;
        Ok(Self::new(id))
    }
}
impl Fixed for FastpqSourceExecutionKindV1 {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = match tag(bytes)? {
            0 => Self::ExecutionCall,
            1 => Self::ProtocolPurpose,
            _ => return Err(invalid_tag()),
        };
        finish(bytes, 4)?;
        Ok(value)
    }
}
impl Fixed for FastpqSourceEffectCoverageV1 {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = match tag(bytes)? {
            0 => Self::Complete,
            1 => Self::Unsupported,
            _ => return Err(invalid_tag()),
        };
        finish(bytes, 4)?;
        Ok(value)
    }
}
impl Fixed for FastpqSourceRouteV1 {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 4;
        let value = match tag(bytes)? {
            0 => Self::Unrouted,
            1 => Self::Lane(field::<FastpqSourceLaneV1, _>(
                bytes,
                &mut offset,
                Fixed::decode,
            )?),
            _ => return Err(invalid_tag()),
        };
        finish(bytes, offset)?;
        Ok(value)
    }
}
impl Fixed for AssetBalanceScope {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 4;
        let value = match tag(bytes)? {
            0 => Self::Global,
            1 => Self::Dataspace(field::<DataSpaceId, _>(bytes, &mut offset, Fixed::decode)?),
            _ => return Err(invalid_tag()),
        };
        finish(bytes, offset)?;
        Ok(value)
    }
}

#[derive(Default)]
pub(super) struct ManifestDestination {
    source: Option<FastpqSourceStatementContextV1>,
    executed_entry_count: Option<u32>,
    source_entries_digest: Option<Hash>,
    coverage: Option<FastpqSourceEffectCoverageV1>,
    statement_count: Option<u32>,
    statement_root: Option<Hash>,
    valid: bool,
}
impl ManifestDestination {
    pub(super) fn value(&self) -> Option<FastpqOrdinarySourceStatementManifestV1> {
        if !self.valid {
            return None;
        }
        Some(FastpqOrdinarySourceStatementManifestV1 {
            source: self.source?,
            executed_entry_count: self.executed_entry_count?,
            source_entries_digest: self.source_entries_digest?,
            coverage: self.coverage?,
            statement_count: self.statement_count?,
            statement_root: self.statement_root?,
        })
    }
}
impl ncore::FieldDestination for ManifestDestination {
    type Error = Error;
}
macro_rules! manifest_field {
    ($i:literal, $field:ident, $type:ty) => {
        impl ncore::DecodeField<$i, $type> for ManifestDestination {
            type Value = ();
            fn decode_field(
                &mut self,
                field: ncore::CanonicalField<'_, $type>,
            ) -> Result<(), ncore::DecodeIntoError<Error>> {
                self.$field =
                    Some(field.with_payload(|bytes| {
                        <$type as Fixed>::decode(bytes).map_err(destination)
                    })?);
                self.valid = $i == 5;
                Ok(())
            }
        }
    };
}
manifest_field!(0, source, FastpqSourceStatementContextV1);
manifest_field!(1, executed_entry_count, u32);
manifest_field!(2, source_entries_digest, Hash);
manifest_field!(3, coverage, FastpqSourceEffectCoverageV1);
manifest_field!(4, statement_count, u32);
manifest_field!(5, statement_root, Hash);
impl norito::SerializePayload for ManifestDestination {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        norito::SerializePayload::serialize(
            &self.value().ok_or(norito::Error::LengthMismatch)?,
            writer,
        )
    }
}
impl ncore::PreparedRecordDestination<FastpqOrdinarySourceStatementManifestV1>
    for ManifestDestination
{
    fn reset(&mut self) {
        self.valid = false;
    }
}
