//! Immutable original parent-service QC bytes with the existing Vec<u8> payload layout.
//!
//! Custody of these opaque bytes is not QC verification or historical authority.
//! TODO: fund the independently decoded QC graph and the producer's pre-assembly copy.
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedShared};
use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, VecMeta};
use norito::core as ncore;
use std::{alloc::Layout, cmp::Ordering, fmt, ops::Deref};

mod prepared;
pub use prepared::{ParentServiceCustodyError, PreparedParentServiceCommitQc};

/// The original parent-service CommitQC frame, retaining exact admitted byte custody.
///
/// Untrusted transport is an input only. Admitted values expose immutable bytes and
/// clone only their original control; neither path grants signature or quorum authority.
#[derive(Default)]
pub struct NposParentServiceCommitQc {
    storage: Storage,
}
enum Storage {
    Untrusted(Vec<u8>),
    Admitted(ChargedShared<ChargedBuffer<u8>>),
}
impl Default for Storage {
    fn default() -> Self {
        Self::Untrusted(Vec::new())
    }
}
impl NposParentServiceCommitQc {
    /// Retain ordinary untrusted transport bytes without claiming physical admission.
    #[must_use]
    pub fn from_untrusted(bytes: Vec<u8>) -> Self {
        Self {
            storage: Storage::Untrusted(bytes),
        }
    }
    /// Borrow the original immutable byte sequence.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match &self.storage {
            Storage::Untrusted(bytes) => bytes,
            Storage::Admitted(owner) => owner.as_slice(),
        }
    }
    /// Whether both the byte allocation and its immutable control retain this exact pool.
    #[must_use]
    pub fn admitted_to(&self, pool: &AllocationBudget) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => false,
            Storage::Admitted(owner) => {
                owner.belongs_to(pool) && ChargedBuffer::belongs_to(owner, pool)
            }
        }
    }
    /// Whether two admitted values share the original physical control.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.storage, &right.storage) {
            (Storage::Admitted(left), Storage::Admitted(right)) => {
                ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
    /// Exact shared-control allocation, excluding its byte leaf.
    #[must_use]
    pub fn allocation_layout() -> Layout {
        ChargedShared::<ChargedBuffer<u8>>::allocation_layout()
    }
}
impl Deref for NposParentServiceCommitQc {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl Clone for NposParentServiceCommitQc {
    fn clone(&self) -> Self {
        if cfg!(all(test, sumeragi_model_mutation = "DM50")) {
            return Self::from_untrusted(self.as_slice().to_vec());
        }
        Self {
            storage: match &self.storage {
                Storage::Untrusted(bytes) => Storage::Untrusted(bytes.clone()),
                Storage::Admitted(owner) => Storage::Admitted(owner.clone()),
            },
        }
    }
}
impl fmt::Debug for NposParentServiceCommitQc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}
impl PartialEq for NposParentServiceCommitQc {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for NposParentServiceCommitQc {}
impl PartialOrd for NposParentServiceCommitQc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for NposParentServiceCommitQc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
impl ncore::SerializePayload for NposParentServiceCommitQc {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::SerializePayload::serialize(&self.as_slice(), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_hint(&self.as_slice())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_exact(&self.as_slice())
    }
}
impl<'de> ncore::DeserializePayload<'de> for NposParentServiceCommitQc {
    fn deserialize(archive: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archive).expect("canonical parent-service byte sequence")
    }
    fn try_deserialize(archive: &'de ncore::Archived<Self>) -> Result<Self, norito::Error> {
        <Vec<u8> as ncore::DeserializePayload>::try_deserialize(archive.cast())
            .map(Self::from_untrusted)
    }
}
impl<'de> ncore::DecodeFromSlice<'de> for NposParentServiceCommitQc {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        <Vec<u8> as ncore::DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(bytes, used)| (Self::from_untrusted(bytes), used))
    }
}
// Payload-only child of SignedBlockWire, without a separate root-frame identity.
impl TypeId for NposParentServiceCommitQc {
    fn id() -> String {
        <Vec<u8> as TypeId>::id()
    }
}
impl IntoSchema for NposParentServiceCommitQc {
    fn type_name() -> String {
        <Vec<u8> as IntoSchema>::type_name()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: std::any::TypeId::of::<u8>(),
            }));
            u8::update_schema_map(map);
        }
    }
}
impl norito::json::JsonSerialize for NposParentServiceCommitQc {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, byte) in self.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            norito::json::JsonSerialize::json_serialize(byte, out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, byte) in self.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                norito::json::JsonSerialize::json_serialize_to(byte, out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
impl norito::json::JsonDeserialize for NposParentServiceCommitQc {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        <Vec<u8> as norito::json::JsonDeserialize>::json_deserialize(parser)
            .map(Self::from_untrusted)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        <Vec<u8> as norito::json::JsonDeserialize>::json_from_value(value).map(Self::from_untrusted)
    }
}
