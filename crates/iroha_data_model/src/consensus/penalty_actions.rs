//! Immutable native penalty actions with exact original decoded allocation custody.
//!
//! This is the existing ordered action sequence, with no new wire layout or authority.
//! Prepared values retain all actual arrays, peer/controller keys and Quantity digits.
//! TODO: extend original-pool ownership to the parent-service certificate, evidence
//! validation graph and Core effect construction before claiming complete effects custody.

use super::NposPenaltyAction;
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedShared};
use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, VecMeta};
use norito::core as ncore;
use std::{alloc::Layout, cmp::Ordering, fmt};

mod prepared;
use prepared::ActionCustody;
pub use prepared::{NposPenaltyActionsCustodyError, PreparedNposPenaltyActions};

/// The canonical ordered penalty-action sequence.
///
/// Ordinary transport remains untrusted. An admitted clone retains the exact
/// original immutable action graph and every associated finite-pool charge.
#[derive(Default)]
pub struct NposPenaltyActions {
    storage: Storage,
}
enum Storage {
    Untrusted(Vec<NposPenaltyAction>),
    Admitted(ChargedShared<Funded>),
}
impl Default for Storage {
    fn default() -> Self {
        Self::Untrusted(Vec::new())
    }
}
struct Funded {
    // All canonical allocations are destroyed before their original leaf charges.
    values: ChargedBuffer<NposPenaltyAction>,
    custody: ChargedBuffer<ActionCustody>,
}
impl Funded {
    fn belongs_to(&self, pool: &AllocationBudget) -> bool {
        self.values.belongs_to(pool)
            && self.custody.belongs_to(pool)
            && self.custody.as_slice().iter().all(|v| v.belongs_to(pool))
    }
}
impl NposPenaltyActions {
    /// Construct untrusted transport without sorting, deduplication or authority.
    #[must_use]
    pub fn from_untrusted(values: Vec<NposPenaltyAction>) -> Self {
        Self {
            storage: Storage::Untrusted(values),
        }
    }
    /// Borrow the exact ordered actions without mutable or allocation escape.
    #[must_use]
    pub fn as_slice(&self) -> &[NposPenaltyAction] {
        match &self.storage {
            Storage::Untrusted(values) => values,
            Storage::Admitted(owner) => owner.values.as_slice(),
        }
    }
    /// Iterate the original ordered sequence.
    pub fn iter(&self) -> std::slice::Iter<'_, NposPenaltyAction> {
        self.as_slice().iter()
    }
    /// Exact initialized action count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    /// Whether the canonical sequence has no actions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
    /// Whether every array, control and nested allocation belongs to this pool.
    #[must_use]
    pub fn admitted_to(&self, pool: &AllocationBudget) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => false,
            Storage::Admitted(owner) => owner.belongs_to(pool) && Funded::belongs_to(owner, pool),
        }
    }
    /// Whether admitted clones retain the same immutable physical owner.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.storage, &right.storage) {
            (Storage::Admitted(left), Storage::Admitted(right)) => {
                ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
    /// Exact immutable shell layout, separate from all typed and leaf allocations.
    #[must_use]
    pub fn allocation_layout() -> Layout {
        ChargedShared::<Funded>::allocation_layout()
    }
}
impl Clone for NposPenaltyActions {
    fn clone(&self) -> Self {
        if cfg!(all(test, sumeragi_model_mutation = "DM45")) {
            return Self::from_untrusted(self.as_slice().to_vec());
        }
        Self {
            storage: match &self.storage {
                Storage::Untrusted(values) => Storage::Untrusted(values.clone()),
                Storage::Admitted(owner) => Storage::Admitted(owner.clone()),
            },
        }
    }
}
impl fmt::Debug for NposPenaltyActions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}
impl PartialEq for NposPenaltyActions {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for NposPenaltyActions {}
impl PartialOrd for NposPenaltyActions {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for NposPenaltyActions {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
impl<'a> IntoIterator for &'a NposPenaltyActions {
    type Item = &'a NposPenaltyAction;
    type IntoIter = std::slice::Iter<'a, NposPenaltyAction>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl ncore::SerializePayload for NposPenaltyActions {
    fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::write_element_sequence::<NposPenaltyAction, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        ncore::sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        ncore::sequence_encoded_len_exact(self.iter())
    }
}
impl<'de> ncore::DeserializePayload<'de> for NposPenaltyActions {
    fn deserialize(archive: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archive).expect("canonical native penalty action sequence")
    }
    fn try_deserialize(archive: &'de ncore::Archived<Self>) -> Result<Self, norito::Error> {
        <Vec<NposPenaltyAction> as ncore::DeserializePayload>::try_deserialize(archive.cast())
            .map(Self::from_untrusted)
    }
}
impl<'de> ncore::DecodeFromSlice<'de> for NposPenaltyActions {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        <Vec<NposPenaltyAction> as ncore::DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(values, used)| (Self::from_untrusted(values), used))
    }
}
// This is a payload sequence inside the canonical SignedBlockWire, like
// BlockSignatures. No standalone root-frame identity is declared for its actions.
impl TypeId for NposPenaltyActions {
    fn id() -> String {
        <Vec<NposPenaltyAction> as TypeId>::id()
    }
}
impl IntoSchema for NposPenaltyActions {
    fn type_name() -> String {
        <Vec<NposPenaltyAction> as IntoSchema>::type_name()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: std::any::TypeId::of::<NposPenaltyAction>(),
            }));
            NposPenaltyAction::update_schema_map(map);
        }
    }
}
impl norito::json::JsonSerialize for NposPenaltyActions {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, action) in self.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            norito::json::JsonSerialize::json_serialize(action, out);
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
            for (index, action) in self.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                norito::json::JsonSerialize::json_serialize_to(action, out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
impl norito::json::JsonDeserialize for NposPenaltyActions {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        <Vec<NposPenaltyAction> as norito::json::JsonDeserialize>::json_deserialize(parser)
            .map(Self::from_untrusted)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        <Vec<NposPenaltyAction> as norito::json::JsonDeserialize>::json_from_value(value)
            .map(Self::from_untrusted)
    }
}
