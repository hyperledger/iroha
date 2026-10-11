//! Immutable canonical DA commitments and exact original decoded allocation custody.
//!
//! The sole wire record remains version, ordered commitments. Storage
//! state is never serialized. Prepared decoding retains the actual commitment array,
//! every UTF-8 governance tag and signature payload and their ledger through the last block reader. Transport
//! construction does not grant custody, DA authorization or finality.

use super::DaCommitmentRecord;
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_allocation::{AllocationBudget, ChargedShared, RetainedPayload};
use iroha_crypto::{Hash, HashOf};
use iroha_schema::{Declaration, IntoSchema, MetaMap, Metadata, NamedFieldsMeta, TypeId};
use norito::{
    codec::{Decode, Encode},
    core as ncore,
};
use std::{alloc::Layout, cmp::Ordering, fmt};

/// Versioned immutable proof commitments for every configured lane.
///
/// Ordinary construction and decoding are untrusted transport. Prepared decoding
/// shares only the same original charged arrays and UTF-8/signature leaves; callers cannot
/// extract or grow an admitted allocation independently of its retained ledger.
pub struct DaCommitmentBundle {
    storage: Storage,
}
#[allow(
    variant_size_differences,
    reason = "untrusted transport is bounded inline; admitted custody retains its original prepaid shared owner without a second heap allocation"
)]
enum Storage {
    Untrusted(CanonicalParts),
    Admitted(ChargedShared<RetainedPayload<CanonicalParts>>),
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields, decode_fields)]
struct CanonicalParts {
    version: u16,
    commitments: Vec<DaCommitmentRecord>,
}
mod prepared;
pub use prepared::{DaCommitmentCustodyError, PreparedDaCommitmentBundle};

impl DaCommitmentBundle {
    /// Initial and sole first-release commitment layout.
    pub const VERSION_V1: u16 = 1;
    /// Construct current untrusted transport in canonical record order.
    #[must_use]
    pub fn new(mut commitments: Vec<DaCommitmentRecord>) -> Self {
        commitments.sort();
        Self::from_untrusted_parts(Self::VERSION_V1, commitments)
    }
    /// Preserve exact untrusted fields without repairing version or record order.
    /// Transport decoding grants no admission or DA signature authorization.
    #[must_use]
    pub fn from_untrusted_parts(version: u16, commitments: Vec<DaCommitmentRecord>) -> Self {
        Self {
            storage: Storage::Untrusted(CanonicalParts {
                version,
                commitments,
            }),
        }
    }
    fn parts(&self) -> &CanonicalParts {
        match &self.storage {
            Storage::Untrusted(parts) => parts,
            Storage::Admitted(parts) => parts.get(),
        }
    }
    /// Exact advertised bundle version; transport decoding does not validate it.
    #[must_use]
    pub fn version(&self) -> u16 {
        self.parts().version
    }
    /// Borrow every original record, tag and signature without mutable extraction.
    /// Explicit record clones and semantic/Merkle scratch create separate untrusted
    /// graphs and are never funded by this original immutable owner.
    #[must_use]
    pub fn commitments(&self) -> &[DaCommitmentRecord] {
        &self.parts().commitments
    }
    /// Whether the control, ledger and all actual children retain this original pool.
    /// This is allocation custody only, never DA or consensus authorization.
    #[must_use]
    pub fn admitted_to(&self, budget: &AllocationBudget) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => false,
            Storage::Admitted(owner) => {
                owner.belongs_to(budget) && RetainedPayload::belongs_to(owner, budget)
            }
        }
    }
    /// Whether two admitted readers keep the identical original immutable owner.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.storage, &right.storage) {
            (Storage::Admitted(left), Storage::Admitted(right)) => {
                ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
    /// Exact physical immutable control, separate from its array, leaves and ledger.
    #[must_use]
    pub fn allocation_layout() -> Layout {
        ChargedShared::<RetainedPayload<CanonicalParts>>::allocation_layout()
    }
    /// Returns `true` if there are no commitments in the bundle.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commitments().is_empty()
    }
    /// Canonical Merkle root over the commitment records in this bundle.
    ///
    /// Leaves and internal nodes use distinct, versioned hash domains. Odd leaves are promoted
    /// unchanged to the next layer instead of being duplicated.
    #[must_use]
    pub fn merkle_root(&self) -> Option<Hash> {
        if self.commitments().is_empty() {
            return None;
        }
        let mut layer: Vec<Hash> = self
            .commitments()
            .iter()
            .map(super::commitment_leaf_hash)
            .collect();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut iter = layer.chunks(2);
            for pair in iter.by_ref() {
                let combined = if pair.len() == 1 {
                    pair[0]
                } else {
                    super::commitment_internal_hash(&pair[0], &pair[1])
                };
                next.push(combined);
            }
            layer = next;
        }
        layer.pop()
    }
    /// Header commitment to the V1 tree shape, leaf count, and Merkle root.
    ///
    /// This commitment can be reconstructed from a logarithmic membership
    /// proof without the complete bundle.
    #[must_use]
    pub fn merkle_commitment(&self) -> Option<HashOf<Self>> {
        let leaf_count = u32::try_from(self.commitments().len()).ok()?;
        let root = self.merkle_root()?;
        Some(super::commitment_merkle_commitment(
            self.version(),
            leaf_count,
            &root,
        ))
    }
}
impl Clone for DaCommitmentBundle {
    fn clone(&self) -> Self {
        Self {
            storage: match &self.storage {
                Storage::Untrusted(parts) => Storage::Untrusted(parts.clone()),
                Storage::Admitted(parts) => Storage::Admitted(parts.clone()),
            },
        }
    }
}
impl fmt::Debug for DaCommitmentBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaCommitmentBundle")
            .field("version", &self.version())
            .field("commitments", &self.commitments())
            .finish()
    }
}
impl PartialEq for DaCommitmentBundle {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}
impl Eq for DaCommitmentBundle {}
impl PartialOrd for DaCommitmentBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DaCommitmentBundle {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parts().cmp(other.parts())
    }
}
impl ncore::SerializePayload for DaCommitmentBundle {
    fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), ncore::Error> {
        ncore::SerializePayload::serialize(self.parts(), encoder)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_hint(self.parts())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_exact(self.parts())
    }
}
impl<'de> ncore::DeserializePayload<'de> for DaCommitmentBundle {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical DA commitment archive")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let parts =
            <CanonicalParts as ncore::DeserializePayload>::try_deserialize(archived.cast())?;
        Ok(Self {
            storage: Storage::Untrusted(parts),
        })
    }
}
impl<D> ncore::DecodeRecordFields<D> for DaCommitmentBundle
where
    D: ncore::FieldDestination
        + ncore::DecodeField<0, u16>
        + ncore::DecodeField<1, Vec<DaCommitmentRecord>>,
{
    type Values = (
        <D as ncore::DecodeField<0, u16>>::Value,
        <D as ncore::DecodeField<1, Vec<DaCommitmentRecord>>>::Value,
    );
    fn decode_fields(
        bytes: &[u8],
        destination: &mut D,
    ) -> Result<(Self::Values, usize), ncore::DecodeIntoError<D::Error>> {
        <CanonicalParts as ncore::DecodeRecordFields<D>>::decode_fields(bytes, destination)
    }
}
impl norito::NoritoSchema for DaCommitmentBundle {
    fn nominal_name() -> String {
        Self::static_frame_name()
            .expect("fixed DA commitment identity")
            .to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_data_model::da::commitment::DaCommitmentBundle")
    }
}
impl TypeId for DaCommitmentBundle {
    fn id() -> String {
        "DaCommitmentBundle".to_owned()
    }
}
impl IntoSchema for DaCommitmentBundle {
    fn type_name() -> String {
        "DaCommitmentBundle".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "version".to_owned(),
                        ty: std::any::TypeId::of::<u16>(),
                    },
                    Declaration {
                        name: "commitments".to_owned(),
                        ty: std::any::TypeId::of::<Vec<DaCommitmentRecord>>(),
                    },
                ],
            }));
            u16::update_schema_map(map);
            Vec::<DaCommitmentRecord>::update_schema_map(map);
        }
    }
}
impl norito::json::FastJsonWrite for DaCommitmentBundle {
    fn json_object_field_order() -> Option<&'static [&'static str]> {
        Some(&["version", "commitments"])
    }
    fn write_json(&self, out: &mut String) {
        norito::json::FastJsonWrite::write_json(self.parts(), out)
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::FastJsonWrite::write_json_to(self.parts(), out)
    }
}
impl norito::json::JsonDeserialize for DaCommitmentBundle {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        Ok(Self {
            storage: Storage::Untrusted(
                <CanonicalParts as norito::json::JsonDeserialize>::json_deserialize(parser)?,
            ),
        })
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        Ok(Self {
            storage: Storage::Untrusted(
                <CanonicalParts as norito::json::JsonDeserialize>::json_from_value(value)?,
            ),
        })
    }
}

impl<'a> ncore::DecodeFromSlice<'a> for DaCommitmentBundle {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let prepared = ncore::prepare_decode_from_slice(
            bytes,
            ncore::archived_payload_size::<CanonicalParts>(),
            ncore::archived_payload_align::<CanonicalParts>(),
        )?;
        let logical_len = prepared.logical_len();
        let _context = ncore::PayloadCtxGuard::enter_with_len(prepared.bytes(), logical_len);
        let parts = <CanonicalParts as ncore::DeserializePayload>::try_deserialize(
            prepared.archived::<CanonicalParts>(),
        )?;
        Ok((
            Self {
                storage: Storage::Untrusted(parts),
            },
            logical_len,
        ))
    }
}
impl Default for DaCommitmentBundle {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
