//! Immutable committed event collection retaining its original allocation custody.
//!
//! Storage has no wire discriminator: both forms use the canonical event Vec codec.
//! Ordinary decoding is untrusted transport; admitted clones share the original graph.

use std::{alloc::Layout, cmp::Ordering, fmt};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, ChargedShared, RetainedPayload, SharedFromChargeError,
};
use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, VecMeta};
use norito::core as ncore;

use super::ContractEmissionV1;

type Payload = RetainedPayload<Vec<ContractEmissionV1>>;

/// Immutable ordered committed emissions and their optional original physical custody.
pub struct ContractEmissionsV1 {
    storage: Storage,
}

enum Storage {
    Untrusted(Vec<ContractEmissionV1>),
    Admitted(ChargedShared<Payload>),
}

/// Move-only original event graph and shell charge retained across admission retries.
///
/// This staging owner grants no execution authority. Admission checks both original
/// pools, and only a successful transition transfers the graph into the shared carrier.
pub struct PreparedContractEmissionsV1 {
    original: Option<(Payload, AllocationCharge)>,
}

impl fmt::Debug for PreparedContractEmissionsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedContractEmissionsV1")
            .field("pending", &self.original.is_some())
            .finish_non_exhaustive()
    }
}

/// Refusal before the original event graph enters a shared carrier owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractEmissionAdmissionErrorV1 {
    /// A successful admission has already transferred the original graph.
    Consumed,
    /// The original payload or control charge belongs to a different finite pool.
    ForeignPool,
    /// The exact original control charge cannot initialize this shared shell.
    Shared(SharedFromChargeError),
}

impl fmt::Display for ContractEmissionAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed => formatter.write_str("event graph has already been admitted"),
            Self::ForeignPool => {
                formatter.write_str("event payload and control must retain the original pool")
            }
            Self::Shared(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for ContractEmissionAdmissionErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Shared(error) => Some(error),
            Self::Consumed | Self::ForeignPool => None,
        }
    }
}

impl PreparedContractEmissionsV1 {
    /// Retain the original funded journal and its existing control charge without allocation.
    #[must_use]
    pub fn new(payload: Payload, control_charge: AllocationCharge) -> Self {
        Self {
            original: Some((payload, control_charge)),
        }
    }

    /// Transfer the original graph into its shared carrier without copying any payload.
    ///
    /// No capacity is acquired, refunded or replaced by this transition. Every refusal
    /// keeps both inputs in this owner so the caller can retry without reconstructing custody.
    ///
    /// # Errors
    /// Rejects a consumed owner, foreign pool, wrong shell layout or allocator refusal.
    pub fn try_admit(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<ContractEmissionsV1, ContractEmissionAdmissionErrorV1> {
        let (payload, control_charge) = self
            .original
            .as_ref()
            .ok_or(ContractEmissionAdmissionErrorV1::Consumed)?;
        if !payload.belongs_to(budget) || !control_charge.belongs_to(budget) {
            return Err(ContractEmissionAdmissionErrorV1::ForeignPool);
        }
        let (payload, control_charge) = self.original.take().expect("original checked above");
        let shell = match ChargedShared::<Payload>::reserve_from_charge(control_charge) {
            Ok(shell) => shell,
            Err((charge, error)) => {
                self.original = Some((payload, charge));
                return Err(ContractEmissionAdmissionErrorV1::Shared(error));
            }
        };
        Ok(ContractEmissionsV1 {
            storage: Storage::Admitted(shell.initialize(payload)),
        })
    }
}

impl ContractEmissionsV1 {
    /// Construct untrusted transport without granting execution or allocation authority.
    #[must_use]
    pub fn from_untrusted(values: Vec<ContractEmissionV1>) -> Self {
        Self {
            storage: Storage::Untrusted(values),
        }
    }

    /// Exact shared shell layout, separate from original payload and ledger allocations.
    #[must_use]
    pub fn allocation_layout() -> Layout {
        ChargedShared::<Payload>::allocation_layout()
    }

    /// Borrow the original ordered emissions without mutable or owned extraction.
    #[must_use]
    pub fn as_slice(&self) -> &[ContractEmissionV1] {
        self.values().as_slice()
    }
    fn values(&self) -> &Vec<ContractEmissionV1> {
        match &self.storage {
            Storage::Untrusted(values) => values,
            Storage::Admitted(owner) => owner.get(),
        }
    }
    /// Iterate the exact original records in execution order.
    pub fn iter(&self) -> std::slice::Iter<'_, ContractEmissionV1> {
        self.as_slice().iter()
    }
    /// Number of committed emissions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    /// Whether this invocation emitted no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
    /// Whether all original payload, ledger and shared-control charges retain this pool.
    #[must_use]
    pub fn admitted_to(&self, budget: &AllocationBudget) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => false,
            Storage::Admitted(owner) => {
                owner.belongs_to(budget) && RetainedPayload::belongs_to(owner, budget)
            }
        }
    }
    /// Whether two admitted collections share the same original physical graph.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.storage, &right.storage) {
            (Storage::Admitted(left), Storage::Admitted(right)) => {
                ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
}
impl<'a> IntoIterator for &'a ContractEmissionsV1 {
    type Item = &'a ContractEmissionV1;
    type IntoIter = std::slice::Iter<'a, ContractEmissionV1>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl Default for ContractEmissionsV1 {
    fn default() -> Self {
        Self::from_untrusted(Vec::new())
    }
}
impl Clone for ContractEmissionsV1 {
    fn clone(&self) -> Self {
        Self {
            storage: match &self.storage {
                Storage::Untrusted(values) => Storage::Untrusted(values.clone()),
                Storage::Admitted(owner) => Storage::Admitted(owner.clone()),
            },
        }
    }
}
impl fmt::Debug for ContractEmissionsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}
impl PartialEq for ContractEmissionsV1 {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for ContractEmissionsV1 {}
impl PartialOrd for ContractEmissionsV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ContractEmissionsV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
impl ncore::SerializePayload for ContractEmissionsV1 {
    fn serialize(&self, encoder: &mut ncore::Encoder<'_>) -> Result<(), norito::Error> {
        ncore::SerializePayload::serialize(self.values(), encoder)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_hint(self.values())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        ncore::SerializePayload::encoded_len_exact(self.values())
    }
}
impl<'de> ncore::DeserializePayload<'de> for ContractEmissionsV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical contract emission collection")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, norito::Error> {
        <Vec<ContractEmissionV1> as ncore::DeserializePayload>::try_deserialize(archived.cast())
            .map(Self::from_untrusted)
    }
}
impl<'de> ncore::DecodeFromSlice<'de> for ContractEmissionsV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let (values, used) = ncore::decode_vec_from_slice_serial::<ContractEmissionV1>(bytes)?;
        Ok((Self::from_untrusted(values), used))
    }
}
impl norito::NoritoSchema for ContractEmissionsV1 {
    fn nominal_name() -> String {
        "iroha_data_model::smart_contract::event::ContractEmissionsV1".into()
    }
    fn frame_name() -> String {
        <Vec<ContractEmissionV1> as norito::NoritoSchema>::frame_name()
    }
}
impl TypeId for ContractEmissionsV1 {
    fn id() -> String {
        "ContractEmissionsV1".into()
    }
}
impl IntoSchema for ContractEmissionsV1 {
    fn type_name() -> String {
        "ContractEmissionsV1".into()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: std::any::TypeId::of::<ContractEmissionV1>(),
            }));
            ContractEmissionV1::update_schema_map(map);
        }
    }
}
impl norito::json::JsonSerialize for ContractEmissionsV1 {
    fn json_serialize(&self, output: &mut String) {
        norito::json::JsonSerialize::json_serialize(self.values(), output);
    }
    fn json_serialize_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(self.values(), output)
    }
}
impl norito::json::JsonDeserialize for ContractEmissionsV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        <Vec<ContractEmissionV1> as norito::json::JsonDeserialize>::json_deserialize(parser)
            .map(Self::from_untrusted)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        <Vec<ContractEmissionV1> as norito::json::JsonDeserialize>::json_from_value(value)
            .map(Self::from_untrusted)
    }
}
impl<'a> norito::json::FastFromJson<'a> for ContractEmissionsV1 {
    fn parse(
        walker: &mut norito::json::TapeWalker<'a>,
        _arena: &mut norito::json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let input = walker.input();
        let mut parser = norito::json::Parser::new_at(input, walker.raw_pos());
        let value = <Self as norito::json::JsonDeserialize>::json_deserialize(&mut parser)
            .map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::ChargedBuffer;

    #[allow(unsafe_code)]
    fn funded_empty_with_backing(budget: &AllocationBudget) -> Payload {
        let values = ChargedBuffer::<ContractEmissionV1>::new(1, budget).unwrap();
        let mut ledger = ChargedBuffer::new(1, budget).unwrap();
        // SAFETY: the original empty Vec still owns its exact capacity allocation.
        // Its sole charge follows that same allocation into the retained payload.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        ledger.push_reserved(charge);
        unsafe { RetainedPayload::try_new(values, ledger, budget) }.unwrap_or_else(
            |_original_owners| panic!("original funded payload belongs to its pool"),
        )
    }
    fn control(budget: &AllocationBudget, layout: Layout) -> AllocationCharge {
        let mut reservation = budget.try_reserve(layout).unwrap();
        reservation.try_split(layout).unwrap()
    }
    fn sample() -> ContractEmissionV1 {
        use crate::smart_contract::{ContractAddress, entrypoint::*};
        use iroha_crypto::{Hash, HashOf, KeyPair};
        let caller =
            crate::account::AccountId::new(KeyPair::try_random().unwrap().public_key().clone());
        let network = crate::id::NetworkId::from_genesis_hash(
            HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                b"event custody test network",
            )),
        );
        let contract = ContractAddress::derive(
            &network,
            &caller,
            1,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let payload_type = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Struct(
                EntrypointStructTypeNodeV1 {
                    name: "Fixture::Accepted".into(),
                    fields: vec![],
                },
            )],
        };
        ContractEmissionV1 {
            contract,
            caller,
            code_hash: Hash::new(b"event custody code"),
            entrypoint: 0,
            event: 0,
            payload: EntrypointReturnRecordV1 {
                schema_hash: entrypoint_return_schema_hash_v1(&norito::codec::Encode::encode(
                    &payload_type,
                )),
                atoms: vec![],
            },
            definition: super::super::ContractEventDescriptorV1 {
                name: "Accepted".parse().unwrap(),
                payload_type,
            },
        }
    }

    #[test]
    fn admitted_clones_keep_original_graph_and_credit_through_last_reader() {
        let budget = AllocationBudget::new(64 * 1024);
        let payload = funded_empty_with_backing(&budget);
        let pointer = payload.get().as_ptr();
        let charge = control(&budget, ContractEmissionsV1::allocation_layout());
        let before = budget.reserved_bytes();
        let mut prepared = PreparedContractEmissionsV1::new(payload, charge);
        assert!(format!("{prepared:?}").contains("pending: true"));
        let admitted = prepared
            .try_admit(&budget)
            .expect("original event source must admit");
        assert!(admitted.admitted_to(&budget));
        let reader = admitted.clone();
        assert!(ContractEmissionsV1::ptr_eq(&admitted, &reader));
        assert_eq!(reader.as_slice().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), before);
        assert!(reader.is_empty());
        assert_eq!(reader.len(), 0);
        assert_eq!(reader.iter().count(), 0);
        assert_eq!(
            prepared.try_admit(&budget).unwrap_err(),
            ContractEmissionAdmissionErrorV1::Consumed
        );
        assert!(format!("{prepared:?}").contains("pending: false"));
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), before);
        drop(admitted);
        assert_eq!(budget.reserved_bytes(), before);
        drop(reader);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn rejected_admission_retains_unchanged_original_owners_without_refund() {
        let original = AllocationBudget::new(64 * 1024);
        let foreign = AllocationBudget::new(64 * 1024);
        let payload = funded_empty_with_backing(&original);
        let pointer = payload.get().as_ptr();
        let charge = control(&original, ContractEmissionsV1::allocation_layout());
        let before = original.reserved_bytes();
        let mut prepared = PreparedContractEmissionsV1::new(payload, charge);
        let error = prepared.try_admit(&foreign).unwrap_err();
        assert_eq!(error, ContractEmissionAdmissionErrorV1::ForeignPool);
        let (payload, charge) = prepared.original.as_ref().unwrap();
        assert_eq!(payload.get().as_ptr(), pointer);
        assert!(payload.belongs_to(&original));
        assert!(charge.belongs_to(&original));
        assert_eq!(original.reserved_bytes(), before);
        assert_eq!(foreign.reserved_bytes(), 0);
        let admitted = prepared
            .try_admit(&original)
            .expect("retry preserves original source");
        drop(admitted);
        assert_eq!(original.reserved_bytes(), 0);

        let payload = funded_empty_with_backing(&original);
        let pointer = payload.get().as_ptr();
        let charge = control(&original, Layout::new::<u8>());
        let before = original.reserved_bytes();
        let mut prepared = PreparedContractEmissionsV1::new(payload, charge);
        for _ in 0..2 {
            let error = prepared.try_admit(&original).unwrap_err();
            assert_eq!(
                error,
                ContractEmissionAdmissionErrorV1::Shared(SharedFromChargeError::LayoutMismatch {
                    expected: ContractEmissionsV1::allocation_layout(),
                    actual: Layout::new::<u8>(),
                })
            );
            let ContractEmissionAdmissionErrorV1::Shared(cause) = &error else {
                unreachable!()
            };
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<SharedFromChargeError>()
                .unwrap();
            assert!(std::ptr::eq(cause, source));
            let (payload, charge) = prepared.original.as_ref().unwrap();
            assert_eq!(payload.get().as_ptr(), pointer);
            assert!(payload.belongs_to(&original));
            assert!(charge.belongs_to(&original));
            assert_eq!(original.reserved_bytes(), before);
        }
        assert_eq!(original.reserved_bytes(), before);
        drop(prepared);
        assert_eq!(original.reserved_bytes(), 0);
    }

    #[test]
    fn prepared_admission_rejects_foreign_control_without_changing_either_pool() {
        let original = AllocationBudget::new(64 * 1024);
        let foreign = AllocationBudget::new(64 * 1024);
        let payload = funded_empty_with_backing(&original);
        let pointer = payload.get().as_ptr();
        let charge = control(&foreign, ContractEmissionsV1::allocation_layout());
        let before = (original.reserved_bytes(), foreign.reserved_bytes());
        let mut prepared = PreparedContractEmissionsV1::new(payload, charge);
        for pool in [&original, &foreign] {
            let error = prepared.try_admit(pool).unwrap_err();
            assert_eq!(error, ContractEmissionAdmissionErrorV1::ForeignPool);
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(
                prepared.original.as_ref().unwrap().0.get().as_ptr(),
                pointer
            );
            assert_eq!(
                (original.reserved_bytes(), foreign.reserved_bytes()),
                before
            );
        }
        drop(prepared);
        assert_eq!(
            (original.reserved_bytes(), foreign.reserved_bytes()),
            (0, 0)
        );
    }

    #[test]
    fn collection_has_one_vector_wire_and_json_layout_and_transport_stays_untrusted() {
        let values = vec![sample()];
        let collection = ContractEmissionsV1::from_untrusted(values.clone());
        assert_eq!(collection.len(), 1);
        assert_eq!(collection.iter().next(), values.first());
        let borrowed = (&collection).into_iter().next().unwrap();
        assert!(std::ptr::eq(borrowed, &raw const collection.as_slice()[0]));
        assert_eq!((&collection).into_iter().count(), collection.len());
        let bytes = norito::encode_canonical(&values).unwrap();
        assert_eq!(norito::encode_canonical(&collection).unwrap(), bytes);
        let decoded = norito::decode_canonical::<ContractEmissionsV1>(&bytes).unwrap();
        assert_eq!(decoded, collection);
        let json = norito::json::to_json(&values).unwrap();
        assert_eq!(norito::json::to_json(&collection).unwrap(), json);
        assert_eq!(
            norito::json::from_str::<ContractEmissionsV1>(&json).unwrap(),
            collection
        );
        let budget = AllocationBudget::new(64 * 1024);
        assert!(!decoded.admitted_to(&budget));
        assert!(!ContractEmissionsV1::ptr_eq(
            &collection,
            &collection.clone()
        ));
        assert_eq!(collection.clone(), collection);
        assert!(ContractEmissionsV1::default() < collection);
        assert!(format!("{collection:?}").contains("Accepted"));
    }
}
