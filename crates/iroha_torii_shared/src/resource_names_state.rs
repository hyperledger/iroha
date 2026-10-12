//! Complete canonical alias and SNS originals for an authorized ledger-wide reader.
//!
//! This versioned data carrier grants no read, finality, or release authority.
//! The native signed-request publisher enforces existing ledger read permission;
//! consumers still independently verify the challenged certified World cut.

use iroha_data_model::{
    asset::AssetDefinitionId,
    sumeragi_finality::{SumeragiFinalityAttestation, WorldStateSnapshotV1},
};
use iroha_model_base::state_path::StatePath;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};

/// Reader ceiling for complete hashes, native proofs and canonical name originals.
pub const NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1: usize = 128 * 1024 * 1024;
/// Exact route prefix; the final component is one nonzero lowercase 32-byte challenge.
pub const NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1: &str = "/v1/ledger/resource-names/";

/// Original canonical asset-definition binding record, independent of materialized aliases.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(
    name = "iroha_torii_shared::resource_names_state::NativeAssetAliasBindingOriginalV1"
)]
pub struct NativeAssetAliasBindingOriginalV1 {
    /// Exact canonical definition key.
    pub definition_id: AssetDefinitionId,
    /// Bounded canonical frame of the native Core binding record.
    pub binding_record_wire: Vec<u8>,
}

/// Actual dataspace SNS value under its native smart-contract `StatePath`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_torii_shared::resource_names_state::NativeDataspaceSnsOriginalV1")]
pub struct NativeDataspaceSnsOriginalV1 {
    /// Original canonical state key.
    pub storage_key: StatePath,
    /// Original native stored bytes; consumers decode exact `NameRecordV1` semantics.
    pub raw_value: Vec<u8>,
}

/// Complete fixed-field originals at one challenged native certified cut.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(
    name = "iroha_torii_shared::resource_names_state::NativeResourceNamesStateV1",
    frame = "iroha.torii.v1.ledger.resource-names.response"
)]
pub struct NativeResourceNamesStateV1 {
    /// Native installed node's current challenged attestation for this exact cut.
    pub attestation: SumeragiFinalityAttestation,
    /// Every canonical World element at the original certified pre-tail cut.
    pub world_snapshot: WorldStateSnapshotV1,
    /// Every canonical asset-definition alias binding and its original value.
    pub asset_alias_bindings: Vec<NativeAssetAliasBindingOriginalV1>,
    /// Every smart-contract key; unrelated smart-contract values are withheld.
    pub smart_contract_keys: Vec<StatePath>,
    /// Every dataspace SNS original value selected from the complete keyset.
    pub dataspace_names: Vec<NativeDataspaceSnsOriginalV1>,
}

/// Decode only bounded exact canonical data; authentication remains the consumer's job.
///
/// # Errors
/// Empty, oversized, malformed or noncanonical native carrier.
pub fn decode_unverified_native_resource_names_state_v1(
    bytes: &[u8],
) -> Result<NativeResourceNamesStateV1, norito::Error> {
    if bytes.is_empty() || bytes.len() > NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1 {
        return Err(norito::Error::Message(
            "native resource names state exceeds reader bound".into(),
        ));
    }
    norito::decode_canonical_with_limits(
        bytes,
        norito::canonical_decode_limits(NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1),
    )
}

/// Borrowed canonical binding wire without a replacement owned allocation.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeAssetAliasBindingOriginalRefV1<'a> {
    definition_id: FieldRef<'a, AssetDefinitionId>,
    binding_record_wire: ByteRef<'a>,
}
impl<'a> NativeAssetAliasBindingOriginalRefV1<'a> {
    /// Borrow an exact native key and already funded canonical binding bytes.
    #[must_use]
    pub fn new(definition_id: &'a AssetDefinitionId, binding_record_wire: &'a [u8]) -> Self {
        Self {
            definition_id: FieldRef(definition_id),
            binding_record_wire: ByteRef(binding_record_wire),
        }
    }
}

/// Borrowed SNS original, withholding unrelated smart-contract values.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeDataspaceSnsOriginalRefV1<'a> {
    storage_key: FieldRef<'a, StatePath>,
    raw_value: ByteRef<'a>,
}
impl<'a> NativeDataspaceSnsOriginalRefV1<'a> {
    /// Borrow the native `StatePath` and exact raw value.
    #[must_use]
    pub fn new(storage_key: &'a StatePath, raw_value: &'a [u8]) -> Self {
        Self {
            storage_key: FieldRef(storage_key),
            raw_value: ByteRef(raw_value),
        }
    }
}

/// Exact borrowed encoder of the owned carrier's sole canonical layout.
#[derive(NoritoSerialize, JsonSerialize)]
pub struct NativeResourceNamesStateRefV1<'a> {
    attestation: FieldRef<'a, SumeragiFinalityAttestation>,
    world_snapshot: FieldRef<'a, WorldStateSnapshotV1>,
    asset_alias_bindings: SequenceRef<'a, NativeAssetAliasBindingOriginalRefV1<'a>>,
    smart_contract_keys: KeySequenceRef<'a>,
    dataspace_names: SequenceRef<'a, NativeDataspaceSnsOriginalRefV1<'a>>,
}
impl<'a> NativeResourceNamesStateRefV1<'a> {
    /// Borrow all original buffers; no resource, release or monetary authority is selected.
    #[must_use]
    pub fn new(
        attestation: &'a SumeragiFinalityAttestation,
        world_snapshot: &'a WorldStateSnapshotV1,
        asset_alias_bindings: &'a [NativeAssetAliasBindingOriginalRefV1<'a>],
        smart_contract_keys: &'a [&'a StatePath],
        dataspace_names: &'a [NativeDataspaceSnsOriginalRefV1<'a>],
    ) -> Self {
        Self {
            attestation: FieldRef(attestation),
            world_snapshot: FieldRef(world_snapshot),
            asset_alias_bindings: SequenceRef(asset_alias_bindings),
            smart_contract_keys: KeySequenceRef(smart_contract_keys),
            dataspace_names: SequenceRef(dataspace_names),
        }
    }
}
impl norito::NoritoSchema for NativeResourceNamesStateRefV1<'_> {
    fn nominal_name() -> String {
        NativeResourceNamesStateV1::nominal_name()
    }
    fn frame_name() -> String {
        NativeResourceNamesStateV1::frame_name()
    }
}
struct FieldRef<'a, T: ?Sized>(&'a T);
impl<T: norito::core::SerializePayload + ?Sized> norito::core::SerializePayload
    for FieldRef<'_, T>
{
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}
impl<T: norito::json::JsonSerialize + ?Sized> norito::json::JsonSerialize for FieldRef<'_, T> {
    fn json_serialize(&self, out: &mut String) {
        self.0.json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.0.json_serialize_to(out)
    }
}

// All borrowed sequences forward the codec's sole canonical element-sequence
// owner. They never collect a replacement Vec or guess active Norito flags.
struct SequenceRef<'a, T>(&'a [T]);
impl<T: norito::core::SerializePayload> norito::core::SerializePayload for SequenceRef<'_, T> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<T, _>(out, self.0.iter())
    }
}
impl<T: norito::json::JsonSerialize> norito::json::JsonSerialize for SequenceRef<'_, T> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, value) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, value) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}
struct ByteRef<'a>(&'a [u8]);
impl norito::core::SerializePayload for ByteRef<'_> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::SerializePayload::serialize(&self.0, out)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.len().checked_add(8)
    }
}
impl norito::json::JsonSerialize for ByteRef<'_> {
    fn json_serialize(&self, out: &mut String) {
        SequenceRef(self.0).json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        SequenceRef(self.0).json_serialize_to(out)
    }
}
struct KeySequenceRef<'a>(&'a [&'a StatePath]);
impl norito::core::SerializePayload for KeySequenceRef<'_> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::core::write_element_sequence::<StatePath, _>(out, self.0.iter().copied())
    }
}
impl norito::json::JsonSerialize for KeySequenceRef<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, value) in self.0.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            value.json_serialize(out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('[')?;
            for (index, value) in self.0.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                value.json_serialize_to(out)?;
            }
            out.push(']')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "resource_names_state/tests.rs"]
mod tests;

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{RefusingLeaf, audit, byte_refusal, error};
    use norito::json::{BoundedJsonError, JsonSerialize};

    #[test]
    fn original_resource_sequence_keeps_non_fast_manual_leaf_and_refusal_depth() {
        let values = [1_u64, 7];
        let source = SequenceRef(&values);
        audit("[1,7]", |sink| source.json_serialize_to(sink));
        assert_eq!(source.0.as_ptr(), values.as_ptr());
        let values = [RefusingLeaf {
            visits: std::cell::Cell::new(0),
        }];
        let source = SequenceRef(&values);
        byte_refusal(|sink| source.json_serialize_to(sink));
        assert_eq!(values[0].visits.get(), 0);
        error(BoundedJsonError::Unsupported, |sink| {
            source.json_serialize_to(sink)
        });
        assert_eq!(values[0].visits.get(), 1);
    }
    #[test]
    fn original_resource_key_sequence_keeps_actual_state_paths_and_refusal_depth() {
        let keys = [
            "sns/records/4099/is2".parse::<StatePath>().unwrap(),
            "private/customer-name".parse().unwrap(),
        ];
        let refs = [&keys[0], &keys[1]];
        let source = KeySequenceRef(&refs);
        let mut expected = String::new();
        source.json_serialize(&mut expected);
        audit(&expected, |sink| source.json_serialize_to(sink));
        assert!(std::ptr::eq(source.0[0], &raw const keys[0]));
    }
}
