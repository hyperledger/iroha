//! One-use, exact-owner initialization of native escrow completeness.
use super::*;
use crate::nexus::AxtAssetIncarnationV1;
isi! {
    /// Derive a scope from canonical escrow rows; callers cannot supply a count.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_escrow_scope::InitializeAssetEscrowReadScopeV1")]
    pub struct InitializeAssetEscrowReadScopeV1 {
        /// Exact definition whose current owner authorizes initialization.
        pub asset_definition_id: AssetDefinitionId,
        /// Exact live native incarnation, obtained from authenticated evidence.
        pub expected_incarnation: AxtAssetIncarnationV1,
        /// Must be zero and the native scope must be absent.
        pub expected_revision: u64,
    }
}
impl InitializeAssetEscrowReadScopeV1 {
    /// Stable first-release instruction identity.
    pub const WIRE_ID: &'static str = "iroha.asset.escrow.read_scope.initialize.v1";
}
impl crate::seal::Instruction for InitializeAssetEscrowReadScopeV1 {}
impl<'a> norito::core::DecodeFromSlice<'a> for InitializeAssetEscrowReadScopeV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0;
        let asset_definition_id = super::decode_aos_canonical_field::<AssetDefinitionId>(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let expected_incarnation = super::decode_aos_canonical_field::<AxtAssetIncarnationV1>(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        let expected_revision = super::decode_aos_canonical_field::<u64>(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
        if offset != bytes.len() { return Err(norito::core::Error::LengthMismatch); }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { asset_definition_id, expected_incarnation, expected_revision }, offset))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escrow_scope_initialization_has_exact_registry_and_slice_identity() {
        let value = InitializeAssetEscrowReadScopeV1 {
            asset_definition_id: "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap(),
            expected_incarnation: AxtAssetIncarnationV1::try_from_bytes(*iroha_crypto::Hash::new("scope").as_ref()).unwrap(),
            expected_revision: 0,
        };
        crate::isi::test_support::assert_slice_roundtrip(value.clone());
        crate::isi::test_support::assert_registry_decodes(&crate::isi::registry::default(), InitializeAssetEscrowReadScopeV1::WIRE_ID, value);
    }
}
