//! Explicit asset-owner authority for private contract holdings quotes.

use crate::isi::*;
use crate::smart_contract::ContractAddress;

isi! {
    /// Grant or revoke private beneficial-holdings reads for an exact controller.
    ///
    /// This permission grants neither UID roster access nor wallet debit authority.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_uid::SetAssetUidPolicyReaderV1")]
    pub struct SetAssetUidPolicyReaderV1 {
        /// Exact globally scoped asset.
        pub asset_definition_id: AssetDefinitionId,
        /// Exact contract instance approved by the asset owner.
        pub controller: ContractAddress,
        /// Starts at one and advances exactly once on each owner update.
        pub revision: u64,
        /// Explicit enablement or revocation.
        pub enabled: bool,
    }
}

impl SetAssetUidPolicyReaderV1 {
    /// Canonical first-release instruction wire identity.
    pub const WIRE_ID: &'static str = "iroha.asset.uid.policy.reader.set.v1";
}
impl crate::seal::Instruction for SetAssetUidPolicyReaderV1 {}

impl<'a> norito::core::DecodeFromSlice<'a> for SetAssetUidPolicyReaderV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0;
        let asset_definition_id = crate::isi::decode_aos_canonical_field::<AssetDefinitionId>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let controller = crate::isi::decode_aos_canonical_field::<ContractAddress>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let revision = crate::isi::decode_aos_canonical_field::<u64>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let enabled = crate::isi::decode_aos_canonical_field::<bool>(
            crate::isi::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                asset_definition_id,
                controller,
                revision,
                enabled,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};

    #[test]
    fn uid_reader_grant_preserves_exact_contract_revision_and_revocation() {
        let owner = AccountId::new(
            KeyPair::try_from_seed(vec![61; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let network = crate::NetworkId::from_genesis_hash(
            HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                b"uid-reader-test",
            )),
        );
        let controller = ContractAddress::derive(
            &network,
            &owner,
            71,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("reader", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        for (revision, enabled) in [(1, true), (2, false)] {
            let value = SetAssetUidPolicyReaderV1 {
                asset_definition_id: asset_definition_id.clone(),
                controller: controller.clone(),
                revision,
                enabled,
            };
            let bytes = norito::encode_canonical(&value).unwrap();
            assert_eq!(
                norito::decode_canonical::<SetAssetUidPolicyReaderV1>(&bytes).unwrap(),
                value
            );
            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(
                norito::json::from_str::<SetAssetUidPolicyReaderV1>(&json).unwrap(),
                value
            );
            let boxed: InstructionBox = value.clone().into();
            let bytes = norito::encode_canonical(&boxed).unwrap();
            let decoded: InstructionBox = norito::decode_canonical(&bytes).unwrap();
            assert_eq!(
                decoded.as_any().downcast_ref::<SetAssetUidPolicyReaderV1>(),
                Some(&value)
            );
        }
    }
}
