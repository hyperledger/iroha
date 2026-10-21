//! Asset-owner enrollment with atomic reconciliation and no implicit exemptions.

use super::*;
use crate::asset::uid_enrollment::AssetUidSystemAccountV1;

isi! {
    /// Permanently require explicit native classification for this asset.
    ///
    /// Every existing positive balance must already belong to a UID, an exact
    /// FI/system registration, or native custody with its enrolled original
    /// payer. Any unresolved balance blocks activation without changing money.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_uid_enrollment::ActivateAssetUidEnrollmentV1")]
    pub struct ActivateAssetUidEnrollmentV1 {
        /// Exact Global asset owned by the transaction authority.
        pub asset_definition_id: AssetDefinitionId,
    }
}

isi! {
    /// Explicitly classify a non-retail system account as the exact asset owner.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_uid_enrollment::SetAssetUidSystemAccountV1")]
    pub struct SetAssetUidSystemAccountV1 {
        /// Complete system record with the next revision.
        pub account: AssetUidSystemAccountV1,
    }
}

macro_rules! enrollment_instruction {
    ($ty:ident, $wire:literal, $field:ident : $field_ty:ty) => {
        impl $ty {
            /// Canonical first-release wire identity.
            pub const WIRE_ID: &'static str = $wire;
        }
        impl crate::seal::Instruction for $ty {}
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = norito::core::effective_decode_flags()
                    .unwrap_or_else(norito::core::default_encode_flags);
                let mut offset = 0usize;
                let $field = super::decode_aos_canonical_field::<$field_ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $field }, offset))
            }
        }
    };
}
enrollment_instruction!(ActivateAssetUidEnrollmentV1, "iroha.asset.uid.enrollment.activate.v1",
    asset_definition_id: AssetDefinitionId);
enrollment_instruction!(SetAssetUidSystemAccountV1, "iroha.asset.uid.system.set.v1",
    account: AssetUidSystemAccountV1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;

    #[test]
    fn explicit_enrollment_preserves_system_identity_revision_and_revocation() {
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("enrollment", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let account_id = AccountId::new(
            KeyPair::try_from_seed(vec![71; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        );
        let activation = ActivateAssetUidEnrollmentV1 {
            asset_definition_id: definition.clone(),
        };
        let system = SetAssetUidSystemAccountV1 {
            account: AssetUidSystemAccountV1 {
                asset_definition_id: definition,
                account_id,
                revision: 3,
                enabled: false,
            },
        };
        assert_slice_roundtrip(activation.clone());
        assert_slice_roundtrip(system.clone());
        let registry = crate::isi::registry::default();
        assert_registry_decodes(&registry, ActivateAssetUidEnrollmentV1::WIRE_ID, activation);
        assert_registry_decodes(
            &registry,
            SetAssetUidSystemAccountV1::WIRE_ID,
            system.clone(),
        );
        assert_eq!(
            norito::json::from_str::<SetAssetUidSystemAccountV1>(
                &norito::json::to_json(&system).unwrap()
            )
            .unwrap(),
            system
        );
    }
}
