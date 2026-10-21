//! Owner-authorized, versioned aggregate wallet policy.
use super::*;
use crate::asset::uid::AssetUidPolicyV1;

isi! {
    /// Install or revise one identity's aggregate policy on an existing asset.
    ///
    /// Only the exact asset-definition owner may execute this instruction.
    /// Membership is append-only and accounts cannot move between identities.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::asset_uid::SetAssetUidPolicyV1")]
    pub struct SetAssetUidPolicyV1 {
        /// Complete policy, including the next exact revision.
        pub policy: AssetUidPolicyV1,
    }
}

impl SetAssetUidPolicyV1 {
    /// Stable additive wire identity; existing V1 instructions are unchanged.
    pub const WIRE_ID: &'static str = "iroha.asset.uid.policy.set.v1";
}
impl crate::seal::Instruction for SetAssetUidPolicyV1 {}

impl<'a> norito::core::DecodeFromSlice<'a> for SetAssetUidPolicyV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0;
        let policy = super::decode_aos_canonical_field::<AssetUidPolicyV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { policy }, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::uid::{AssetUidBindingV1, AssetUidDailyWindowV1, AssetUidUsageV1};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use std::collections::BTreeSet;

    #[test]
    fn additive_policy_and_state_roundtrip() {
        let key = KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519).unwrap();
        let account = AccountId::new(key.public_key().clone());
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("uid", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let policy = AssetUidPolicyV1 {
            asset_definition_id: asset.clone(),
            uid: [17; 32],
            revision: 1,
            accounts: BTreeSet::from([account.clone()]),
            holding_limit: Some(100_u32.into()),
            daily_window: AssetUidDailyWindowV1::UtcDay,
            daily_spend_limit: Some(20_u32.into()),
            daily_outgoing_limit: None,
        };
        assert!(policy.validate_shape().is_ok());
        let instruction = SetAssetUidPolicyV1 {
            policy: policy.clone(),
        };
        let bytes = norito::encode_canonical(&instruction).unwrap();
        let decoded: SetAssetUidPolicyV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, instruction);
        let registry = crate::isi::registry::default();
        let boxed: InstructionBox = instruction.clone().into();
        let (wire_id, framed) = super::super::encoded_instruction_pair_payload(&boxed).unwrap();
        assert_eq!(wire_id, SetAssetUidPolicyV1::WIRE_ID);
        assert_eq!(
            registry
                .decode(wire_id, &framed)
                .unwrap()
                .unwrap()
                .as_any()
                .downcast_ref::<SetAssetUidPolicyV1>(),
            Some(&instruction)
        );
        let binding = AssetUidBindingV1 {
            asset_definition_id: asset.clone(),
            account_id: account,
            uid: policy.uid,
        };
        assert_eq!(
            norito::decode_canonical::<AssetUidBindingV1>(
                &norito::encode_canonical(&binding).unwrap()
            )
            .unwrap(),
            binding
        );
        let usage = AssetUidUsageV1 {
            asset_definition_id: asset,
            uid: policy.uid,
            daily_window: policy.daily_window,
            day_start_ms: 86_400_000,
            spend_amount: 7_u32.into(),
            outgoing_amount: 9_u32.into(),
        };
        assert_eq!(
            norito::decode_canonical::<AssetUidUsageV1>(&norito::encode_canonical(&usage).unwrap())
                .unwrap(),
            usage
        );
        let mut invalid = policy;
        invalid.uid = [0; 32];
        assert!(invalid.validate_shape().is_err());
    }
}

#[path = "asset_uid_reader.rs"]
mod reader;
pub use reader::SetAssetUidPolicyReaderV1;
