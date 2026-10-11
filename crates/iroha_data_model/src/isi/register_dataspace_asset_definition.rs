//! Direct-dataspace asset registration without changing existing registration payloads.

use super::*;
use iroha_model_base::{error::ParseError, topology::DataSpaceId};

isi! {
    /// Register an asset definition directly under an explicit dataspace namespace.
    ///
    /// The ledger atomically registers `object` and its immutable direct-dataspace home after
    /// checking the current SNS dataspace owner's authority. The existing definition payload
    /// remains unchanged; its `owning_domain` must be absent. An alias is an optional label and
    /// does not supply registration authority or determine the home.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::register_dataspace_asset_definition::RegisterDataspaceAssetDefinition")]
    pub struct RegisterDataspaceAssetDefinition {
        /// Exact immutable dataspace home, supplied independently from any alias or balance bucket.
        pub dataspace_id: DataSpaceId,
        /// Existing asset-definition registration payload, with no owning domain.
        pub object: NewAssetDefinition,
    }
}

impl RegisterDataspaceAssetDefinition {
    /// Stable native instruction wire identifier.
    pub const WIRE_ID: &'static str = "iroha.asset_definition.dataspace.register.v1";

    /// Construct an explicit direct-dataspace registration without changing the definition.
    ///
    /// Both balance partition policies are retained. The executor separately checks namespace
    /// authority, dataspace existence and visibility, and all ordinary registration rules.
    ///
    /// # Errors
    /// Returns an error when `object` already claims an owning domain or `dataspace_id` is the
    /// reserved universal dataspace.
    pub fn new(dataspace_id: DataSpaceId, object: NewAssetDefinition) -> Result<Self, ParseError> {
        let instruction = Self {
            dataspace_id,
            object,
        };
        instruction.validate()?;
        Ok(instruction)
    }

    /// Check that the payload specifies exactly the direct home selected by this instruction.
    ///
    /// Execution must call this for decoded instructions as well as constructor-built values.
    /// This check does not establish the caller's on-chain authority.
    ///
    /// # Errors
    /// Returns an error when the definition also claims an owning domain or the selected
    /// dataspace is the reserved universal dataspace.
    pub fn validate(&self) -> Result<(), ParseError> {
        if self.dataspace_id == DataSpaceId::UNIVERSAL {
            return Err(ParseError::new(
                "direct-dataspace asset registration requires a non-universal dataspace",
            ));
        }
        if self.object.owning_domain.is_some() {
            return Err(ParseError::new(
                "direct-dataspace asset registration cannot specify an owning domain",
            ));
        }
        Ok(())
    }
}

impl crate::seal::Instruction for RegisterDataspaceAssetDefinition {}

impl_aos_decode_from_slice!(RegisterDataspaceAssetDefinition {
    dataspace_id: DataSpaceId,
    object: NewAssetDefinition,
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::AssetBalancePolicy;
    use iroha_model_base::domain::DomainId;
    use norito::core::DecodeFromSlice;

    fn definition(policy: AssetBalancePolicy) -> NewAssetDefinition {
        let id = AssetDefinitionId::from_uuid_bytes([
            0x91, 0x21, 0x63, 0x05, 0x0a, 0xb8, 0x46, 0x22, 0xab, 0x0d, 0x09, 0x0c, 0x31, 0x41,
            0x51, 0x61,
        ])
        .expect("public synthetic UUIDv4");
        AssetDefinition::numeric(id, "Native unit", policy, None)
    }

    #[test]
    fn constructor_preserves_policy_definition_bytes_and_full_width_dataspace() {
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            let object = definition(policy);
            let original = norito::encode_canonical(&object).expect("encode original definition");
            let instruction =
                RegisterDataspaceAssetDefinition::new(DataSpaceId::new(u64::MAX), object)
                    .expect("explicit direct home");
            assert_eq!(instruction.dataspace_id.as_u64(), u64::MAX);
            assert_eq!(instruction.object.balance_scope_policy, policy);
            assert_eq!(
                norito::encode_canonical(&instruction.object).expect("encode nested definition"),
                original
            );
            assert!(instruction.validate().is_ok());
        }
    }

    #[test]
    fn constructor_and_executor_validation_reject_conflicting_domain() {
        let object = definition(AssetBalancePolicy::DataspaceRestricted)
            .with_owning_domain(Some(DomainId::try_new("issuer", "public").expect("domain")));
        assert!(
            RegisterDataspaceAssetDefinition::new(DataSpaceId::new(42), object.clone()).is_err()
        );
        assert!(
            RegisterDataspaceAssetDefinition {
                dataspace_id: DataSpaceId::new(42),
                object
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn direct_registration_rejects_universal_without_changing_global_registration() {
        let object = definition(AssetBalancePolicy::Global);
        assert!(
            RegisterDataspaceAssetDefinition::new(DataSpaceId::UNIVERSAL, object.clone()).is_err()
        );
        assert!(
            RegisterDataspaceAssetDefinition {
                dataspace_id: DataSpaceId::UNIVERSAL,
                object: object.clone(),
            }
            .validate()
            .is_err()
        );
        let ordinary = Register::asset_definition(object.clone());
        assert_eq!(ordinary.object, object);
    }

    #[test]
    fn direct_registration_has_distinct_native_registry_and_lossless_roundtrip() {
        let instruction = RegisterDataspaceAssetDefinition::new(
            DataSpaceId::new(u64::MAX),
            definition(AssetBalancePolicy::DataspaceRestricted),
        )
        .expect("direct registration");
        let registry = crate::instruction_registry::default();
        assert!(registry.contains(RegisterDataspaceAssetDefinition::WIRE_ID));
        assert_ne!(
            RegisterDataspaceAssetDefinition::WIRE_ID,
            RegisterBox::WIRE_ID
        );
        let bare = instruction.encode();
        let (decoded, consumed) = RegisterDataspaceAssetDefinition::decode_from_slice(&bare)
            .expect("decode exact mandatory fields");
        assert_eq!(decoded, instruction);
        assert_eq!(consumed, bare.len());
        let boxed = InstructionBox::from(instruction.clone());
        let bytes = norito::encode_canonical(&boxed).expect("encode native instruction");
        assert_eq!(
            norito::decode_canonical::<InstructionBox>(&bytes).expect("decode native instruction"),
            boxed
        );
        let json = norito::json::to_json(&instruction).expect("serialize instruction");
        assert_eq!(
            norito::json::from_json::<RegisterDataspaceAssetDefinition>(&json)
                .expect("deserialize instruction"),
            instruction
        );
    }

    #[test]
    fn direct_registration_requires_both_fields_and_rejects_unknown_json_fields() {
        let instruction = RegisterDataspaceAssetDefinition::new(
            DataSpaceId::new(42),
            definition(AssetBalancePolicy::DataspaceRestricted),
        )
        .expect("direct registration");
        let json = norito::json::to_json(&instruction).expect("serialize instruction");
        let object = norito::json::to_json(&instruction.object).expect("serialize object");
        for invalid in [
            format!("{{\"object\":{object}}}"),
            "{\"dataspace_id\":42}".to_owned(),
            json.replacen('{', "{\"owning_dataspace\":43,", 1),
        ] {
            assert!(norito::json::from_json::<RegisterDataspaceAssetDefinition>(&invalid).is_err());
        }
        let mut bytes = instruction.encode();
        bytes.push(0);
        assert!(RegisterDataspaceAssetDefinition::decode_from_slice(&bytes).is_err());
        assert!(RegisterDataspaceAssetDefinition::decode_from_slice(&[]).is_err());
    }
}
