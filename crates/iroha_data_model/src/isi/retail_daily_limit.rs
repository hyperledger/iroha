//! One-shot, owner-authorized retail asset activation and issuer-signed identity binding.
use super::*;
use crate::asset::{
    AssetDefinitionId, NewAssetDefinition, RetailDailyLimitPolicyV1, RetailIdentityAttestationV1,
    RetailMonetaryPurposeV1,
};
use iroha_primitives::numeric::Quantity;

isi! {
    /// Register a fresh restricted asset definition and activate its immutable
    /// first-release retail DAY policy in the same state transaction.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::retail_daily_limit::ActivateRetailDailyLimitV1")]
    pub struct ActivateRetailDailyLimitV1 {
        /// Definition registered atomically by this instruction. Release admission
        /// must also prove that this ID has no earlier finalized value history.
        pub definition: NewAssetDefinition,
        /// Exact owner-selected asset, physical dataspace, cap and issuer trust.
        pub policy: RetailDailyLimitPolicyV1,
    }
}

isi! {
    /// Retain one exact issuer-signed account-to-person commitment under the
    /// active policy. Existing bindings cannot be replaced in this release.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::retail_daily_limit::BindRetailIdentityV1")]
    pub struct BindRetailIdentityV1 {
        /// Complete issuer-signed binding to verify and store canonically.
        pub attestation: RetailIdentityAttestationV1,
    }
}

isi! {
    /// Execute one policy-bound monetary purpose. A bank operation digest is
    /// only a linkage value; it does not authenticate a bank receipt.
    #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1")]
    pub struct RetailMonetaryMovementV1 {
        /// Exact activated definition.
        pub asset_definition_id: AssetDefinitionId,
        /// One closed monetary effect and direction.
        pub purpose: RetailMonetaryPurposeV1,
        /// Exact retail endpoint for credit or defund; absent for supply effects.
        pub retail_account: Option<AccountId>,
        /// Positive amount in the definition's numeric precision.
        pub amount: Quantity,
        /// Nonzero one-use operation binding. Core separately authenticates any
        /// corresponding bank receipt and finalized ledger execution.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub operation_digest: [u8; 32],
    }
}

impl ActivateRetailDailyLimitV1 {
    /// Stable wire identifier for one-shot activation.
    pub const WIRE_ID: &'static str = "iroha.asset.retail_day.activate.v1";
}
impl BindRetailIdentityV1 {
    /// Stable wire identifier for signed identity enrollment.
    pub const WIRE_ID: &'static str = "iroha.asset.retail_day.identity.bind.v1";
}
impl RetailMonetaryMovementV1 {
    /// Stable wire identifier for exact monetary effects.
    pub const WIRE_ID: &'static str = "iroha.asset.retail_day.monetary_movement.v1";
}
impl crate::seal::Instruction for ActivateRetailDailyLimitV1 {}
impl crate::seal::Instruction for BindRetailIdentityV1 {}
impl crate::seal::Instruction for RetailMonetaryMovementV1 {}

impl<'a> norito::core::DecodeFromSlice<'a> for ActivateRetailDailyLimitV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let definition = super::decode_aos_canonical_field::<NewAssetDefinition>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let policy = super::decode_aos_canonical_field::<RetailDailyLimitPolicyV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { definition, policy }, offset))
    }
}

impl<'a> norito::core::DecodeFromSlice<'a> for BindRetailIdentityV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let attestation = super::decode_aos_canonical_field::<RetailIdentityAttestationV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { attestation }, offset))
    }
}

impl<'a> norito::core::DecodeFromSlice<'a> for RetailMonetaryMovementV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let asset_definition_id = super::decode_aos_canonical_field::<AssetDefinitionId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let purpose = super::decode_aos_canonical_field::<RetailMonetaryPurposeV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let retail_account = super::decode_aos_canonical_field::<Option<AccountId>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let amount = super::decode_aos_canonical_field::<Quantity>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let operation_digest = super::decode_aos_byte_array_field::<32>(bytes, &mut offset, flags)?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                asset_definition_id,
                purpose,
                retail_account,
                amount,
                operation_digest,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::AccountId,
        asset::{
            AssetBalancePolicy, AssetDefinition, AssetDefinitionId,
            RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1, RetailIdentityAttestationBodyV1,
            RetailIdentityCommitmentV1,
        },
        isi::test_support::{assert_registry_decodes, assert_slice_roundtrip},
    };
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_primitives::numeric::{NumericSpec, Quantity};
    use std::collections::BTreeSet;

    #[test]
    fn activation_and_binding_have_exact_canonical_instruction_frames() {
        let key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
            .expect("test-only retail key");
        let issuer = AccountId::new(key.public_key().clone());
        let reserve_key = KeyPair::try_from_seed(vec![0x74; 32], Algorithm::Ed25519)
            .expect("test-only reserve key");
        let domain = DomainId::try_new("retail", "bpng").expect("test domain");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain.clone(),
            "kina".parse().expect("asset name"),
        );
        let policy = RetailDailyLimitPolicyV1 {
            asset_definition_id: definition_id.clone(),
            physical_dataspace: DataSpaceId::new(7),
            revision: 1,
            daily_cap: Quantity::from(5_u32),
            identity_issuer: issuer.clone(),
            identity_issuer_public_key: key.public_key().clone(),
            monetary_issuer_account: issuer.clone(),
            reserve_account: AccountId::new(reserve_key.public_key().clone()),
            institutional_exceptions: BTreeSet::new(),
        };
        let activation = ActivateRetailDailyLimitV1 {
            definition: AssetDefinition::new(
                definition_id.clone(),
                "Kina".to_owned(),
                NumericSpec::fractional(2),
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain),
            ),
            policy: policy.clone(),
        };
        let body = RetailIdentityAttestationBodyV1 {
            domain: RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
            asset_definition_id: definition_id,
            physical_dataspace: policy.physical_dataspace,
            policy_revision: policy.revision,
            account_id: issuer.clone(),
            identity: RetailIdentityCommitmentV1 { digest: [0xA1; 32] },
            uniqueness_evidence_digest: [0xB1; 32],
        };
        let binding = BindRetailIdentityV1 {
            attestation: RetailIdentityAttestationV1 {
                signature: SignatureOf::try_new(key.private_key(), &body)
                    .expect("test-only signed binding"),
                body,
            },
        };
        let monetary = RetailMonetaryMovementV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            purpose: RetailMonetaryPurposeV1::CreditRetail,
            retail_account: Some(issuer.clone()),
            amount: Quantity::from(2_u32),
            operation_digest: [0xC1; 32],
        };
        assert_slice_roundtrip(activation.clone());
        assert_slice_roundtrip(binding.clone());
        assert_slice_roundtrip(monetary.clone());
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<ActivateRetailDailyLimitV1>(
                ActivateRetailDailyLimitV1::WIRE_ID,
            )
            .register_with_id_slice::<BindRetailIdentityV1>(BindRetailIdentityV1::WIRE_ID)
            .register_with_id_slice::<RetailMonetaryMovementV1>(RetailMonetaryMovementV1::WIRE_ID);
        assert_registry_decodes(&registry, ActivateRetailDailyLimitV1::WIRE_ID, activation);
        assert_registry_decodes(&registry, BindRetailIdentityV1::WIRE_ID, binding);
        assert_registry_decodes(&registry, RetailMonetaryMovementV1::WIRE_ID, monetary);
    }
}
