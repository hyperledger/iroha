//! One committed monetary fee policy for Global and independent data space roots.

use std::collections::BTreeSet;

use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    account::AccountId,
    asset::AssetDefinitionId,
    block::consensus::SumeragiRootScope,
    parameter::{CustomParameter, CustomParameterId, Parameters},
};

/// Complete root-local monetary policy, authored by genesis and changed by committed parameters.
///
/// Every block consumes its predecessor's policy. Global Nexus fees burn the committed
/// network XOR currency; a data space root burns only its scoped currency. Sink identity,
/// sponsor custody and successful-claim exemptions are committed alongside the rates.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::RootFeePolicy")]
#[norito(deny_unknown_fields)]
pub struct RootFeePolicy {
    /// Canonical fee currency. Execution checks Global XOR or the exact data space scope.
    pub fee_asset_id: AssetDefinitionId,
    /// Exact account receiving native fees that transfer instead of burning.
    pub fee_sink_account_id: AccountId,
    /// Exact custody account of isolated public sponsor-program vault balances.
    pub sponsor_vault_custody_account_id: AccountId,
    /// Authorities permitted to claim public XOR without a successful-claim fee.
    pub successful_claim_fee_exempt_authorities: BTreeSet<AccountId>,
    /// Charge applied to every ordinary transaction (positive on data space roots).
    pub base_fee: Quantity,
    /// Charge for each byte of the signed transaction payload.
    pub per_byte_fee: Quantity,
    /// Charge for each native instruction in the transaction.
    pub per_instruction_fee: Quantity,
    /// Multiplier applied to measured execution gas (positive on data space roots).
    pub per_gas_unit_fee: Quantity,
}

/// Why a committed root fee parameter cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RootFeePolicyError {
    /// Required base or gas charge was zero.
    #[error("private-root base and gas fees must be positive")]
    ZeroRequiredRate,
    /// Public fee exemptions cannot be installed on an independent data space root.
    #[error("dataspace-root fee policy cannot grant public claim exemptions")]
    PrivateExemption,
    /// The supplied custom parameter identifies another policy.
    #[error("wrong root fee parameter identity")]
    WrongParameter,
    /// The parameter did not contain the strict typed policy.
    #[error("malformed root fee parameter")]
    MalformedParameter,
}

impl RootFeePolicy {
    /// Canonical identity of the committed root fee parameter.
    pub const PARAMETER_ID_STR: &'static str = "root_fees_v1";

    /// Canonical parameter key.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("static parameter identifier")
    }

    /// Validate the policy against the immutable signed root scope.
    ///
    /// # Errors
    /// Private roots require positive base/gas fees and cannot grant public exemptions.
    /// Global roots may explicitly commit a zero schedule, including test and initial networks.
    /// Asset ownership and account registration are checked by their execution owners.
    pub fn validate_for_scope(&self, scope: &SumeragiRootScope) -> Result<(), RootFeePolicyError> {
        if matches!(scope, SumeragiRootScope::Dataspace { .. }) {
            if self.base_fee.is_zero() || self.per_gas_unit_fee.is_zero() {
                return Err(RootFeePolicyError::ZeroRequiredRate);
            }
            if !self.successful_claim_fee_exempt_authorities.is_empty() {
                return Err(RootFeePolicyError::PrivateExemption);
            }
        }
        Ok(())
    }

    /// Encode the validated policy as its canonical custom parameter.
    ///
    /// # Errors
    /// Rejects an unrepresentable parameter payload. Scope validation is performed by the root owner.
    pub fn into_custom_parameter(self) -> Result<CustomParameter, RootFeePolicyError> {
        // The typed constructor canonicalizes object-key order. Parsing serializer text
        // would require declaration order to happen to match canonical lexical order.
        let payload = iroha_primitives::json::Json::try_new(self)
            .map_err(|_| RootFeePolicyError::MalformedParameter)?;
        Ok(CustomParameter::new(Self::parameter_id(), payload))
    }

    /// Decode only the exact, strictly validated policy parameter.
    ///
    /// # Errors
    /// Rejects a different identity, malformed payload or unknown fields.
    pub fn from_custom_parameter(parameter: &CustomParameter) -> Result<Self, RootFeePolicyError> {
        if parameter.id() != &Self::parameter_id() {
            return Err(RootFeePolicyError::WrongParameter);
        }
        let policy: Self = parameter
            .payload()
            .try_into_any()
            .map_err(|_| RootFeePolicyError::MalformedParameter)?;
        Ok(policy)
    }

    /// Read committed parameters, distinguishing an absent policy from a malformed one.
    ///
    /// # Errors
    /// A present policy must decode. Execution on either root scope must reject `None`.
    pub fn from_parameters(parameters: &Parameters) -> Result<Option<Self>, RootFeePolicyError> {
        parameters
            .custom()
            .get(&Self::parameter_id())
            .map(Self::from_custom_parameter)
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RootFeePolicy {
        let account = AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .unwrap(),
        );
        RootFeePolicy {
            fee_asset_id: AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::parse_fully_qualified("app.acme").unwrap(),
                "gas".parse().unwrap(),
            ),
            fee_sink_account_id: account.clone(),
            sponsor_vault_custody_account_id: account,
            successful_claim_fee_exempt_authorities: BTreeSet::new(),
            base_fee: "0.01".parse().unwrap(),
            per_byte_fee: Quantity::zero(),
            per_instruction_fee: "0.002".parse().unwrap(),
            per_gas_unit_fee: "0.000001".parse().unwrap(),
        }
    }

    fn private_scope() -> SumeragiRootScope {
        SumeragiRootScope::Dataspace {
            parent_network_id: crate::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"fee parent",
                )),
            ),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
        }
    }

    #[test]
    fn committed_accounts_refuse_aliases_and_malformed_literals() {
        for field in ["fee_sink_account_id", "sponsor_vault_custody_account_id"] {
            for invalid in ["merchant@banka.paynet", "   ", "not-an-account-literal"] {
                let mut payload = norito::json::value::to_value(&policy()).unwrap();
                payload
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), norito::json::Value::String(invalid.into()));
                let custom = CustomParameter::new(
                    RootFeePolicy::parameter_id(),
                    iroha_primitives::json::Json::new(payload),
                );
                assert_eq!(
                    RootFeePolicy::from_custom_parameter(&custom),
                    Err(RootFeePolicyError::MalformedParameter)
                );
            }
        }
    }

    #[test]
    fn committed_policy_preserves_every_monetary_field_in_all_codecs() {
        let mut expected = policy();
        expected
            .successful_claim_fee_exempt_authorities
            .insert(expected.fee_sink_account_id.clone());
        let bytes = norito::encode_canonical(&expected).unwrap();
        assert_eq!(
            norito::decode_canonical::<RootFeePolicy>(&bytes).unwrap(),
            expected
        );
        let json = norito::json::to_json(&expected).unwrap();
        assert_eq!(
            norito::json::from_str::<RootFeePolicy>(&json).unwrap(),
            expected
        );
        let parameter = expected.clone().into_custom_parameter().unwrap();
        assert_eq!(parameter.id(), &RootFeePolicy::parameter_id());
        assert_eq!(
            RootFeePolicy::from_custom_parameter(&parameter).unwrap(),
            expected
        );
        let mut parameters = Parameters::default();
        assert_eq!(RootFeePolicy::from_parameters(&parameters).unwrap(), None);
        parameters.set_parameter(crate::parameter::Parameter::Custom(parameter));
        assert_eq!(
            RootFeePolicy::from_parameters(&parameters).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn private_rates_and_exemptions_are_restricted_by_the_original_root_scope() {
        let mut fees = policy();
        fees.validate_for_scope(&private_scope()).unwrap();
        for gas in [false, true] {
            let mut invalid = fees.clone();
            if gas {
                invalid.per_gas_unit_fee = Quantity::zero();
            } else {
                invalid.base_fee = Quantity::zero();
            }
            assert_eq!(
                invalid.validate_for_scope(&private_scope()),
                Err(RootFeePolicyError::ZeroRequiredRate)
            );
            invalid
                .validate_for_scope(&SumeragiRootScope::Global)
                .unwrap();
        }
        fees.successful_claim_fee_exempt_authorities
            .insert(fees.fee_sink_account_id.clone());
        assert_eq!(
            fees.validate_for_scope(&private_scope()),
            Err(RootFeePolicyError::PrivateExemption)
        );
        fees.validate_for_scope(&SumeragiRootScope::Global).unwrap();
    }

    #[test]
    fn committed_policy_rejects_retired_layout_aliases_and_malformed_parameters() {
        let valid = policy().into_custom_parameter().unwrap();
        for id in ["other", "private_root_fees_v1"] {
            let wrong = CustomParameter::new(id.parse().unwrap(), valid.payload().clone());
            assert_eq!(
                RootFeePolicy::from_custom_parameter(&wrong),
                Err(RootFeePolicyError::WrongParameter)
            );
        }
        let malformed = CustomParameter::new(RootFeePolicy::parameter_id(), "{}".parse().unwrap());
        assert_eq!(
            RootFeePolicy::from_custom_parameter(&malformed),
            Err(RootFeePolicyError::MalformedParameter)
        );
        for field in ["node_override", "settlement_mode"] {
            let mut value = norito::json::to_value(&policy()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), "direct".into());
            assert!(norito::json::from_value::<RootFeePolicy>(value).is_err());
        }
        for field in [
            "fee_asset_id",
            "fee_sink_account_id",
            "sponsor_vault_custody_account_id",
        ] {
            let mut value = norito::json::to_value(&policy()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), "alias@universal".into());
            assert!(
                norito::json::from_value::<RootFeePolicy>(value).is_err(),
                "{field} is an exact identity"
            );
        }
        for field in [
            "base_fee",
            "per_byte_fee",
            "per_instruction_fee",
            "per_gas_unit_fee",
        ] {
            let mut value = norito::json::to_value(&policy()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), "-1".into());
            assert!(
                norito::json::from_value::<RootFeePolicy>(value).is_err(),
                "{field} cannot be negative"
            );
        }
    }
}
