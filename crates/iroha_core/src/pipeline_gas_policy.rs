//! One MV owner for canonical parameters and validated pipeline fee/limit projections.
//!
//! Views and block construction read this projection from committed parameters.
//! A block freezes its predecessor's projection; execution never refreshes it
//! from transaction-local writes. Missing parameters have protocol defaults,
//! and malformed parameters are errors rather than a node-local fallback.

use std::{collections::BTreeSet, str::FromStr as _};

use iroha_config::parameters::actual::{Gas, GasLiquidity, GasRate, GasVolatility};
use iroha_data_model::pipeline_validity_policy::PipelineValidityPolicyV1;
use iroha_data_model::{
    account::{
        AccountId,
        address::{AccountAddress, AccountAddressError},
    },
    asset::AssetDefinitionId,
    parameter::{CustomParameter, CustomParameterId, Parameters},
};
use iroha_primitives::{json::Json, numeric::Numeric};

/// One MV value owning canonical parameters and validated pipeline fees and limits.
///
/// Only `parameters` is serialized or committed. The derived fields are rebuilt
/// on restore and changed atomically with their source; readers never decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateParameters {
    parameters: Parameters,
    gas: Gas,
    pipeline: PipelineValidityPolicyV1,
}

impl Default for StateParameters {
    fn default() -> Self {
        Self {
            parameters: Parameters::default(),
            gas: Gas::default(),
            pipeline: PipelineValidityPolicyV1::protocol_default(),
        }
    }
}

impl std::ops::Deref for StateParameters {
    type Target = Parameters;
    fn deref(&self) -> &Self::Target {
        &self.parameters
    }
}

impl TryFrom<Parameters> for StateParameters {
    type Error = norito::Error;
    fn try_from(parameters: Parameters) -> Result<Self, Self::Error> {
        let gas = from_parameters(&parameters)?;
        let pipeline = parameters
            .custom()
            .get(&PipelineValidityPolicyV1::parameter_id())
            .map(|custom| pipeline_policy(custom.payload()))
            .transpose()?
            .unwrap_or_else(PipelineValidityPolicyV1::protocol_default);
        Ok(Self {
            parameters,
            gas,
            pipeline,
        })
    }
}

impl StateParameters {
    /// Borrow the validated fee projection from this exact parameters version.
    pub fn gas(&self) -> &Gas {
        &self.gas
    }

    /// Borrow the validated execution limits from this same parameters version.
    pub fn pipeline_policy(&self) -> &PipelineValidityPolicyV1 {
        &self.pipeline
    }

    /// Validate and atomically update one original parameter and its derived policies.
    ///
    /// Errors preserve the original decoder refusal and leave both values unchanged.
    ///
    /// # Errors
    /// Returns a Norito decode or validation error for malformed custom gas or
    /// pipeline policy, including noncanonical or duplicate asset addresses,
    /// invalid receiver identities, rates or execution limits. Both stored values
    /// remain unchanged, and original decoder refusals are preserved.
    pub fn set_parameter(
        &mut self,
        parameter: iroha_data_model::parameter::Parameter,
    ) -> Result<(), norito::Error> {
        if let iroha_data_model::parameter::Parameter::Custom(custom) = &parameter
            && matches!(
                custom.id().name().as_ref(),
                TECH_ACCOUNT | ACCEPTED_ASSETS | RATES
            )
        {
            let mut gas = self.gas.clone();
            apply_parameter(&mut gas, custom)?;
            self.parameters.set_parameter(parameter);
            self.gas = gas;
        } else if let iroha_data_model::parameter::Parameter::Custom(custom) = &parameter
            && custom.id().name().as_ref() == PipelineValidityPolicyV1::PARAMETER_ID_STR
        {
            let pipeline = pipeline_policy(custom.payload())?;
            self.parameters.set_parameter(parameter);
            self.pipeline = pipeline;
        } else {
            // Other parameters cannot change these projections and need no decoding.
            self.parameters.set_parameter(parameter);
        }
        Ok(())
    }

    /// Replace the consensus family without touching or decoding custom fee fields.
    /// The execution caller retains responsibility for the authorized transition.
    pub fn set_sumeragi(&mut self, parameters: iroha_data_model::parameter::SumeragiParameters) {
        self.parameters.sumeragi = parameters;
    }

    /// Remove one custom parameter, restoring that field's deterministic default.
    pub fn remove_custom_parameter(&mut self, id: &CustomParameterId) -> Option<CustomParameter> {
        let previous = self.parameters.custom.remove(id);
        match id.name().as_ref() {
            TECH_ACCOUNT => self.gas.tech_account_id = Gas::default().tech_account_id,
            ACCEPTED_ASSETS => self.gas.accepted_assets.clear(),
            RATES => self.gas.units_per_gas.clear(),
            PipelineValidityPolicyV1::PARAMETER_ID_STR => {
                self.pipeline = PipelineValidityPolicyV1::protocol_default();
            }
            _ => {}
        }
        previous
    }

    /// Replace the canonical input only after its entire projection validates.
    ///
    /// # Errors
    /// Returns the original Norito decode or validation error if any supplied gas
    /// or pipeline policy cannot form a valid projection. The existing owner
    /// remains unchanged.
    pub fn replace(&mut self, parameters: Parameters) -> Result<(), norito::Error> {
        *self = Self::try_from(parameters)?;
        Ok(())
    }
}

impl norito::SerializePayload for StateParameters {
    fn serialize(&self, encoder: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        self.parameters.serialize(encoder)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.parameters.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.parameters.encoded_len_exact()
    }
}

impl norito::json::JsonSerialize for StateParameters {
    fn json_serialize(&self, out: &mut String) {
        self.parameters.json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.parameters.json_serialize_to(out)
    }
}

impl norito::json::JsonDeserialize for StateParameters {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let parameters = Parameters::json_deserialize(parser)?;
        Self::try_from(parameters).map_err(norito::json::Error::from_decode_resource)
    }
}

fn pipeline_policy(payload: &Json) -> Result<PipelineValidityPolicyV1, norito::Error> {
    let policy = payload.try_into_any_norito::<PipelineValidityPolicyV1>()?;
    policy
        .validate()
        .map_err(|error| norito::Error::Message(error.to_string()))?;
    Ok(policy)
}

const TECH_ACCOUNT: &str = "ivm_gas_tech_account_id";
const ACCEPTED_ASSETS: &str = "ivm_gas_accepted_assets";
const RATES: &str = "ivm_gas_units_per_gas";

/// The three committed fee fields protected from executor reconciliation.
pub(crate) fn parameter_ids() -> [CustomParameterId; 3] {
    [TECH_ACCOUNT, ACCEPTED_ASSETS, RATES]
        .map(|name| name.parse().expect("static fee parameter id"))
}

#[derive(crate::json_macros::JsonDeserialize)]
#[cfg_attr(test, derive(crate::json_macros::JsonSerialize))]
#[norito(deny_unknown_fields)]
struct CommittedGasRate {
    asset: String,
    units_per_gas: u64,
    twap_local_per_xor: Option<String>,
    liquidity_profile: Option<String>,
    volatility_class: Option<String>,
}

fn canonical_asset(value: &str, field: &str) -> Result<AssetDefinitionId, String> {
    let asset = AssetDefinitionId::parse_address_literal(value)
        .map_err(|error| format!("invalid {field} asset `{value}`: {error}"))?;
    if value != asset.canonical_address() {
        return Err(format!(
            "{field} asset `{value}` is not a canonical asset definition address"
        ));
    }
    Ok(asset)
}

/// Decode a committed canonical receiver without consulting node address prefixes.
pub(crate) fn receiver_id(value: &str) -> Result<AccountId, norito::Error> {
    let decode = || AccountAddress::parse_encoded(value, None)?.to_account_id();
    decode().map_err(|error| match error {
        AccountAddressError::DecodeResourceLimit => {
            norito::Error::Json(norito::json::Error::DecodeResourceLimit)
        }
        AccountAddressError::DecodeResource(resource) => resource.into(),
        AccountAddressError::ScopedDecodeResource(origin) => {
            norito::Error::ScopedDecodeResource(origin)
        }
        other => norito::Error::Message(other.to_string()),
    })
}

fn technical_account(payload: &Json) -> Result<String, norito::Error> {
    let value = payload.try_into_any_norito::<String>()?;
    receiver_id(&value)?;
    Ok(value)
}

fn accepted_assets(payload: &Json) -> Result<Vec<String>, norito::Error> {
    let values = payload.try_into_any_norito::<Vec<String>>()?;
    let mut seen = BTreeSet::new();
    for value in &values {
        if !seen.insert(canonical_asset(value, ACCEPTED_ASSETS).map_err(norito::Error::Message)?) {
            return Err(norito::Error::Message(format!(
                "{ACCEPTED_ASSETS} contains duplicate asset `{value}`"
            )));
        }
    }
    Ok(values)
}

fn rates(payload: &Json) -> Result<Vec<GasRate>, norito::Error> {
    let values = payload.try_into_any_norito::<Vec<CommittedGasRate>>()?;
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .map(|value| {
            if !seen.insert(canonical_asset(&value.asset, RATES).map_err(norito::Error::Message)?) {
                return Err(norito::Error::Message(format!(
                    "{RATES} contains duplicate asset `{}`",
                    value.asset
                )));
            }
            let twap_local_per_xor = match value.twap_local_per_xor {
                None => Numeric::one(),
                Some(text) => {
                    let parsed = Numeric::from_str(&text).map_err(|error| {
                        norito::Error::Message(format!("invalid {RATES} twap `{text}`: {error}"))
                    })?;
                    if parsed <= Numeric::zero() {
                        return Err(norito::Error::Message(format!(
                            "invalid {RATES} twap `{text}`: value must be positive"
                        )));
                    }
                    parsed
                }
            };
            let liquidity = match value.liquidity_profile {
                None => GasLiquidity::default(),
                Some(text) => GasLiquidity::from_str(&text).map_err(|()| {
                    norito::Error::Message(format!("invalid {RATES} liquidity `{text}`"))
                })?,
            };
            let volatility = match value.volatility_class {
                None => GasVolatility::default(),
                Some(text) => GasVolatility::from_str(&text).map_err(|()| {
                    norito::Error::Message(format!("invalid {RATES} volatility `{text}`"))
                })?,
            };
            // Zero retains the current Nexus convention: signature-bound gas is
            // priced by Nexus instead of creating a second pipeline transfer.
            Ok(GasRate {
                asset: value.asset,
                units_per_gas: value.units_per_gas,
                twap_local_per_xor,
                liquidity,
                volatility,
            })
        })
        .collect()
}

/// Validate a fee parameter before ordinary authorized `SetParameter` commits it.
///
/// Returns false for another parameter, or an error for malformed fee policy.
#[cfg(test)]
pub(crate) fn validate_parameter(custom: &CustomParameter) -> Result<bool, norito::Error> {
    apply_parameter(&mut Gas::default(), custom)
}

fn apply_parameter(gas: &mut Gas, custom: &CustomParameter) -> Result<bool, norito::Error> {
    match custom.id().name().as_ref() {
        TECH_ACCOUNT => gas.tech_account_id = technical_account(custom.payload())?,
        ACCEPTED_ASSETS => gas.accepted_assets = accepted_assets(custom.payload())?,
        RATES => gas.units_per_gas = rates(custom.payload())?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Project all fee fields using only committed parameters and protocol defaults.
///
/// A malformed carried value is an error; it never selects local configuration
/// or silently falls back to a default.
pub(crate) fn from_parameters(parameters: &Parameters) -> Result<Gas, norito::Error> {
    let mut policy = Gas::default();
    let [technical_id, assets_id, rates_id] = parameter_ids();
    if let Some(value) = parameters.custom().get(&technical_id) {
        policy.tech_account_id = technical_account(value.payload())?;
    }
    if let Some(value) = parameters.custom().get(&assets_id) {
        policy.accepted_assets = accepted_assets(value.payload())?;
    }
    if let Some(value) = parameters.custom().get(&rates_id) {
        policy.units_per_gas = rates(value.payload())?;
    }
    Ok(policy)
}

/// Explicit committed fields for a test's genesis or prepared fixture World.
///
/// This helper authors parameters; it is never a runtime configuration fallback.
#[cfg(test)]
pub(crate) fn parameters_for_testing(gas: Gas) -> [iroha_data_model::parameter::Parameter; 3] {
    use iroha_data_model::parameter::Parameter;
    let rates = gas
        .units_per_gas
        .into_iter()
        .map(|rate| CommittedGasRate {
            asset: rate.asset,
            units_per_gas: rate.units_per_gas,
            twap_local_per_xor: Some(rate.twap_local_per_xor.to_string()),
            liquidity_profile: Some(
                match rate.liquidity {
                    GasLiquidity::Tier1 => "tier1",
                    GasLiquidity::Tier2 => "tier2",
                    GasLiquidity::Tier3 => "tier3",
                }
                .to_owned(),
            ),
            volatility_class: Some(
                match rate.volatility {
                    GasVolatility::Stable => "stable",
                    GasVolatility::Elevated => "elevated",
                    GasVolatility::Dislocated => "dislocated",
                }
                .to_owned(),
            ),
        })
        .collect::<Vec<_>>();
    let payloads = [
        Json::new(gas.tech_account_id),
        Json::new(gas.accepted_assets),
        Json::new(rates),
    ];
    let mut payloads = payloads.into_iter();
    parameter_ids().map(|id| {
        let parameter = CustomParameter::new(id, payloads.next().expect("three fee fields"));
        validate_parameter(&parameter).expect("valid explicitly authored fixture fee policy");
        Parameter::Custom(parameter)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::parameter::Parameter;
    use iroha_test_samples::ALICE_ID;

    fn parameter(name: &str, payload: Json) -> CustomParameter {
        CustomParameter::new(name.parse().expect("parameter id"), payload)
    }

    #[test]
    fn pipeline_limits_share_atomic_owner_and_read_without_decoding() {
        let mut owner = StateParameters::default();
        let mut limits_policy = PipelineValidityPolicyV1::protocol_default();
        limits_policy.ivm_max_cycles_upper_bound = 777;
        let update = Parameter::Custom(limits_policy.into_custom_parameter());
        let zero = norito::DecodeLimits::new(0, 0, 0, 0, 0);
        let before = owner.clone();
        norito::with_decode_limits_scope(zero, || {
            let error = owner.set_parameter(update.clone()).unwrap_err();
            assert!(norito::core::decode_error_matches_active_limits(&error));
            assert_eq!(owner, before);
        });
        owner.set_parameter(update).unwrap();
        let mut local = iroha_config::parameters::actual::Pipeline::default();
        local.ivm_max_cycles_upper_bound = std::num::NonZeroU64::new(123).unwrap();
        let effective = norito::with_decode_limits_scope(zero, || {
            crate::pipeline_validity_policy::effective_pipeline(local, &owner)
        });
        assert_eq!(effective.ivm_max_cycles_upper_bound.get(), 777);
        let committed = owner.clone();
        limits_policy.ivm_max_cycles_upper_bound = 0;
        assert!(
            owner
                .set_parameter(Parameter::Custom(limits_policy.into_custom_parameter()))
                .is_err()
        );
        assert_eq!(owner, committed);
        let canonical = norito::json::to_json(&owner).unwrap();
        let restored: StateParameters = norito::json::from_str(&canonical).unwrap();
        assert_eq!(restored, owner);
        owner
            .remove_custom_parameter(&PipelineValidityPolicyV1::parameter_id())
            .unwrap();
        assert_eq!(
            owner.pipeline_policy(),
            &PipelineValidityPolicyV1::protocol_default()
        );
        assert!(
            owner
                .custom()
                .get(&PipelineValidityPolicyV1::parameter_id())
                .is_none()
        );
    }

    #[test]
    fn state_parameters_keep_original_serialization_and_rebuild_on_restore() {
        use norito::codec::Encode as _;
        let custom = parameter(TECH_ACCOUNT, Json::new(ALICE_ID.to_string()));
        let mut original = Parameters::default();
        original.set_parameter(Parameter::Custom(custom));
        let owner = StateParameters::try_from(original.clone()).unwrap();
        assert_eq!(owner.encode(), original.encode());
        let canonical = norito::json::to_json(&original).unwrap();
        assert_eq!(norito::json::to_json(&owner).unwrap(), canonical);
        let restored: StateParameters = norito::json::from_str(&canonical).unwrap();
        assert_eq!(restored, owner);
        assert_eq!(restored.gas().tech_account_id, ALICE_ID.to_string());
        original.set_parameter(Parameter::Custom(parameter(
            TECH_ACCOUNT,
            Json::new("alias@domain"),
        )));
        let malformed = norito::json::to_json(&original).unwrap();
        assert!(norito::json::from_str::<StateParameters>(&malformed).is_err());
    }

    #[test]
    fn state_parameter_failures_leave_both_original_and_projection_unchanged() {
        let mut owner = StateParameters::default();
        let initial = owner.clone();
        let update = Parameter::Custom(parameter(TECH_ACCOUNT, Json::new(ALICE_ID.to_string())));
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        norito::with_decode_limits_scope(limits, || {
            let error = owner.set_parameter(update.clone()).unwrap_err();
            assert!(norito::core::decode_error_matches_active_limits(&error));
            assert_eq!(owner, initial);
        });
        owner.set_parameter(update).unwrap();
        assert_eq!(owner.gas().tech_account_id, ALICE_ID.to_string());
        let mut consensus = owner.sumeragi().clone();
        consensus.block_cadence_ms = std::num::NonZeroU64::new(777).unwrap();
        norito::with_decode_limits_scope(limits, || owner.set_sumeragi(consensus.clone()));
        assert_eq!(owner.sumeragi(), &consensus);
        assert_eq!(owner.gas().tech_account_id, ALICE_ID.to_string());
        let committed = owner.clone();
        let mut malformed = Parameters::default();
        malformed.set_parameter(Parameter::Custom(parameter(
            TECH_ACCOUNT,
            Json::new("invalid"),
        )));
        assert!(owner.replace(malformed).is_err());
        assert_eq!(owner, committed);
        let id = parameter_ids()[0].clone();
        assert!(owner.remove_custom_parameter(&id).is_some());
        assert_eq!(owner.gas(), &Gas::default());
        assert!(owner.custom().get(&id).is_none());
        owner.replace((*committed).clone()).unwrap();
        assert_eq!(owner, committed);
    }

    #[test]
    fn parameter_mv_publication_and_rollback_keep_the_same_projection() {
        let cell = mv::cell::Cell::new(StateParameters::default());
        let predecessor = cell.view();
        let mut block = cell.block();
        block
            .set_parameter(Parameter::Custom(parameter(
                TECH_ACCOUNT,
                Json::new(ALICE_ID.to_string()),
            )))
            .unwrap();
        assert_eq!(predecessor.gas(), &Gas::default());
        block.commit();
        assert_eq!(cell.view().gas().tech_account_id, ALICE_ID.to_string());
        let replacement = cell.block_and_revert();
        assert_eq!(replacement.gas(), &Gas::default());
        replacement.commit();
        assert_eq!(cell.view().gas(), &Gas::default());
        assert_eq!(predecessor.gas(), &Gas::default());
    }

    #[test]
    fn policy_and_receiver_preserve_original_scoped_resource_refusals() {
        let literal = AccountAddress::from_account_id(&ALICE_ID)
            .unwrap()
            .to_i105_for_discriminant(427)
            .unwrap();
        let custom = parameter(TECH_ACCOUNT, Json::new(literal.clone()));
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        norito::with_decode_limits_scope(limits, || {
            let original = receiver_id(&literal).unwrap_err();
            assert!(norito::core::decode_error_matches_active_limits(&original));
            let original = validate_parameter(&custom).unwrap_err();
            assert!(norito::core::decode_error_matches_active_limits(&original));
        });
        assert_eq!(receiver_id(&literal).unwrap(), *ALICE_ID);
        assert!(validate_parameter(&custom).unwrap());
        assert!(matches!(
            receiver_id("collector@fees.universal"),
            Err(norito::Error::Message(_))
        ));
    }

    #[test]
    fn committed_receiver_accepts_its_own_prefix_and_rejects_aliases() {
        let address = AccountAddress::from_account_id(&ALICE_ID).unwrap();
        for discriminant in [0, 427, 753] {
            let literal = address.to_i105_for_discriminant(discriminant).unwrap();
            assert_eq!(receiver_id(&literal).unwrap(), *ALICE_ID);
            let mut parameters = Parameters::default();
            parameters.set_parameter(Parameter::Custom(parameter(
                TECH_ACCOUNT,
                Json::new(literal.clone()),
            )));
            assert_eq!(
                from_parameters(&parameters).unwrap().tech_account_id,
                literal
            );
            assert!(receiver_id(&format!(" {literal}")).is_err());
        }
        assert!(receiver_id("collector@fees.universal").is_err());
        assert!(technical_account(&Json::new("collector@fees.universal")).is_err());
    }

    #[test]
    fn explicit_fixture_parameters_roundtrip_the_full_policy() {
        let gas = Gas {
            tech_account_id: ALICE_ID.to_string(),
            accepted_assets: vec!["66owaQmAQMuHxPzxUN3bqZ6FJfDa".to_owned()],
            units_per_gas: vec![GasRate {
                asset: "66owaQmAQMuHxPzxUN3bqZ6FJfDa".to_owned(),
                units_per_gas: 7,
                twap_local_per_xor: Numeric::from(2_u32),
                liquidity: GasLiquidity::Tier3,
                volatility: GasVolatility::Elevated,
            }],
        };
        let mut parameters = Parameters::default();
        for parameter in parameters_for_testing(gas.clone()) {
            parameters.set_parameter(parameter);
        }
        assert_eq!(from_parameters(&parameters).unwrap(), gas);
    }

    #[test]
    fn absent_and_partial_parameters_use_only_protocol_defaults() {
        let mut parameters = Parameters::default();
        assert_eq!(from_parameters(&parameters).unwrap(), Gas::default());
        assert!(receiver_id(&Gas::default().tech_account_id).is_ok());
        parameters.set_parameter(Parameter::Custom(parameter(
            TECH_ACCOUNT,
            Json::new(ALICE_ID.to_string()),
        )));
        let gas = from_parameters(&parameters).unwrap();
        assert_eq!(gas.tech_account_id, ALICE_ID.to_string());
        assert!(gas.accepted_assets.is_empty());
        assert!(gas.units_per_gas.is_empty());
    }

    #[test]
    fn malformed_committed_fields_fail_in_validation_and_projection() {
        for (name, payload) in [
            (TECH_ACCOUNT, Json::new("not an account")),
            (ACCEPTED_ASSETS, Json::new(vec!["not an asset"])),
            (RATES, Json::new("not a list")),
        ] {
            let parameter = parameter(name, payload);
            assert!(validate_parameter(&parameter).is_err());
            let mut parameters = Parameters::default();
            parameters.set_parameter(Parameter::Custom(parameter));
            assert!(from_parameters(&parameters).is_err());
        }
        assert!(!validate_parameter(&parameter("unrelated", Json::new(1_u64))).unwrap());
    }

    #[test]
    fn committed_rates_preserve_zero_and_reject_invalid_or_duplicate_fields() {
        let asset = AssetDefinitionId::parse_address_literal("66owaQmAQMuHxPzxUN3bqZ6FJfDa")
            .unwrap()
            .canonical_address();
        let make = |tail: &str| {
            Json::new(
                norito::json::from_str::<norito::json::Value>(&format!(
                    r#"[{{"asset":"{asset}","units_per_gas":0,{tail}}}]"#
                ))
                .unwrap(),
            )
        };
        let valid = make(
            r#""twap_local_per_xor":"1","liquidity_profile":"tier1","volatility_class":"stable""#,
        );
        let row = rates(&valid).unwrap().remove(0);
        assert_eq!(row.units_per_gas, 0);
        assert_eq!(row.twap_local_per_xor, Numeric::one());
        assert_eq!(row.liquidity, GasLiquidity::Tier1);
        assert_eq!(row.volatility, GasVolatility::Stable);
        let minimal = format!(r#"{{"asset":"{asset}","units_per_gas":0}}"#);
        let minimal = Json::from_str_norito(&format!("[{minimal}]")).unwrap();
        let defaults = rates(&minimal).unwrap().remove(0);
        assert_eq!(defaults.twap_local_per_xor, Numeric::one());
        assert_eq!(defaults.liquidity, GasLiquidity::default());
        assert_eq!(defaults.volatility, GasVolatility::default());
        let duplicated_rates = Json::new(vec![
            norito::json::from_str::<norito::json::Value>(minimal.get()).unwrap()[0].clone(),
            norito::json::from_str::<norito::json::Value>(minimal.get()).unwrap()[0].clone(),
        ]);
        assert!(
            rates(&duplicated_rates)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        for tail in [
            r#""twap_local_per_xor":"0""#,
            r#""twap_local_per_xor":"invalid""#,
            r#""liquidity_profile":"invalid""#,
            r#""volatility_class":"invalid""#,
            r#""unknown":1"#,
        ] {
            assert!(rates(&make(tail)).is_err(), "{tail}");
        }
        let duplicated = Json::new(vec![asset.clone(), asset]);
        assert!(
            accepted_assets(&duplicated)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }
}
