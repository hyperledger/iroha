//! Canonical committed monetary policy for public-lane staking on either root scope.
//!
//! TODO: connect genesis, restore and authorized updates to the charged original
//! typed parameter owner, migrate all execution consumers, and retire local fields
//! together before adopting this model into the complete staking implementation.

use core::num::NonZeroU32;

use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonSerialize,
    account::AccountId,
    asset::AssetDefinitionId,
    parameter::{CustomParameter, CustomParameterId, Parameters},
    validation_fee_rewards::MAX_REWARD_RECIPIENTS,
};

/// Monetary staking rules authored in signed genesis and changed by committed parameters.
///
/// The same mandatory policy is available on permissioned and NPoS roots. Validator
/// modes and committee capacity retain their separate committed owners. Exact account
/// and asset identities are part of this policy; no node-local selector supplies them.
///
/// Account registration, asset scope, retained liabilities and authorized updates are
/// validated by execution. The policy does not grant a caller authority to move funds.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::PublicLaneStakingPolicy")]
#[norito(deny_unknown_fields)]
pub struct PublicLaneStakingPolicy {
    /// Minimum stake required when admitting a validator.
    pub min_validator_stake: Quantity,
    /// Maximum distinct stake shares represented by one validator's reward exposure.
    pub max_stake_shares_per_validator: NonZeroU32,
    /// Maximum outstanding unbond requests retained for each stake share.
    pub max_pending_unbonds_per_share: NonZeroU32,
    /// Minimum delay between a committed unbond request and its release, in milliseconds.
    pub unbonding_delay_ms: u64,
    /// Maximum slash fraction in basis points, including zero and the full 10,000.
    pub max_slash_bps: u16,
    /// Canonical currency held by the staking custody account.
    pub stake_asset_id: AssetDefinitionId,
    /// Canonical account that owns the public staking custody balance.
    pub stake_escrow_account_id: AccountId,
    /// Canonical account receiving a committed slash transfer.
    pub slash_sink_account_id: AccountId,
}

impl norito::json::JsonDeserialize for PublicLaneStakingPolicy {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::monetary_json::decode_staking_ordinary(parser)
    }
}

/// Why a committed staking monetary policy cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum PublicLaneStakingPolicyError {
    /// The root has no mandatory staking policy.
    #[error("missing committed public-lane staking policy")]
    MissingParameter,
    /// Genesis execution lost or changed its authenticated original policy source.
    #[error("staking policy does not match its authenticated original genesis source")]
    GenesisSourceMismatch,
    /// The supplied custom parameter identifies a different policy.
    #[error("wrong public-lane staking parameter identity")]
    WrongParameter,
    /// Original codec failure, including its scoped resource refusal and provenance.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// One validator's shares cannot fit the canonical historical reward exposure.
    #[error("staking share cap exceeds the historical reward recipient bound")]
    TooManyStakeShares,
    /// A slash fraction exceeds the full exposure.
    #[error("staking slash fraction exceeds 10000 basis points")]
    InvalidSlashFraction,
}

impl PublicLaneStakingPolicy {
    /// Canonical identity of the mandatory committed policy.
    pub const PARAMETER_ID_STR: &'static str = "public_lane_staking_v1";

    /// Return the one canonical policy key.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("static staking parameter identifier")
    }

    /// Validate intrinsic bounds without consulting node-local configuration.
    ///
    /// # Errors
    /// Rejects a share cap that cannot fit one historical reward exposure or a slash
    /// fraction exceeding the entire retained exposure. Nonzero caps and nonnegative
    /// quantities are enforced by their types. Custody and liability checks belong to State.
    pub fn validate(&self) -> Result<(), PublicLaneStakingPolicyError> {
        if usize::try_from(self.max_stake_shares_per_validator.get())
            .map_or(true, |shares| shares > MAX_REWARD_RECIPIENTS)
        {
            return Err(PublicLaneStakingPolicyError::TooManyStakeShares);
        }
        if self.max_slash_bps > 10_000 {
            return Err(PublicLaneStakingPolicyError::InvalidSlashFraction);
        }
        Ok(())
    }

    /// Encode a policy under its canonical parameter identity after validating its bounds.
    ///
    /// # Errors
    /// Rejects invalid intrinsic bounds or an unrepresentable canonical JSON payload.
    /// Codec failures retain their original typed cause, including resource refusal.
    pub fn into_custom_parameter(self) -> Result<CustomParameter, PublicLaneStakingPolicyError> {
        self.validate()?;
        let payload = iroha_primitives::json::Json::try_new(self)
            .map_err(PublicLaneStakingPolicyError::Codec)?;
        Ok(CustomParameter::new(Self::parameter_id(), payload))
    }

    /// Decode and validate exactly the canonical policy parameter.
    ///
    /// # Errors
    /// Rejects another parameter identity, missing or unknown fields, malformed typed
    /// identities and quantities, and invalid intrinsic bounds. Original codec failures
    /// are returned without formatting, copying their cause or replacing their scope.
    pub fn from_custom_parameter(
        parameter: &CustomParameter,
    ) -> Result<Self, PublicLaneStakingPolicyError> {
        if parameter.id() != &Self::parameter_id() {
            return Err(PublicLaneStakingPolicyError::WrongParameter);
        }
        let policy: Self = parameter
            .payload()
            .try_into_any()
            .map_err(PublicLaneStakingPolicyError::Codec)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Read the mandatory policy when authoring or validating committed parameters.
    ///
    /// This allocating decoder is not a transaction resource-admission boundary. Runtime
    /// execution must retain the charged original typed parameter owner for the whole attempt.
    ///
    /// # Errors
    /// Rejects absent and malformed policies instead of supplying a node-local default.
    pub fn from_parameters(parameters: &Parameters) -> Result<Self, PublicLaneStakingPolicyError> {
        let parameter = parameters
            .custom()
            .get(&Self::parameter_id())
            .ok_or(PublicLaneStakingPolicyError::MissingParameter)?;
        Self::from_custom_parameter(parameter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter::Parameter;

    fn policy() -> PublicLaneStakingPolicy {
        let account = AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .unwrap(),
        );
        PublicLaneStakingPolicy {
            min_validator_stake: "2000.25".parse().unwrap(),
            max_stake_shares_per_validator: NonZeroU32::new(7).unwrap(),
            max_pending_unbonds_per_share: NonZeroU32::new(3).unwrap(),
            unbonding_delay_ms: 43_210,
            max_slash_bps: 1_001,
            stake_asset_id: AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::parse_fully_qualified("app.acme").unwrap(),
                "stake".parse().unwrap(),
            ),
            stake_escrow_account_id: account.clone(),
            slash_sink_account_id: account,
        }
    }

    #[test]
    fn canonical_policy_preserves_every_monetary_field_in_all_codecs() {
        let expected = policy();
        let encoded = norito::encode_canonical(&expected).unwrap();
        assert_eq!(
            norito::decode_canonical::<PublicLaneStakingPolicy>(&encoded).unwrap(),
            expected
        );
        let json = norito::json::to_json(&expected).unwrap();
        assert_eq!(
            norito::json::from_str::<PublicLaneStakingPolicy>(&json).unwrap(),
            expected
        );
        let parameter = expected.clone().into_custom_parameter().unwrap();
        assert_eq!(parameter.id().to_string(), "public_lane_staking_v1");
        assert_eq!(parameter.id(), &PublicLaneStakingPolicy::parameter_id());
        assert_eq!(
            PublicLaneStakingPolicy::from_custom_parameter(&parameter).unwrap(),
            expected
        );
        let mut parameters = Parameters::default();
        parameters.set_parameter(Parameter::Custom(parameter));
        assert_eq!(
            PublicLaneStakingPolicy::from_parameters(&parameters).unwrap(),
            expected
        );
    }

    #[test]
    fn absent_malformed_and_wrong_policy_never_supply_defaults() {
        assert!(matches!(
            PublicLaneStakingPolicy::from_parameters(&Parameters::default()),
            Err(PublicLaneStakingPolicyError::MissingParameter)
        ));
        let valid = policy().into_custom_parameter().unwrap();
        let wrong = CustomParameter::new("other_policy".parse().unwrap(), valid.payload().clone());
        assert!(matches!(
            PublicLaneStakingPolicy::from_custom_parameter(&wrong),
            Err(PublicLaneStakingPolicyError::WrongParameter)
        ));
        let malformed = CustomParameter::new(
            PublicLaneStakingPolicy::parameter_id(),
            "{}".parse::<iroha_primitives::json::Json>().unwrap(),
        );
        let PublicLaneStakingPolicyError::Codec(error) =
            PublicLaneStakingPolicy::from_custom_parameter(&malformed).unwrap_err()
        else {
            panic!("missing required fields must retain the original codec failure");
        };
        assert!(error.decode_resource_error().is_none());
        let mut parameters = Parameters::default();
        parameters.set_parameter(Parameter::Custom(malformed));
        assert!(matches!(
            PublicLaneStakingPolicy::from_parameters(&parameters),
            Err(PublicLaneStakingPolicyError::Codec(_))
        ));
    }

    #[test]
    fn share_and_slash_bounds_reject_one_over_before_parameter_encoding() {
        let mut exact = policy();
        exact.max_stake_shares_per_validator =
            NonZeroU32::new(u32::try_from(MAX_REWARD_RECIPIENTS).unwrap()).unwrap();
        exact.max_slash_bps = 10_000;
        exact.validate().unwrap();
        exact.clone().into_custom_parameter().unwrap();
        for over_shares in [true, false] {
            let mut invalid = exact.clone();
            let expected = if over_shares {
                invalid.max_stake_shares_per_validator =
                    NonZeroU32::new(exact.max_stake_shares_per_validator.get() + 1).unwrap();
                PublicLaneStakingPolicyError::TooManyStakeShares
            } else {
                invalid.max_slash_bps += 1;
                PublicLaneStakingPolicyError::InvalidSlashFraction
            };
            let assert_kind = |error| match &expected {
                PublicLaneStakingPolicyError::TooManyStakeShares => {
                    assert!(matches!(
                        error,
                        PublicLaneStakingPolicyError::TooManyStakeShares
                    ));
                }
                PublicLaneStakingPolicyError::InvalidSlashFraction => {
                    assert!(matches!(
                        error,
                        PublicLaneStakingPolicyError::InvalidSlashFraction
                    ));
                }
                _ => unreachable!("two intrinsic policy boundary failures"),
            };
            assert_kind(invalid.validate().unwrap_err());
            assert_kind(invalid.clone().into_custom_parameter().unwrap_err());
            let unchecked = CustomParameter::new(
                PublicLaneStakingPolicy::parameter_id(),
                iroha_primitives::json::Json::try_new(invalid).unwrap(),
            );
            assert_kind(PublicLaneStakingPolicy::from_custom_parameter(&unchecked).unwrap_err());
        }
        exact.max_slash_bps = 0;
        exact.unbonding_delay_ms = 0;
        exact.min_validator_stake = Quantity::zero();
        exact.validate().unwrap();
    }

    #[test]
    fn policy_decode_preserves_original_scoped_resource_refusal_and_retry() {
        use norito::core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError,
            classify_decode_attempt,
        };
        let parameter = policy().into_custom_parameter().unwrap();
        let limits = |bytes| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let decode = || PublicLaneStakingPolicy::from_custom_parameter(&parameter);
        let (decoded, usage) =
            norito::core::with_decode_limits_measured(limits(usize::MAX), decode);
        let expected = decoded.unwrap();
        let demand = usage.total_allocated_bytes();
        assert!(demand > 0);
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original =
            DecodeBudgetContext::try_new_owned(limits(demand.checked_mul(4).unwrap()), &pool)
                .unwrap();
        let reserved = pool.reserved_bytes();
        let mut observed = None;
        let refusal = original
            .with(|| {
                norito::with_decode_limits_scope(limits(0), || {
                    classify_decode_attempt(|| {
                        let PublicLaneStakingPolicyError::Codec(error) = decode().unwrap_err()
                        else {
                            panic!("resource refusal must remain an original codec error");
                        };
                        let norito::Error::ScopedDecodeResource(origin) = &error else {
                            panic!("policy decoder must retain the original scoped observer");
                        };
                        observed = Some(origin.clone());
                        Err::<(), _>(error)
                    })
                })
            })
            .unwrap_err();
        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let error = refusal.into_error();
        let Some(DecodeResourceError::TotalAllocationExceeded { attempted, limit }) =
            error.decode_resource_error()
        else {
            panic!("policy must preserve exact original allocation refusal fields");
        };
        assert!(attempted > 0);
        assert_eq!(limit, 0);
        let norito::Error::ScopedDecodeResource(returned) = error else {
            panic!("policy must return the original scoped observer");
        };
        assert_eq!(returned, observed.unwrap());
        drop(returned);
        assert_eq!(original.with(decode).unwrap(), expected);
        assert_eq!(pool.reserved_bytes(), reserved);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn strict_layout_requires_all_fields_and_rejects_local_selectors() {
        let valid = norito::json::to_value(&policy()).unwrap();
        for field in valid.as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(norito::json::from_value::<PublicLaneStakingPolicy>(missing).is_err());
        }
        let mut unknown = valid.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("node_local_override".into(), true.into());
        assert!(norito::json::from_value::<PublicLaneStakingPolicy>(unknown).is_err());
        for field in [
            "stake_asset_id",
            "stake_escrow_account_id",
            "slash_sink_account_id",
        ] {
            let mut alias = valid.clone();
            alias
                .as_object_mut()
                .unwrap()
                .insert(field.into(), "merchant@banka.paynet".into());
            assert!(norito::json::from_value::<PublicLaneStakingPolicy>(alias).is_err());
        }
        for field in [
            "max_stake_shares_per_validator",
            "max_pending_unbonds_per_share",
        ] {
            let mut zero = valid.clone();
            zero.as_object_mut()
                .unwrap()
                .insert(field.into(), 0_u32.into());
            assert!(norito::json::from_value::<PublicLaneStakingPolicy>(zero).is_err());
        }
        let mut negative = valid;
        negative
            .as_object_mut()
            .unwrap()
            .insert("min_validator_stake".into(), "-1".into());
        assert!(norito::json::from_value::<PublicLaneStakingPolicy>(negative).is_err());
    }
}
