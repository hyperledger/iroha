//! Committed clock bounds for shared governance and SCCP progress carriers.

use super::{CustomParameter, CustomParameterId};

/// Canonical first-release governance clock policy, stored in World custom parameters.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito_schema(
    name = "iroha_data_model::parameter::governance_clock::GovernanceClockParametersV1"
)]
#[norito(deny_unknown_fields)]
pub struct GovernanceClockParametersV1 {
    /// Maximum local lag of an uncertified block performing due work.
    pub due_work_max_lag_ms: u64,
    /// Deterministic G1–G3 block-start work budget.
    pub governance_block_start_work_units: u32,
}

impl Default for GovernanceClockParametersV1 {
    fn default() -> Self {
        Self {
            due_work_max_lag_ms: 60_000,
            governance_block_start_work_units: 64,
        }
    }
}

impl GovernanceClockParametersV1 {
    /// Six cost-one SCCP conclusions and one cost-four enactment must fit in one
    /// pass, so recertification alone cannot starve every pause until expiry.
    pub const MIN_BLOCK_START_WORK_UNITS: u32 = 10;

    /// The sole canonical custom parameter identity.
    #[must_use]
    pub fn parameter_id() -> &'static CustomParameterId {
        static ID: std::sync::OnceLock<CustomParameterId> = std::sync::OnceLock::new();
        ID.get_or_init(|| {
            "governance_clock_v1"
                .parse()
                .expect("static parameter identity")
        })
    }

    /// Validate the lag against the same committed Sumeragi clock parameters.
    /// # Errors
    /// Rejects work capacity below ten, arithmetic overflow, or insufficient lag.
    pub fn validate(self, drift_ms: u64, cadence_ms: u64) -> Result<(), &'static str> {
        let minimum = drift_ms
            .checked_mul(2)
            .and_then(|drift| {
                cadence_ms
                    .checked_mul(4)
                    .and_then(|cadence| drift.checked_add(cadence))
            })
            .ok_or("governance clock bound overflows")?;
        if self.governance_block_start_work_units < Self::MIN_BLOCK_START_WORK_UNITS {
            return Err("governance block-start work budget must be at least ten");
        }
        if self.due_work_max_lag_ms < minimum {
            return Err("governance due-work lag must cover twice drift plus four cadences");
        }
        Ok(())
    }

    /// Decode the exact committed parameter without substituting defaults on failure.
    /// # Errors
    /// Rejects another identity, excessive JSON, or a malformed fixed-field payload.
    pub fn from_custom_parameter(parameter: &CustomParameter) -> Result<Self, &'static str> {
        if parameter.id() != Self::parameter_id() || parameter.payload().get().len() > 256 {
            return Err("invalid governance clock parameter identity or size");
        }
        norito::json::from_str(parameter.payload().get())
            .map_err(|_| "malformed governance clock parameter")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::{Decode, Encode};

    #[test]
    fn work_budget_funds_all_six_pause_conclusions_and_one_enactment() {
        for units in 0..10 {
            let policy = GovernanceClockParametersV1 {
                governance_block_start_work_units: units,
                ..GovernanceClockParametersV1::default()
            };
            assert!(policy.validate(1_000, 1_000).is_err());
        }
        for units in [10, 64, u32::MAX] {
            let policy = GovernanceClockParametersV1 {
                governance_block_start_work_units: units,
                ..GovernanceClockParametersV1::default()
            };
            assert_eq!(policy.validate(1_000, 1_000), Ok(()));
            assert!(units - 6 >= 4);
        }
    }

    #[test]
    fn committed_clock_bound_and_wire_roundtrip() {
        let default = GovernanceClockParametersV1::default();
        assert_eq!(default.validate(1_000, 1_000), Ok(()));
        assert!(default.validate(30_000, 1).is_err());
        assert!(default.validate(u64::MAX, 1).is_err());
        assert!(
            GovernanceClockParametersV1 {
                governance_block_start_work_units: 0,
                ..default
            }
            .validate(0, 1)
            .is_err()
        );
        assert_eq!(
            GovernanceClockParametersV1::decode(&mut default.encode().as_slice()).unwrap(),
            default
        );
        let json = norito::json::to_json(&default).unwrap();
        let parameter = CustomParameter::new(
            GovernanceClockParametersV1::parameter_id().clone(),
            json.parse::<iroha_primitives::json::Json>().unwrap(),
        );
        assert_eq!(
            GovernanceClockParametersV1::from_custom_parameter(&parameter),
            Ok(default)
        );
        let foreign = CustomParameter::new("other".parse().unwrap(), parameter.payload().clone());
        assert!(GovernanceClockParametersV1::from_custom_parameter(&foreign).is_err());
    }
}
