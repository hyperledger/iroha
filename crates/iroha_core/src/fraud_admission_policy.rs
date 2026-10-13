//! Project the committed fraud policy into the existing admission reader.
//!
//! Parameters and their validated projection share State's existing MV owner.
//! Node settings contribute transport only. A block freezes its predecessor;
//! policy changes inside it cannot alter admission of its remaining transactions.

use iroha_config::parameters::actual::FraudMonitoring;
pub use iroha_data_model::fraud::{
    FraudAdmissionAttesterV1, FraudAdmissionPolicyError, FraudAdmissionPolicyV1, FraudRiskBandV1,
};

/// Retain the exact Model policy read by deterministic assessment admission.
#[must_use]
pub fn policy_of(settings: &FraudMonitoring) -> FraudAdmissionPolicyV1 {
    settings.policy.clone()
}

/// Install the exact validated chain policy while preserving transport resources.
///
/// # Errors
/// Invalid policies leave the destination unchanged.
pub fn apply_policy(
    policy: &FraudAdmissionPolicyV1,
    settings: &mut FraudMonitoring,
) -> Result<(), FraudAdmissionPolicyError> {
    policy.validate()?;
    settings.policy = policy.clone();
    Ok(())
}

/// Keep node transport while resetting every nonauthoritative semantic projection.
#[must_use]
pub fn node_local_resources(mut settings: FraudMonitoring) -> FraudMonitoring {
    apply_policy(&FraudAdmissionPolicyV1::protocol_default(), &mut settings)
        .expect("the fixed default policy is valid");
    settings
}

/// Combine transport with the validated policy of this exact parameters version.
///
/// The owner validated the policy when its source changed. Reads do not decode
/// and therefore cannot turn local decoder capacity into transaction rejection.
#[must_use]
pub fn effective_fraud(
    settings: FraudMonitoring,
    parameters: &crate::pipeline_gas_policy::StateParameters,
) -> FraudMonitoring {
    let mut effective = settings;
    apply_policy(parameters.fraud_policy(), &mut effective)
        .expect("the parameter owner retains a validated fraud policy");
    effective
}

#[cfg(test)]
#[path = "fraud_admission_policy_tests.rs"]
mod tests;
