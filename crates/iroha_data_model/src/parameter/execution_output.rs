//! Agreed first-release output capacity, distinct from node-local memory limits.
//!
//! The genesis capacity envelope bounds later registry growth and active Time
//! scheduling. These are logical output limits, not a proof that source bytes,
//! execution metadata and host allocations fit the complete carrier.

use crate::block::{
    consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
    output_budget::{ExecutionOutputLimits, ExecutionOutputTerminalCeilings},
};

/// Atomic consensus output-capacity envelope installed at genesis.
///
/// Core rejects post-genesis changes: already-admitted indivisible work must not
/// lose its capacity to a later policy tightening. The active Time count is a
/// separate block parameter and may change within this fixed envelope.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
)]
#[norito_schema(name = "iroha_data_model::parameter::execution_output::ExecutionOutputPolicyV1")]
#[norito(deny_unknown_fields)]
pub struct ExecutionOutputPolicyV1 {
    /// Maximum top-level Network, Pipeline and Time output rows.
    pub max_outputs: u32,
    /// Maximum canonical frame bytes of one complete output row.
    pub max_output_bytes: u64,
    /// Maximum sum of complete canonical output-row frame bytes.
    pub max_total_output_bytes: u64,
    /// Maximum complete executed `SignedBlockWire` bytes, including non-output data.
    pub max_executed_wire_bytes: u64,
    /// Maximum total Pipeline registrations, including disabled/depleted actions.
    /// Zero disables new Pipeline registrations; it never means unlimited.
    pub max_pipeline_triggers: u32,
    /// Maximum total Time registrations, including disabled/depleted actions.
    pub max_time_triggers: u32,
    /// Upper bound for the separately governed active Time invocation count.
    pub max_time_invocations: u32,
}

impl ExecutionOutputPolicyV1 {
    /// Finite first-release bootstrap profile, shared by every validator.
    ///
    /// Genesis may explicitly replace this whole profile before publication.
    /// No node-local configuration silently overrides canonical execution policy.
    /// These defaults reserve logical output capacity only; full source/metadata
    /// and host admission must still be established by the execution owner.
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            max_outputs: 65_536,
            max_output_bytes: 1024 * 1024,
            max_total_output_bytes: 64 * 1024 * 1024,
            max_executed_wire_bytes: MAX_EXECUTED_BLOCK_WIRE_BYTES,
            max_pipeline_triggers: 256,
            max_time_triggers: 4096,
            max_time_invocations: 512,
        }
    }

    /// The logical model limits belonging to this exact agreed profile.
    #[must_use]
    pub const fn limits(self) -> ExecutionOutputLimits {
        ExecutionOutputLimits {
            max_outputs: self.max_outputs,
            max_output_bytes: self.max_output_bytes,
            max_total_output_bytes: self.max_total_output_bytes,
            max_executed_wire_bytes: self.max_executed_wire_bytes,
        }
    }

    /// Validate ordered finite bounds and minimum terminal-row feasibility.
    ///
    /// This proves only the one-input terminal count/row-byte lemma under maximum
    /// permitted registry/Time growth. It grants no complete-source admission.
    /// # Errors
    /// Rejects invalid limits, an excessive protocol wire ceiling, unbounded Time
    /// work, or an envelope unable to hold even one input's terminal output plan.
    pub fn validate(self) -> Result<(), String> {
        let limits = self.limits();
        limits.validate()?;
        if self.max_executed_wire_bytes > MAX_EXECUTED_BLOCK_WIRE_BYTES
            || self.max_time_triggers == 0
            || self.max_time_invocations == 0
        {
            return Err(
                "execution output policy exceeds protocol bounds or has zero Time capacity".into(),
            );
        }
        let terminals = ExecutionOutputTerminalCeilings::derive()?;
        let envelope = terminals.envelope(self.max_pipeline_triggers, self.max_time_invocations);
        if envelope.maximum_network_inputs(&limits)? == 0 {
            return Err(
                "execution output policy cannot reserve one input's complete terminal plan".into(),
            );
        }
        Ok(())
    }

    /// Conservative Network count whose terminal plan fits under all permitted
    /// later Pipeline/Time growth. Source bytes and host work need separate checks.
    /// # Errors
    /// Rejects invalid policy or canonical terminal sizing failures.
    pub fn maximum_terminal_network_inputs(self) -> Result<u32, String> {
        self.validate()?;
        ExecutionOutputTerminalCeilings::derive()?
            .envelope(self.max_pipeline_triggers, self.max_time_invocations)
            .maximum_network_inputs(&self.limits())
    }

    /// Validate the active count without deriving it from the Network input cap.
    /// # Errors
    /// Rejects a zero or above-envelope count.
    pub fn validate_time_invocations(self, count: u32) -> Result<(), String> {
        if count == 0 || count > self.max_time_invocations {
            return Err("active Time invocation count exceeds agreed execution capacity".into());
        }
        Ok(())
    }
}

impl core::fmt::Display for ExecutionOutputPolicyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{},{},{},{},{},{},{}_OUTPUT",
            self.max_outputs,
            self.max_output_bytes,
            self.max_total_output_bytes,
            self.max_executed_wire_bytes,
            self.max_pipeline_triggers,
            self.max_time_triggers,
            self.max_time_invocations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_policy_is_finite_and_has_terminal_capacity() {
        let policy = ExecutionOutputPolicyV1::bootstrap();
        policy.validate().unwrap();
        assert!(policy.maximum_terminal_network_inputs().unwrap() > 0);
        assert_eq!(policy.limits().max_outputs, policy.max_outputs);
        assert_eq!(policy.limits().max_output_bytes, policy.max_output_bytes);
        assert_eq!(
            policy.limits().max_total_output_bytes,
            policy.max_total_output_bytes
        );
        assert_eq!(
            policy.limits().max_executed_wire_bytes,
            policy.max_executed_wire_bytes
        );
        assert!(!policy.to_string().is_empty());
    }

    #[test]
    fn policy_rejects_infeasible_terminal_and_protocol_limits() {
        let original = ExecutionOutputPolicyV1::bootstrap();
        let mut bad = original;
        bad.max_outputs = 1;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_total_output_bytes = 1;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_executed_wire_bytes = MAX_EXECUTED_BLOCK_WIRE_BYTES + 1;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_time_invocations = 0;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_time_triggers = 0;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_pipeline_triggers = u32::MAX;
        assert!(bad.validate().is_err());
        bad = original;
        bad.max_pipeline_triggers = 0;
        bad.validate().unwrap();
    }

    #[test]
    fn active_time_count_is_independent_and_bounded() {
        let policy = ExecutionOutputPolicyV1::bootstrap();
        assert!(policy.validate_time_invocations(0).is_err());
        policy.validate_time_invocations(1).unwrap();
        policy
            .validate_time_invocations(policy.max_time_invocations)
            .unwrap();
        assert!(
            policy
                .validate_time_invocations(policy.max_time_invocations + 1)
                .is_err()
        );
    }

    #[test]
    fn output_policy_roundtrips_and_rejects_unknown_json_claims() {
        let policy = ExecutionOutputPolicyV1::bootstrap();
        assert_eq!(
            norito::decode_canonical::<ExecutionOutputPolicyV1>(
                &norito::encode_canonical(&policy).unwrap()
            )
            .unwrap(),
            policy
        );
        let mut value = norito::json::to_value(&policy).unwrap();
        assert_eq!(
            norito::json::from_value::<ExecutionOutputPolicyV1>(value.clone()).unwrap(),
            policy
        );
        value
            .as_object_mut()
            .unwrap()
            .insert("local_memory_override".into(), 1_u64.into());
        assert!(norito::json::from_value::<ExecutionOutputPolicyV1>(value).is_err());
    }
}

impl norito::json::JsonDeserialize for ExecutionOutputPolicyV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::system::parameters_json::decode_execution_output(parser)
    }
}
