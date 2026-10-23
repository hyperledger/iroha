//! Committed execution-limit policy of a chain.
//!
//! [`PipelineValidityPolicyV1`] is the typed payload of the custom parameter
//! [`PipelineValidityPolicyV1::PARAMETER_ID_STR`]. It carries the limits of
//! the transaction pipeline that decide whether a transaction, a contract
//! program or a query is accepted: overlay size, IVM cycle and decoded-program
//! bounds, the quarantine lane, stored-query limits and the AMX budget model,
//! and the access-set derivation mode. A chain installs it with an ordinary
//! authorized `SetParameter`, in genesis or later; a change takes effect from
//! the block after the one that commits it. A chain that never installs the
//! parameter uses [`PipelineValidityPolicyV1::protocol_default`].
//!
//! This module owns the type, the protocol default and the canonical
//! validation, so genesis tools and SDKs author and check a policy without a
//! node. Applying a policy to State is Core's job. Worker counts, caches,
//! tracing, accelerator selection and signature batch sizes are local
//! resources of a node and are not part of this policy.

use iroha_primitives::json::Json;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonSerialize,
    parameter::custom::{CustomParameter, CustomParameterId},
};

mod json_decode;
pub use json_decode::PipelinePolicyJsonAdmissionError;

/// Largest value of a policy field that counts in-memory items.
///
/// A fixed protocol constant, independent of the pointer width of the
/// validator that checks it.
pub const MAX_COUNT_FIELD: u64 = u32::MAX as u64;

/// Why a pipeline validity policy value is not a valid chain policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineValidityPolicyError {
    /// The committed payload does not decode as the exact V1 policy.
    #[error("the pipeline validity policy payload is not a canonical V1 policy: {0}")]
    Malformed(String),
    /// A field that must be positive is zero.
    #[error("pipeline validity policy field `{0}` must be non-zero")]
    Zero(&'static str),
    /// A count field exceeds [`MAX_COUNT_FIELD`].
    #[error("pipeline validity policy field `{0}` exceeds the protocol maximum of the field")]
    OutOfRange(&'static str),
}

macro_rules! pipeline_policy {
    ( $( $(#[$field_meta:meta])* $field:ident: $type:ty ),+ $(,)? ) => {
        /// The complete first-release execution-limit policy of a chain.
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Encode,
            Decode,
            IntoSchema,
            DeriveJsonSerialize,
        )]
        #[norito(deny_unknown_fields)]
        pub struct PipelineValidityPolicyV1 {
            $( $(#[$field_meta])* pub $field: $type, )+
        }

        impl norito::json::JsonDeserialize for PipelineValidityPolicyV1 {
            fn json_deserialize(parser: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
                decode_record(parser, &json_decode::Ordinary)
            }
        }

        fn decode_record<D: json_decode::Destination>(parser: &mut norito::json::Parser<'_>, destination: &D) -> Result<PipelineValidityPolicyV1, D::Error> {
            $(let mut $field = None;)+
            let mut object = norito::json::MapVisitor::new(parser)?;
            while let Some(key) = destination.key(&mut object)? {
                match json_decode::key_text(&key) {
                    $(stringify!($field) => {
                        if $field.is_some() {
                            return Err(json_decode::invalid(concat!("duplicate pipeline policy field: ", stringify!($field))).into());
                        }
                        $field = Some(object.parse_value_with_parser_typed(|parser| {
                            <$type as norito::json::JsonDeserialize>::json_deserialize(parser).map_err(D::Error::from)
                        })?);
                    },)+
                    _ => return Err(json_decode::invalid("unknown pipeline policy field").into()),
                }
            }
            object.finish()?;
            Ok(PipelineValidityPolicyV1 {
                $($field: $field.ok_or_else(|| json_decode::invalid(concat!("missing pipeline policy field: ", stringify!($field))))?,)+
            })
        }

        impl PipelineValidityPolicyV1 {
            /// Names of the policy fields, in declaration order.
            pub const FIELD_NAMES: &'static [&'static str] = &[ $( stringify!($field) ),+ ];

            /// Names of the fields whose values differ between `self` and `other`.
            #[must_use]
            pub fn differing_fields(&self, other: &Self) -> Vec<&'static str> {
                let mut out = Vec::new();
                $(
                    if self.$field != other.$field {
                        out.push(stringify!($field));
                    }
                )+
                out
            }

            /// Replace the value of the field `name` by another value that keeps
            /// the policy valid, derived from `salt`.
            ///
            /// Returns `false`, leaving the policy untouched, when `name` is not a
            /// policy field. Coverage tests use it to visit every field without
            /// naming them, so a new field cannot be skipped.
            #[cfg(any(test, feature = "test-fixtures"))]
            pub fn perturb_field(&mut self, name: &str, salt: u32) -> bool {
                $(
                    if name == stringify!($field) {
                        for value in perturb::PolicyField::others(&self.$field, salt) {
                            let mut candidate = *self;
                            candidate.$field = value;
                            if candidate != *self && candidate.validate().is_ok() {
                                *self = candidate;
                                return true;
                            }
                        }
                        return false;
                    }
                )+
                false
            }
        }
    };
}

pipeline_policy! {
    /// Whether access sets are derived by the dynamic prepass. Both modes are
    /// complete; the chain selects one so every validator schedules alike.
    dynamic_prepass: bool,
    /// Instructions one transaction's overlay may retain (0 = unlimited).
    overlay_max_instructions: u64,
    /// Serialized bytes one transaction's overlay may retain (0 = unlimited).
    overlay_max_bytes: u64,
    /// Instructions applied per overlay chunk; at least 1.
    overlay_chunk_instructions: u64,
    /// Largest cycle budget a contract program may declare; non-zero.
    ivm_max_cycles_upper_bound: u64,
    /// Decoded instructions accepted for one program (0 = unlimited).
    ivm_max_decoded_instructions: u64,
    /// Decoded bytes accepted for one program (0 = unlimited).
    ivm_max_decoded_bytes: u64,
    /// Transactions the quarantine lane admits per block (0 = lane disabled).
    quarantine_max_txs_per_block: u64,
    /// Cycle cap of one quarantine-lane transaction (0 = unlimited).
    quarantine_tx_max_cycles: u64,
    /// Largest fetch size of one query inside the IVM (0 is read as 1).
    query_max_fetch_size: u64,
    /// Gas units required before a stored cursor may be used (0 = none).
    query_stored_min_gas_units: u64,
    /// AMX execution budget of one dataspace, in milliseconds.
    amx_per_dataspace_budget_ms: u64,
    /// AMX execution budget of a group across dataspaces, in milliseconds.
    amx_group_budget_ms: u64,
    /// Nanoseconds one instruction is counted as in the AMX budget.
    amx_per_instruction_ns: u64,
    /// Nanoseconds one memory access is counted as in the AMX budget.
    amx_per_memory_access_ns: u64,
    /// Nanoseconds one syscall is counted as in the AMX budget.
    amx_per_syscall_ns: u64,
}

fn non_zero(value: u64, field: &'static str) -> Result<(), PipelineValidityPolicyError> {
    if value == 0 {
        return Err(PipelineValidityPolicyError::Zero(field));
    }
    Ok(())
}

fn count_field(value: u64, field: &'static str) -> Result<(), PipelineValidityPolicyError> {
    if value > MAX_COUNT_FIELD {
        return Err(PipelineValidityPolicyError::OutOfRange(field));
    }
    Ok(())
}

impl PipelineValidityPolicyV1 {
    /// Identifier of the committed custom parameter that carries the policy.
    pub const PARAMETER_ID_STR: &'static str = "pipeline_validity_policy_v1";

    /// The [`CustomParameterId`] of the committed policy.
    ///
    /// # Panics
    ///
    /// Never: the identifier is a valid parameter name.
    #[must_use]
    pub fn parameter_id() -> CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("the pipeline validity policy parameter identifier is a valid name")
    }

    /// The policy of a chain that installs none: the protocol defaults of this
    /// release, identical in every binary.
    #[must_use]
    pub const fn protocol_default() -> Self {
        Self {
            dynamic_prepass: true,
            overlay_max_instructions: 0,
            overlay_max_bytes: 0,
            overlay_chunk_instructions: 256,
            ivm_max_cycles_upper_bound: 1_000_000,
            ivm_max_decoded_instructions: 1_048_576,
            ivm_max_decoded_bytes: 4 * 1024 * 1024,
            quarantine_max_txs_per_block: 0,
            quarantine_tx_max_cycles: 0,
            query_max_fetch_size: 500,
            query_stored_min_gas_units: 0,
            amx_per_dataspace_budget_ms: 30,
            amx_group_budget_ms: 140,
            amx_per_instruction_ns: 50,
            amx_per_memory_access_ns: 80,
            amx_per_syscall_ns: 120,
        }
    }

    /// Check every rule a committed policy must satisfy.
    ///
    /// The decision uses the policy value alone and fixed protocol constants,
    /// so every validator on every supported target reaches the same result.
    ///
    /// Rules: the overlay chunk size and the cycle upper bound are positive;
    /// every field that counts in-memory items
    /// (overlay instructions and chunk size, quarantine transactions) is at
    /// most [`MAX_COUNT_FIELD`]. Every other value is admissible: zero means
    /// "unlimited" or "disabled" as documented on the field, and the two AMX
    /// budgets are independent checks. Limits may shrink while these rules hold.
    ///
    /// # Errors
    ///
    /// Returns the first rule that fails, in the fixed order of this function.
    pub fn validate(&self) -> Result<(), PipelineValidityPolicyError> {
        non_zero(
            self.overlay_chunk_instructions,
            "overlay_chunk_instructions",
        )?;
        non_zero(
            self.ivm_max_cycles_upper_bound,
            "ivm_max_cycles_upper_bound",
        )?;
        count_field(self.overlay_max_instructions, "overlay_max_instructions")?;
        count_field(
            self.overlay_chunk_instructions,
            "overlay_chunk_instructions",
        )?;
        count_field(
            self.quarantine_max_txs_per_block,
            "quarantine_max_txs_per_block",
        )?;
        Ok(())
    }

    /// Wrap the policy as the committed custom parameter.
    #[must_use]
    pub fn into_custom_parameter(self) -> CustomParameter {
        CustomParameter::new(Self::parameter_id(), Json::new(self))
    }

    /// Decode and validate the policy carried by `custom`.
    ///
    /// Returns `None` when `custom` is another parameter.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is not the exact V1 policy or a
    /// value violates a rule of [`Self::validate`]. Every validator derives
    /// the same error from the same committed bytes.
    pub fn from_custom_parameter(
        custom: &CustomParameter,
    ) -> Option<Result<Self, PipelineValidityPolicyError>> {
        if custom.id() != &Self::parameter_id() {
            return None;
        }
        Some(Self::from_payload(custom.payload()))
    }

    /// Decode and validate a policy payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is not the exact V1 policy or a
    /// value violates a rule of [`Self::validate`].
    pub fn from_payload(payload: &Json) -> Result<Self, PipelineValidityPolicyError> {
        let policy = payload
            .try_into_any_norito::<Self>()
            .map_err(|error| PipelineValidityPolicyError::Malformed(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }
}

/// Other values of a policy field, for coverage tests.
#[cfg(any(test, feature = "test-fixtures"))]
mod perturb {
    /// A policy field type that can produce values other than its current one.
    pub(super) trait PolicyField: Sized {
        /// Candidate replacement values, most preferred first.
        fn others(&self, salt: u32) -> Vec<Self>;
    }

    impl PolicyField for bool {
        fn others(&self, _salt: u32) -> Vec<Self> {
            vec![!*self]
        }
    }

    impl PolicyField for u64 {
        fn others(&self, salt: u32) -> Vec<Self> {
            let step = u64::from(salt.max(1));
            [
                self.checked_add(step),
                self.checked_sub(step),
                self.checked_add(1),
                self.checked_sub(1),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_default_is_valid_and_round_trips_through_the_parameter() {
        let policy = PipelineValidityPolicyV1::protocol_default();
        policy.validate().expect("the protocol default is valid");
        let custom = policy.into_custom_parameter();
        assert_eq!(custom.id(), &PipelineValidityPolicyV1::parameter_id());
        assert_eq!(
            PipelineValidityPolicyV1::from_custom_parameter(&custom),
            Some(Ok(policy))
        );
        assert_eq!(
            PipelineValidityPolicyV1::from_payload(custom.payload()),
            Ok(policy)
        );
        let other = CustomParameter::new(
            "another_parameter".parse().expect("valid name"),
            Json::new(1_u32),
        );
        assert!(PipelineValidityPolicyV1::from_custom_parameter(&other).is_none());
        // The binary codec round-trips too.
        let bytes = policy.encode();
        assert_eq!(
            PipelineValidityPolicyV1::decode(&mut bytes.as_slice()).expect("decodes"),
            policy
        );
    }

    #[test]
    fn field_names_match_the_committed_payload() {
        let names = PipelineValidityPolicyV1::FIELD_NAMES;
        assert_eq!(names.len(), 16);
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        let value = norito::json::to_value(&PipelineValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        let mut payload_names: Vec<String> = value
            .as_object()
            .expect("a policy object")
            .keys()
            .cloned()
            .collect();
        payload_names.sort();
        let mut sorted: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        sorted.sort();
        assert_eq!(payload_names, sorted);
    }

    #[test]
    fn every_field_is_perturbed_into_another_valid_policy() {
        let default = PipelineValidityPolicyV1::protocol_default();
        let mut all_changed = default;
        for (index, name) in PipelineValidityPolicyV1::FIELD_NAMES.iter().enumerate() {
            let salt = u32::try_from(index).expect("field count fits") + 1;
            let mut single = default;
            assert!(single.perturb_field(name, salt), "{name} is perturbed");
            assert_eq!(single.differing_fields(&default), [*name]);
            single.validate().expect("a perturbed policy stays valid");
            assert!(all_changed.perturb_field(name, salt), "{name} in sequence");
        }
        all_changed.validate().expect("valid");
        assert_eq!(all_changed.differing_fields(&default).len(), 16);
        let mut untouched = default;
        assert!(!untouched.perturb_field("unknown", 1));
        assert_eq!(untouched, default);
    }

    #[test]
    fn rules_reject_identically_on_every_target() {
        type Edit = fn(&mut PipelineValidityPolicyV1);
        let default = PipelineValidityPolicyV1::protocol_default;
        let zero: [(&str, Edit); 2] = [
            ("overlay_chunk_instructions", |policy| {
                policy.overlay_chunk_instructions = 0;
            }),
            ("ivm_max_cycles_upper_bound", |policy| {
                policy.ivm_max_cycles_upper_bound = 0;
            }),
        ];
        for (field, edit) in zero {
            let mut policy = default();
            edit(&mut policy);
            assert_eq!(
                policy.validate(),
                Err(PipelineValidityPolicyError::Zero(field))
            );
        }
        // A count above the fixed protocol maximum is rejected by its value,
        // not by the pointer width of the validator: 2^32 fits a 64-bit `usize`.
        let over: [(&str, Edit); 3] = [
            ("overlay_max_instructions", |policy| {
                policy.overlay_max_instructions = MAX_COUNT_FIELD + 1;
            }),
            ("overlay_chunk_instructions", |policy| {
                policy.overlay_chunk_instructions = MAX_COUNT_FIELD + 1;
            }),
            ("quarantine_max_txs_per_block", |policy| {
                policy.quarantine_max_txs_per_block = MAX_COUNT_FIELD + 1;
            }),
        ];
        for (field, edit) in over {
            let mut policy = default();
            edit(&mut policy);
            assert_eq!(
                policy.validate(),
                Err(PipelineValidityPolicyError::OutOfRange(field))
            );
        }
        let mut boundary = default();
        boundary.overlay_max_instructions = MAX_COUNT_FIELD;
        boundary.quarantine_max_txs_per_block = MAX_COUNT_FIELD;
        boundary.validate().expect("the maximum itself is accepted");
        // The two AMX budgets are independent checks: neither bounds the other.
        let mut amx = default();
        amx.amx_per_dataspace_budget_ms = amx.amx_group_budget_ms + 1;
        amx.validate().expect("independent budgets");
        // Limits may shrink while the rules hold.
        let mut smaller = default();
        smaller.ivm_max_cycles_upper_bound = 1;
        smaller.ivm_max_decoded_bytes = 1;
        smaller.query_max_fetch_size = 0;
        smaller.overlay_max_instructions = 1;
        smaller.validate().expect("a coherent smaller policy");
    }

    #[test]
    fn payload_with_an_unknown_or_missing_field_is_malformed() {
        let mut value = norito::json::to_value(&PipelineValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        value
            .as_object_mut()
            .expect("a policy object")
            .insert("per_unknown".to_owned(), norito::json::Value::from(1_u64));
        assert!(matches!(
            PipelineValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(PipelineValidityPolicyError::Malformed(_))
        ));
        let mut value = norito::json::to_value(&PipelineValidityPolicyV1::protocol_default())
            .expect("the policy serializes");
        value
            .as_object_mut()
            .expect("a policy object")
            .remove("amx_per_syscall_ns");
        assert!(matches!(
            PipelineValidityPolicyV1::from_payload(&Json::from(&value)),
            Err(PipelineValidityPolicyError::Malformed(_))
        ));
        assert!(matches!(
            PipelineValidityPolicyV1::from_payload(&Json::new("not a policy")),
            Err(PipelineValidityPolicyError::Malformed(_))
        ));
    }
}
