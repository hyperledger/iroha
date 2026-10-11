//! Module containing errors that can occur in transaction lifecycle.
pub use self::model::*;
use crate::{
    ValidationFail,
    isi::{Instruction, InstructionBox},
};

use base64::Engine as _;

use base64::engine::general_purpose::STANDARD;
use derive_more::Display;
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    string::String,
};
#[model]
mod model {
    use super::*;
    /// Error which indicates max instruction count was reached
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::error::model::TransactionLimitError")]
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    #[repr(transparent)]
    // SAFETY: `TransactionLimitError` has no trap representation in `String`
    pub struct TransactionLimitError {
        /// Reason why transaction exceeds limits
        pub reason: String,
    }
    /// Transaction was rejected because of one of its instructions failing.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::error::model::InstructionExecutionFail")]
    #[derive(
        Getters,
        Debug,
        Clone,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        derive_more::Constructor,
    )]
    pub struct InstructionExecutionFail {
        /// Instruction for which execution failed
        #[getset(get = "pub")]
        pub instruction: InstructionBox,
        /// Error which happened during execution
        pub reason: String,
    }
    /// Possible reasons for trigger-specific execution failure.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::transaction::error::model::TriggerExecutionFail")]
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    #[repr(u32)]
    pub enum TriggerExecutionFail {
        /// Exceeded maximum depth for synchronous trigger execution or chained data triggers.
        MaxDepthExceeded,
    }

    impl norito::json::JsonSerialize for TriggerExecutionFail {
        fn json_serialize(&self, out: &mut String) {
            let label = match self {
                TriggerExecutionFail::MaxDepthExceeded => "MaxDepthExceeded",
            };
            norito::json::write_json_string(label, out);
        }
        fn json_serialize_to(
            &self,
            out: &mut dyn norito::json::JsonWriteSink,
        ) -> Result<(), norito::json::BoundedJsonError> {
            norito::json::write_json_string_to("MaxDepthExceeded", out)
        }
    }

    impl norito::json::JsonDeserialize for TriggerExecutionFail {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> Result<Self, norito::json::Error> {
            let value = parser.parse_string()?;
            match value.as_str() {
                "MaxDepthExceeded" => Ok(TriggerExecutionFail::MaxDepthExceeded),
                other => Err(norito::json::Error::UnknownField {
                    field: other.to_owned(),
                }),
            }
        }
    }
    /// The reason for rejecting transaction which happened because of transaction.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_data_model::transaction::error::model::TransactionRejectionReason"
    )]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        displaydoc::Display,
        FromVariant,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[ignore_extra_doc_attributes]
    #[derive(thiserror::Error)]
    pub enum TransactionRejectionReason {
        /// Account does not exist
        AccountDoesNotExist(
            #[skip_from]
            #[skip_try_from]
            #[source]
            crate::query::error::FindError,
        ),
        /// Failed to validate transaction limits
        ///
        /// e.g. number of instructions
        LimitCheck(#[source] TransactionLimitError),
        /// Validation failed
        Validation(#[source] ValidationFail),
        /// Failure in instruction execution
        ///
        /// In practice should be fully replaced by [`crate::ValidationFail::InstructionFailed`]
        /// and will be removed soon.
        InstructionExecution(#[source] InstructionExecutionFail),
        /// Execution of a time trigger or an invoked data trigger failed.
        TriggerExecution(#[source] TriggerExecutionFail),
    }
}

impl norito::json::JsonSerialize for TransactionRejectionReason {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_canonical_base64_json(self, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_canonical_base64_json_to(self, out)
    }
}

impl norito::json::JsonDeserialize for TransactionRejectionReason {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let encoded = parser.parse_string()?;
        let bytes = STANDARD
            .decode(encoded.as_str())
            .map_err(|err| norito::json::Error::Message(err.to_string()))?;
        norito::decode_canonical::<TransactionRejectionReason>(&bytes)
            .map_err(|err| norito::json::Error::Message(err.to_string()))
    }
}
impl PartialEq for InstructionExecutionFail {
    fn eq(&self, other: &Self) -> bool {
        Instruction::id(&*self.instruction) == Instruction::id(&*other.instruction)
            && self.instruction.dyn_encode() == other.instruction.dyn_encode()
            && self.reason == other.reason
    }
}
impl Display for InstructionExecutionFail {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Failed to execute instruction: {}", self.reason)
    }
}

impl norito::json::FastJsonWrite for TransactionLimitError {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.reason, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.reason, out)
    }
}

impl norito::json::JsonDeserialize for TransactionLimitError {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let reason = parser.parse_string()?;
        Ok(Self { reason })
    }
}

impl std::error::Error for TransactionLimitError {}
impl std::error::Error for InstructionExecutionFail {}
impl std::error::Error for TriggerExecutionFail {}
pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this module.
    pub use super::{InstructionExecutionFail, TransactionRejectionReason, TriggerExecutionFail};
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Level, isi::Log};

    #[test]
    fn rejection_reason_json_is_canonical_and_ambient_independent() {
        fn assert_bounded<T: norito::json::JsonSerialize>(value: &T) {
            let expected = norito::json::to_json(value).expect("serialize ordinary JSON");
            assert_eq!(
                norito::json::to_json_bounded(value, expected.len()).expect("exact JSON bound"),
                expected
            );
            assert_eq!(
                norito::json::to_json_bounded(value, expected.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
        }
        let reason = TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "deterministic failure".to_owned(),
        ));
        let canonical_json =
            norito::json::to_json(&reason).expect("encode canonical rejection JSON");
        assert_eq!(
            norito::json::to_json_bounded(&reason, canonical_json.len())
                .expect("encode rejection at exact JSON bound"),
            canonical_json
        );
        assert_eq!(
            norito::json::to_json_bounded(&reason, canonical_json.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            assert_eq!(
                norito::json::to_json(&reason)
                    .expect("encode rejection JSON under alternate ambient layout"),
                canonical_json
            );
        }
        let alternate_frame = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&reason).expect("encode alternate-layout rejection reason")
        };
        let alternate_json = norito::json::to_json(&STANDARD.encode(alternate_frame))
            .expect("encode alternate rejection frame as JSON string");
        norito::json::from_json::<TransactionRejectionReason>(&alternate_json)
            .expect_err("alternate-layout rejection JSON must be rejected");
        assert_bounded(&TriggerExecutionFail::MaxDepthExceeded);
        assert_bounded(&TransactionLimitError {
            reason: "limit".to_owned(),
        });
    }
    #[test]
    fn instruction_execution_fail_equality() {
        let log = Log::new(Level::INFO, "log".to_string());
        let fail1 = InstructionExecutionFail {
            instruction: InstructionBox::from(log.clone()),
            reason: "reason".to_string(),
        };
        let fail2 = InstructionExecutionFail {
            instruction: InstructionBox::from(log),
            reason: "reason".to_string(),
        };
        assert_eq!(fail1, fail2);
        let different_instruction = InstructionExecutionFail {
            instruction: InstructionBox::from(Log::new(Level::INFO, "other".to_string())),
            reason: "reason".to_string(),
        };
        assert_ne!(fail1, different_instruction);
        let different_reason = InstructionExecutionFail {
            instruction: fail1.instruction.clone(),
            reason: "other".to_string(),
        };
        assert_ne!(fail1, different_reason);
    }
}
