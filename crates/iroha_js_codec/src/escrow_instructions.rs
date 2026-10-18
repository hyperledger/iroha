//! Exact first-release JSON contracts for native conditional escrow instructions.
//!
//! `OpenConditionalEscrow`, `AttestEscrowCondition` and `ExpireConditionalEscrow`
//! each use one closed envelope whose payload must equal the model's canonical
//! JSON, including every condition and evidence field. The typed model owns the
//! Norito payload; generic base64 instruction literals cannot bypass these
//! contracts.

use iroha_data_model::isi::{
    Instruction, InstructionBox,
    escrow::{AttestEscrowCondition, ExpireConditionalEscrow, OpenConditionalEscrow},
};
use norito::json::{self, Value};

use crate::{CodecError, CodecResult};

macro_rules! escrow_contracts {
    ($($name:literal => $ty:ty),+ $(,)?) => {
        /// Return whether `instruction` is a conditional escrow instruction owned here.
        pub fn is_conditional_escrow_instruction(instruction: &InstructionBox) -> bool {
            let typed: &dyn Instruction = &**instruction;
            let any = typed.as_any();
            $(any.is::<$ty>())||+
        }

        /// Admit one exact conditional escrow envelope, or return `None`.
        pub fn from_json(value: &Value) -> Option<CodecResult<InstructionBox>> {
            let Value::Object(envelope) = value else { return None; };
            $(if let Some(payload) = envelope.get($name) {
                return Some((|| {
                    crate::require_exact_json_fields(
                        envelope,
                        &[$name],
                        "conditional escrow instruction envelope",
                    )?;
                    let typed: $ty = crate::strict_typed_instruction(payload, $name)?;
                    Ok(typed.into())
                })());
            })+
            None
        }

        /// Render a conditional escrow instruction through its exact envelope.
        pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<Value>> {
            let typed: &dyn Instruction = &**instruction;
            let any = typed.as_any();
            $(if let Some(value) = any.downcast_ref::<$ty>() {
                return Some((|| {
                    let payload = json::to_value(value).map_err(crate::codec_error)?;
                    let reconstructed: $ty = crate::strict_typed_instruction(&payload, $name)?;
                    if norito::encode_canonical(value).map_err(crate::codec_error)?
                        != norito::encode_canonical(&reconstructed).map_err(crate::codec_error)?
                    {
                        return Err(CodecError::failure(
                            "conditional escrow JSON changes canonical Norito bytes",
                        ));
                    }
                    Ok(crate::instruction_envelope($name, payload))
                })());
            })+
            None
        }
    };
}

escrow_contracts! {
    "OpenConditionalEscrow" => OpenConditionalEscrow,
    "AttestEscrowCondition" => AttestEscrowCondition,
    "ExpireConditionalEscrow" => ExpireConditionalEscrow,
}

#[cfg(test)]
#[path = "escrow_instruction_tests.rs"]
mod tests;
