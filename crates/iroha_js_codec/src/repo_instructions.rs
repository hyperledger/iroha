//! Exact first-release JSON contract for the boxed native repo lifecycle.
//!
//! Repo instructions travel only as the registered outer `RepoInstructionBox`
//! (`iroha.repo`); the leaf wire identifiers stay unregistered. The JSON
//! envelope mirrors that box with exactly one variant:
//! `{"Repo": {"Initiate": RepoIsi}}`, `{"Repo": {"Reverse": ReverseRepoIsi}}`
//! or `{"Repo": {"MarginCall": RepoMarginCallIsi}}`. Each payload must be
//! exactly its canonical model JSON, including every governance term, so the
//! decoded proposal yields the same consent hashes as the signed one.

use iroha_data_model::isi::{
    Instruction, InstructionBox,
    repo::{RepoInstructionBox, RepoIsi, RepoMarginCallIsi, ReverseRepoIsi},
};
use norito::json::{self, Value};

use crate::{CodecError, CodecErrorKind, CodecResult};

const ENVELOPE: &str = "Repo";

fn invalid(reason: impl Into<String>) -> CodecError {
    CodecError::new(CodecErrorKind::InvalidArgument, reason)
}

/// Return whether `instruction` is the boxed repo lifecycle owned by this contract.
pub fn is_repo_instruction(instruction: &InstructionBox) -> bool {
    let typed: &dyn Instruction = &**instruction;
    typed.as_any().is::<RepoInstructionBox>()
}

/// Admit the exact `Repo` envelope, or return `None` for other envelopes.
pub fn from_json(value: &Value) -> Option<CodecResult<InstructionBox>> {
    let Value::Object(envelope) = value else {
        return None;
    };
    let payload = envelope.get(ENVELOPE)?;
    Some((|| {
        crate::require_exact_json_fields(envelope, &[ENVELOPE], "repo instruction envelope")?;
        let Value::Object(variants) = payload else {
            return Err(invalid(
                "Repo payload must be an object with exactly one variant",
            ));
        };
        let mut entries = variants.iter();
        let (Some((variant, body)), None) = (entries.next(), entries.next()) else {
            return Err(invalid("Repo payload must contain exactly one variant"));
        };
        let boxed = match variant.as_str() {
            "Initiate" => RepoInstructionBox::from(crate::strict_typed_instruction::<RepoIsi>(
                body,
                "Repo.Initiate",
            )?),
            "Reverse" => RepoInstructionBox::Reverse(crate::strict_typed_instruction::<
                ReverseRepoIsi,
            >(body, "Repo.Reverse")?),
            "MarginCall" => RepoInstructionBox::MarginCall(crate::strict_typed_instruction::<
                RepoMarginCallIsi,
            >(body, "Repo.MarginCall")?),
            other => return Err(invalid(format!("unsupported Repo variant `{other}`"))),
        };
        Ok(InstructionBox::from(boxed))
    })())
}

/// Render the boxed repo lifecycle through its exact JSON envelope.
pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<Value>> {
    let typed: &dyn Instruction = &**instruction;
    let boxed = typed.as_any().downcast_ref::<RepoInstructionBox>()?;
    Some((|| {
        let (variant, payload) = match boxed {
            RepoInstructionBox::Initiate(isi) => (
                "Initiate",
                json::to_value(isi.as_ref()).map_err(crate::codec_error)?,
            ),
            RepoInstructionBox::Reverse(isi) => {
                ("Reverse", json::to_value(isi).map_err(crate::codec_error)?)
            }
            RepoInstructionBox::MarginCall(isi) => (
                "MarginCall",
                json::to_value(isi).map_err(crate::codec_error)?,
            ),
        };
        Ok(crate::instruction_envelope(
            ENVELOPE,
            crate::instruction_envelope(variant, payload),
        ))
    })())
}

#[cfg(test)]
#[path = "repo_instruction_tests.rs"]
mod tests;
