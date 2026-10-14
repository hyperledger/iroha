//! Exact native JSON admission for log instructions, including signed fee markers.
use crate::{CodecError, CodecErrorKind, CodecResult, codec_error, exact_json_object_fields};
use iroha_data_model::{
    Level,
    isi::{InstructionBox, Log},
};
use norito::json;

/// Decode an exact native Log envelope; other instruction kinds return `None`.
/// Malformed Log fields or noncanonical typed values return a codec error.
pub fn from_json(value: &json::Value) -> Option<CodecResult<InstructionBox>> {
    let payload = value.as_object()?.get("Log")?;
    Some((|| {
        exact_json_object_fields(value, &["Log"], "log instruction")?;
        exact_json_object_fields(payload, &["level", "msg"], "Log")?;
        let fields = payload.as_object().expect("validated log object");
        let level: Level = json::from_value(fields["level"].clone()).map_err(codec_error)?;
        let msg: String = json::from_value(fields["msg"].clone()).map_err(codec_error)?;
        let instruction = Log::new(level, msg);
        if json::to_value(&instruction).map_err(codec_error)? != *payload {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Log must contain exactly its canonical typed JSON fields and values",
            ));
        }
        Ok(instruction.into())
    })())
}

/// Encode a native Log envelope; other instruction kinds return `None`.
/// Returns a codec error if the typed Log cannot be encoded as Norito JSON.
pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<json::Value>> {
    instruction.as_any().downcast_ref::<Log>().map(|log| {
        Ok(crate::instruction_envelope(
            "Log",
            json::to_value(log).map_err(codec_error)?,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::Level;

    #[test]
    fn log_admission_roundtrips_exact_native_fields_and_rejects_alternatives() {
        let original: InstructionBox = Log::new(Level::TRACE, "reviewed marker".into()).into();
        let value = crate::instruction_to_json_value(&original).unwrap();
        assert_eq!(crate::value_to_instruction(value).unwrap(), original);
        for input in [
            r#"{"Log":{"level":"trace","msg":"reviewed marker"}}"#,
            r#"{"Log":{"level":0,"msg":"reviewed marker"}}"#,
            r#"{"Log":{"level":"TRACE","msg":1}}"#,
            r#"{"Log":{"level":"TRACE"}}"#,
            r#"{"Log":{"msg":"reviewed marker"}}"#,
            r#"{"Log":null}"#,
            r#"{"Log":{"level":"TRACE","message":"reviewed marker"}}"#,
            r#"{"Log":{"level":"TRACE","msg":"reviewed marker","extra":true}}"#,
            r#"{"Log":{"level":"TRACE","msg":"reviewed marker"},"extra":true}"#,
        ] {
            assert!(crate::instruction_from_json(input).is_err(), "{input}");
        }
    }
}
