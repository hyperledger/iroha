//! Exact native JSON admission for declarative alias setup (`EnsureAlias`).
//!
//! `EnsureAlias` owns its JSON through the native model derive; this module admits
//! only that canonical spelling. It also admits planner-issued `(wire_id, frame)`
//! pairs, such as `/v1/aliases/setup/plan` instructions, after an exact decode and
//! re-frame check. Execution still validates authority, quotes and quote guards.

use iroha_data_model::isi::{
    InstructionBox, alias_setup::EnsureAlias, decode_instruction_from_pair,
    framed_instruction_payload,
};
use norito::json::{self, Value};

use crate::{CodecError, CodecErrorKind, CodecResult, codec_error};

fn invalid(message: impl Into<String>) -> CodecError {
    CodecError::new(CodecErrorKind::InvalidArgument, message)
}

/// Return whether `instruction` is the declarative alias setup instruction.
pub fn is_alias_setup_instruction(instruction: &InstructionBox) -> bool {
    instruction.as_any().is::<EnsureAlias>()
}

/// Admit one exact `{"EnsureAlias": ...}` envelope.
pub fn from_json(value: &Value) -> Option<CodecResult<InstructionBox>> {
    let payload = value.as_object()?.get("EnsureAlias")?;
    Some((|| {
        crate::exact_json_object_fields(value, &["EnsureAlias"], "alias setup instruction")?;
        let ensure: EnsureAlias = json::from_value(payload.clone())
            .map_err(|error| invalid(format!("EnsureAlias: {error}")))?;
        if json::to_value(&ensure).map_err(codec_error)? != *payload {
            return Err(invalid(
                "EnsureAlias must contain exactly its canonical typed JSON fields and values",
            ));
        }
        Ok(ensure.into())
    })())
}

/// Render `EnsureAlias` through its native JSON contract.
pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<Value>> {
    instruction
        .as_any()
        .downcast_ref::<EnsureAlias>()
        .map(|ensure| {
            Ok(crate::instruction_envelope(
                "EnsureAlias",
                json::to_value(ensure).map_err(codec_error)?,
            ))
        })
}

/// Convert one exact `(wire_id, framed_payload)` instruction pair into strict instruction JSON.
///
/// The frame must decode under exactly `wire_id`, and re-framing the decoded instruction must
/// reproduce the same identifier and bytes. The instruction must also have a strict JSON
/// contract, so the result can be passed back to [`crate::value_to_instruction`].
///
/// # Errors
/// Returns an error for an unknown identifier, a noncanonical frame, or an instruction without
/// a JSON contract.
pub fn instruction_json_from_wire_pair(wire_id: &str, framed_payload: &[u8]) -> CodecResult<Value> {
    let instruction = decode_instruction_from_pair(wire_id, framed_payload).map_err(|error| {
        invalid(format!(
            "instruction frame `{wire_id}` does not decode: {error}"
        ))
    })?;
    match framed_instruction_payload(&instruction) {
        Some((reframed_id, reframed)) if reframed_id == wire_id && reframed == framed_payload => {}
        _ => {
            return Err(invalid(format!(
                "instruction frame `{wire_id}` is not the canonical frame of its decoded instruction"
            )));
        }
    }
    let value = crate::instruction_to_json_value(&instruction)?;
    if crate::value_to_instruction(value.clone())? != instruction {
        return Err(invalid(format!(
            "instruction frame `{wire_id}` does not round-trip through its JSON contract"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::{AccountId, address::ChainDiscriminantGuard},
        alias_setup::{
            AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1, AliasQuoteGuardV1,
            ResolvedDomainV1,
        },
        asset::AssetDefinitionId,
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_primitives::numeric::Quantity;

    fn ensure() -> EnsureAlias {
        let owner = AccountId::new(
            KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519)
                .expect("key")
                .public_key()
                .clone(),
        );
        EnsureAlias::new(
            AliasIntentV1::Domain(AliasDomainIntentV1 {
                domain: ResolvedDomainV1 {
                    canonical_name: DomainId::try_new("bondpoc", "universal").expect("domain"),
                    dataspace_id: DataSpaceId::new(0),
                },
                owner,
            }),
            AliasLeaseAcquisitionV1 {
                term_years: 1,
                pricing_class_hint: None,
            },
            AliasQuoteGuardV1 {
                expected_policy_version: 1,
                expected_payment_asset: "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
                    .parse::<AssetDefinitionId>()
                    .expect("asset"),
                max_amount: Quantity::from(100_u32),
                valid_until_ms: 1_900_000_000_000,
            },
        )
    }

    #[test]
    fn ensure_alias_json_and_planner_frames_roundtrip_exactly() {
        let _network = ChainDiscriminantGuard::enter(369);
        let instruction = InstructionBox::from(ensure());
        let value = crate::instruction_to_json_value(&instruction).expect("render");
        let payload = &value["EnsureAlias"];
        assert_eq!(payload["intent"]["kind"], Value::String("domain".into()));
        assert_eq!(
            payload["intent"]["intent"]["domain"]["canonical_name"],
            Value::String("bondpoc.universal".into())
        );
        assert_eq!(payload["acquisition"]["pricing_class_hint"], Value::Null);
        assert_eq!(
            payload["quote_guard"]["max_amount"],
            Value::String("100".into())
        );
        assert_eq!(
            crate::value_to_instruction(value.clone()).expect("admit"),
            instruction
        );

        let (wire_id, frame) = framed_instruction_payload(&instruction).expect("frame");
        assert_eq!(wire_id, EnsureAlias::WIRE_ID);
        assert_eq!(
            instruction_json_from_wire_pair(wire_id, &frame).expect("wire pair"),
            value
        );
        assert!(instruction_json_from_wire_pair("iroha.alias.lease.renew", &frame).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(instruction_json_from_wire_pair(wire_id, &trailing).is_err());
    }

    #[test]
    fn ensure_alias_rejects_alternate_spellings_and_base64_bypass() {
        let _network = ChainDiscriminantGuard::enter(369);
        let value =
            crate::instruction_to_json_value(&InstructionBox::from(ensure())).expect("render");
        let mut missing_hint = value.clone();
        missing_hint
            .as_object_mut()
            .and_then(|envelope| envelope.get_mut("EnsureAlias"))
            .and_then(Value::as_object_mut)
            .and_then(|payload| payload.get_mut("acquisition"))
            .and_then(Value::as_object_mut)
            .expect("acquisition")
            .remove("pricing_class_hint");
        assert!(crate::value_to_instruction(missing_hint).is_err());
        let mut extra = value;
        extra
            .as_object_mut()
            .expect("envelope")
            .insert("Log".into(), Value::Null);
        assert!(crate::value_to_instruction(extra).is_err());
        let frame = norito::encode_canonical(&InstructionBox::from(ensure())).expect("frame");
        assert!(crate::value_to_instruction(Value::String(STANDARD.encode(frame))).is_err());
    }
}
