//! Exact first-release JSON contract for the boxed native bond-servicing kernel.
//!
//! Bond instructions travel only as the registered outer `BondInstructionBox`
//! (`iroha.bond`); the leaf wire identifiers stay unregistered. The JSON
//! envelope mirrors that box with exactly one variant:
//! `{"Bond": {"Register": RegisterBond}}`, `"RecordCashflow"`, `"FundCashflow"`,
//! `"ClaimCashflow"`, `"CloseCashflow"`, `"Call"`, `"DeclareDefault"`,
//! `"ReplacePayingAgent"` or `"RetireTreasuryUnits"`. Each
//! payload must be exactly its canonical model JSON (`snake_case` fields, canonical
//! quantities, lowercase 32-byte hex digests), so the decoded instruction is the
//! signed one. Terms validation stays with Core (`specs/finance/bond_ops.md`);
//! this contract only admits the exact shape.

use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    asset::AssetDefinitionId,
    bond::bond_vault_account_id,
    isi::{Instruction, InstructionBox, bond::BondInstructionBox},
};
use norito::json::{self, Value};

use crate::{CodecError, CodecErrorKind, CodecResult};

const ENVELOPE: &str = "Bond";

fn invalid(reason: impl Into<String>) -> CodecError {
    CodecError::new(CodecErrorKind::InvalidArgument, reason)
}

/// Admit one leaf payload that must equal its canonical model JSON.
fn leaf<T>(body: &Value, variant: &str) -> CodecResult<T>
where
    T: json::JsonDeserialize + json::JsonSerialize,
{
    crate::strict_typed_instruction(body, &format!("{ENVELOPE}.{variant}"))
}

/// Return whether `instruction` is the boxed bond kernel owned by this contract.
pub fn is_bond_instruction(instruction: &InstructionBox) -> bool {
    let typed: &dyn Instruction = &**instruction;
    typed.as_any().is::<BondInstructionBox>()
}

/// Admit the exact `Bond` envelope, or return `None` for other envelopes.
pub fn from_json(value: &Value) -> Option<CodecResult<InstructionBox>> {
    let Value::Object(envelope) = value else {
        return None;
    };
    let payload = envelope.get(ENVELOPE)?;
    Some((|| {
        crate::require_exact_json_fields(envelope, &[ENVELOPE], "bond instruction envelope")?;
        let Value::Object(variants) = payload else {
            return Err(invalid(
                "Bond payload must be an object with exactly one variant",
            ));
        };
        let mut entries = variants.iter();
        let (Some((variant, body)), None) = (entries.next(), entries.next()) else {
            return Err(invalid("Bond payload must contain exactly one variant"));
        };
        let boxed = match variant.as_str() {
            "Register" => BondInstructionBox::Register(leaf(body, variant)?),
            "RecordCashflow" => BondInstructionBox::RecordCashflow(leaf(body, variant)?),
            "FundCashflow" => BondInstructionBox::FundCashflow(leaf(body, variant)?),
            "ClaimCashflow" => BondInstructionBox::ClaimCashflow(leaf(body, variant)?),
            "CloseCashflow" => BondInstructionBox::CloseCashflow(leaf(body, variant)?),
            "Call" => BondInstructionBox::Call(leaf(body, variant)?),
            "DeclareDefault" => BondInstructionBox::DeclareDefault(leaf(body, variant)?),
            "ReplacePayingAgent" => BondInstructionBox::ReplacePayingAgent(leaf(body, variant)?),
            "RetireTreasuryUnits" => BondInstructionBox::RetireTreasuryUnits(leaf(body, variant)?),
            other => return Err(invalid(format!("unsupported Bond variant `{other}`"))),
        };
        Ok(InstructionBox::from(boxed))
    })())
}

/// Render the boxed bond kernel through its exact JSON envelope.
pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<Value>> {
    let typed: &dyn Instruction = &**instruction;
    let boxed = typed.as_any().downcast_ref::<BondInstructionBox>()?;
    Some((|| {
        let (variant, payload) = match boxed {
            BondInstructionBox::Register(isi) => ("Register", json::to_value(isi)),
            BondInstructionBox::RecordCashflow(isi) => ("RecordCashflow", json::to_value(isi)),
            BondInstructionBox::FundCashflow(isi) => ("FundCashflow", json::to_value(isi)),
            BondInstructionBox::ClaimCashflow(isi) => ("ClaimCashflow", json::to_value(isi)),
            BondInstructionBox::CloseCashflow(isi) => ("CloseCashflow", json::to_value(isi)),
            BondInstructionBox::Call(isi) => ("Call", json::to_value(isi)),
            BondInstructionBox::DeclareDefault(isi) => ("DeclareDefault", json::to_value(isi)),
            BondInstructionBox::ReplacePayingAgent(isi) => {
                ("ReplacePayingAgent", json::to_value(isi))
            }
            BondInstructionBox::RetireTreasuryUnits(isi) => {
                ("RetireTreasuryUnits", json::to_value(isi))
            }
        };
        Ok(crate::instruction_envelope(
            ENVELOPE,
            crate::instruction_envelope(variant, payload.map_err(crate::codec_error)?),
        ))
    })())
}

/// Render the deterministic key-less vault account of `bond` for `network_prefix`.
///
/// `bond` must be the exact canonical Base58 asset-definition address. The vault is
/// `bond_vault_account_id` of the data model (`specs/finance/bond_ops.md` §1.4); the
/// derivation is network independent, only the I105 rendering uses the prefix.
///
/// # Errors
///
/// Returns [`CodecErrorKind::InvalidArgument`] when `bond` is not an exact canonical
/// asset-definition address, and a failure when the account cannot be rendered.
pub fn bond_vault_account_literal(bond: &str, network_prefix: u16) -> CodecResult<String> {
    let parsed = AssetDefinitionId::parse_address_literal(bond)
        .map_err(|error| invalid(format!("bond identifier: {error}")))?;
    if parsed.to_string() != bond {
        return Err(invalid(
            "bond identifier must be the canonical asset definition address",
        ));
    }
    let _network = ChainDiscriminantGuard::enter(network_prefix);
    match json::to_value(&bond_vault_account_id(&parsed)).map_err(crate::codec_error)? {
        Value::String(literal) => Ok(literal),
        _ => Err(CodecError::failure(
            "bond vault account must render as a JSON string",
        )),
    }
}

#[cfg(test)]
#[path = "bond_instruction_tests.rs"]
mod tests;
