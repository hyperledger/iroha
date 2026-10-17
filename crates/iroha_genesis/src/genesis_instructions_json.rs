//! Canonical structured JSON projection for genesis instruction lists.

use super::*;
use iroha_data_model::{
    account::{NewAccount, OpaqueAccountId},
    asset::definition::NewAssetDefinition,
    domain::NewDomain,
    isi::{
        ActivatePublicLaneValidator, CustomInstruction, Grant, GrantBox, InstructionBox, Mint,
        MintBox, Register, RegisterPublicLaneValidator, SetAssetDefinitionAlias, SetParameter,
        Transfer, TransferBox, Unregister, UnregisterBox,
        alias_setup::EnsureAlias,
        governance::RegisterCitizen,
        nexus::{
            ActivateFeeSponsorProgramRevision, CreateFeeSponsorProgram,
            EnrollFeeSponsorBeneficiary, FundFeeSponsorProgram, StageFeeSponsorProgramRevision,
        },
        register::RegisterBox,
    },
    nexus::{
        FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramRevision, UniversalAccountId,
    },
    parameter::Parameter,
    permission::Permission,
    prelude::{AccountId, AssetDefinitionId, AssetId, RoleId},
    role::NewRole,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Numeric;
use norito::json::{self, Number, Parser, SeqVisitor, Value};
use std::{collections::BTreeMap, str::FromStr};
/// Render a slice of instructions into a JSON array suitable for the genesis manifest.
pub fn serialize(instructions: &[InstructionBox], out: &mut String) {
    out.push('[');
    for (idx, instruction) in instructions.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let value = instruction_value(instruction);
        let rendered = norito::json::to_json(&value).expect("render genesis instruction JSON");
        out.push_str(&rendered);
    }
    out.push(']');
}
/// Convert a slice of instructions into a structured JSON value array.
#[must_use]
pub fn instructions_to_value(instructions: &[InstructionBox]) -> Value {
    Value::Array(
        instructions
            .iter()
            .map(instruction_value)
            .collect::<Vec<_>>(),
    )
}
/// Convert an instruction into a structured JSON value, falling back to base64 if JSON conversion fails.
pub fn instruction_value(instruction: &InstructionBox) -> Value {
    if let Some(value) = instruction_to_value(instruction) {
        return value;
    }
    norito::json::value::to_value(instruction).expect("serialize genesis instruction to JSON")
}
/// Deserialize a sequence of genesis instructions from a JSON parser.
///
/// # Errors
/// Returns an error when the JSON stream cannot be parsed into genesis instructions
/// or when any instruction fails to decode.
pub fn deserialize(parser: &mut Parser<'_>) -> Result<Vec<InstructionBox>, json::Error> {
    let mut seq = SeqVisitor::new(parser)?;
    let mut instructions = Vec::new();
    while let Some(value) = seq.next_element::<Value>()? {
        match value_to_instruction(value) {
            Ok(instr) => instructions.push(instr),
            Err(err) => {
                return Err(json::Error::Message(format!(
                    "failed to decode genesis instruction: {err}"
                )));
            }
        }
    }
    seq.finish()?;
    Ok(instructions)
}
fn value_to_instruction(value: Value) -> Result<InstructionBox, json::Error> {
    match value {
        Value::Array(_) => Err(json::Error::Message(
            "genesis instructions must be structured objects; byte arrays are unsupported"
                .to_string(),
        )),
        Value::String(encoded) => decode_base64_instruction(&encoded),
        Value::Object(map) => {
            if map.len() == 1
                && let Some((kind, inner)) = map.iter().next()
            {
                let decoded = match kind.as_str() {
                    "Register" => try_decode_register(inner.clone())?,
                    "Unregister" => try_decode_unregister(inner.clone())?,
                    "Mint" => try_decode_mint(inner.clone())?,
                    "Transfer" => try_decode_transfer(inner.clone())?,
                    "SetParameter" => try_decode_set_parameter(inner.clone())?,
                    "Grant" => try_decode_grant(inner.clone())?,
                    "SetAssetDefinitionAlias" => {
                        try_decode_set_asset_definition_alias(inner.clone())?
                    }
                    "EnsureAlias" => try_decode_ensure_alias(inner.clone())?,
                    "Custom" => try_decode_custom(inner.clone())?,
                    "RegisterCitizen" => try_decode_register_citizen(inner.clone())?,
                    "RegisterPublicLaneValidator" => {
                        try_decode_register_public_lane_validator(inner.clone())?
                    }
                    "ActivatePublicLaneValidator" => {
                        try_decode_activate_public_lane_validator(inner.clone())?
                    }
                    "CreateFeeSponsorProgram" => {
                        try_decode_create_fee_sponsor_program(inner.clone())?
                    }
                    "StageFeeSponsorProgramRevision" => {
                        try_decode_stage_fee_sponsor_program_revision(inner.clone())?
                    }
                    "EnrollFeeSponsorBeneficiary" => {
                        try_decode_enroll_fee_sponsor_beneficiary(inner.clone())?
                    }
                    "FundFeeSponsorProgram" => try_decode_fund_fee_sponsor_program(inner.clone())?,
                    "ActivateFeeSponsorProgramRevision" => {
                        try_decode_activate_fee_sponsor_program_revision(inner.clone())?
                    }
                    _ => None,
                };
                if let Some(instr) = decoded {
                    return Ok(instr);
                }
            }
            norito::json::value::from_value::<InstructionBox>(Value::Object(map)).map_err(|err| {
                json::Error::Message(format!("unsupported genesis instruction object: {err}"))
            })
        }
        other => Err(json::Error::Message(format!(
            "genesis instructions must be objects; found {other:?}"
        ))),
    }
}
fn decode_base64_instruction(encoded: &str) -> Result<InstructionBox, json::Error> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| {
            json::Error::Message(format!("invalid base64 genesis instruction: {err}"))
        })?;
    norito::decode_canonical::<InstructionBox>(&bytes).map_err(|err| {
        json::Error::Message(format!(
            "failed to decode canonical base64 genesis instruction: {err}"
        ))
    })
}
fn try_decode_register(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let map = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    if map.len() != 1 {
        return Ok(None);
    }
    let (variant, payload) = map.into_iter().next().unwrap();
    let instruction = match variant.as_str() {
        "Domain" => {
            let new_domain: NewDomain = norito::json::value::from_value(payload)?;
            InstructionBox::from(Register::domain(new_domain))
        }
        "Account" => {
            let mut fields = match payload {
                Value::Object(map) => map,
                other => {
                    return Err(json::Error::Message(format!(
                        "expected object for Register::Account fields, found {other:?}"
                    )));
                }
            };
            let id = parse_account_id(&take_string(&mut fields, "id")?, "register account")?;
            let metadata = match fields.remove("metadata") {
                None | Some(Value::Null) => Metadata::default(),
                Some(value) => norito::json::value::from_value(value)?,
            };
            let label = match fields.remove("label") {
                None | Some(Value::Null) => None,
                Some(value) => Some(parse_account_alias(value, "Register.Account.label")?),
            };
            let uaid: Option<UniversalAccountId> = match fields.remove("uaid") {
                None | Some(Value::Null) => None,
                Some(value) => Some(norito::json::value::from_value(value)?),
            };
            let opaque_ids: Vec<OpaqueAccountId> = match fields.remove("opaque_ids") {
                None | Some(Value::Null) => Vec::new(),
                Some(value) => norito::json::value::from_value(value)?,
            };
            ensure_no_extra_fields(&fields)?;
            let new_account = NewAccount::new(id)
                .with_metadata(metadata)
                .with_label(label)
                .with_uaid(uaid)
                .with_opaque_ids(opaque_ids);
            InstructionBox::from(Register::account(new_account))
        }
        "AssetDefinition" => {
            let new_asset_definition: NewAssetDefinition =
                norito::json::value::from_value(payload)?;
            InstructionBox::from(Register::asset_definition(new_asset_definition))
        }
        "Role" => {
            let fields = object_fields(payload.clone(), "Register::Role")?;
            ensure_only_keys(&fields, &["id", "permissions", "grant_to"])?;
            for required in ["id", "permissions", "grant_to"] {
                if !fields.contains_key(required) {
                    return Err(json::Error::missing_field(required));
                }
            }
            let permission_values = match fields.get("permissions") {
                Some(Value::Array(values)) => values,
                Some(other) => {
                    return Err(json::Error::Message(format!(
                        "expected array for Register::Role.permissions, found {other:?}"
                    )));
                }
                None => return Err(json::Error::missing_field("permissions")),
            };
            for (index, permission) in permission_values.iter().enumerate() {
                let permission_fields = match permission {
                    Value::Object(fields) => fields,
                    other => {
                        return Err(json::Error::Message(format!(
                            "expected object for Register::Role.permissions[{index}], found {other:?}"
                        )));
                    }
                };
                ensure_only_keys(permission_fields, &["name", "payload"])?;
                for required in ["name", "payload"] {
                    if !permission_fields.contains_key(required) {
                        return Err(json::Error::Message(format!(
                            "missing Register::Role.permissions[{index}].{required}"
                        )));
                    }
                }
            }
            let new_role: NewRole = norito::json::value::from_value(payload)?;
            InstructionBox::from(Register::role(new_role))
        }
        _ => return Ok(None),
    };
    Ok(Some(instruction))
}
fn try_decode_unregister(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let variants = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    if variants.len() != 1 {
        return Ok(None);
    }
    let (variant, payload) = variants.into_iter().next().unwrap();
    if variant != "Role" {
        return Ok(None);
    }
    let mut fields = object_fields(payload, "Unregister::Role")?;
    let role_id: RoleId = parse_id(&take_string(&mut fields, "object")?, "role")?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(Unregister::role(role_id))))
}
fn try_decode_mint(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let variants = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    if variants.len() != 1 {
        return Ok(None);
    }
    let (variant, payload) = variants.into_iter().next().unwrap();
    if variant != "Asset" {
        return Ok(None);
    }
    let mut fields = match payload {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for Mint::Asset fields, found {other:?}"
            )));
        }
    };
    let destination_str = take_string(&mut fields, "destination")?;
    let asset_id: AssetId = parse_id(&destination_str, "asset destination")?;
    let object_value = fields
        .remove("object")
        .ok_or_else(|| json::Error::missing_field("object"))?;
    ensure_no_extra_fields(&fields)?;
    let quantity = Quantity::try_from_numeric(parse_numeric(object_value)?)
        .map_err(|error| json::Error::Message(format!("invalid asset mint quantity: {error}")))?;
    let instruction = InstructionBox::from(Mint::asset_quantity(quantity, asset_id));
    Ok(Some(instruction))
}
fn try_decode_transfer(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let variants = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    if variants.len() != 1 {
        return Ok(None);
    }
    let (variant, payload) = variants.into_iter().next().unwrap();
    let mut fields = match payload {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for Transfer::{variant} fields, found {other:?}"
            )));
        }
    };
    let instruction = match variant.as_str() {
        "AssetDefinition" => {
            let source_str = take_string(&mut fields, "source")?;
            let source: AccountId = parse_account_id(&source_str, "transfer source account")?;
            let object_str = take_string(&mut fields, "object")?;
            let object: AssetDefinitionId = parse_id(&object_str, "asset definition")?;
            let destination_str = take_string(&mut fields, "destination")?;
            let destination: AccountId =
                parse_account_id(&destination_str, "transfer destination account")?;
            ensure_no_extra_fields(&fields)?;
            InstructionBox::from(Transfer::asset_definition(source, object, destination))
        }
        "Domain" => {
            let source_str = take_string(&mut fields, "source")?;
            let source: AccountId = parse_account_id(&source_str, "transfer source account")?;
            let domain_str = take_string(&mut fields, "object")?;
            let domain = parse_domain_id(&domain_str, "domain")?;
            let destination_str = take_string(&mut fields, "destination")?;
            let destination: AccountId =
                parse_account_id(&destination_str, "transfer destination account")?;
            ensure_no_extra_fields(&fields)?;
            InstructionBox::from(Transfer::domain(source, domain, destination))
        }
        _ => return Ok(None),
    };
    Ok(Some(instruction))
}
fn try_decode_set_parameter(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    let parameter_value = fields
        .remove("parameter")
        .ok_or_else(|| json::Error::missing_field("parameter"))?;
    ensure_no_extra_fields(&fields)?;
    let parameter: Parameter = norito::json::value::from_value(parameter_value)?;
    Ok(Some(InstructionBox::from(SetParameter::new(parameter))))
}
fn try_decode_grant(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let variants = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    if variants.len() != 1 {
        return Ok(None);
    }
    let (variant, payload) = variants.into_iter().next().unwrap();
    if variant != "Permission" {
        return Ok(None);
    }
    let mut fields = match payload {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for Grant::Permission fields, found {other:?}"
            )));
        }
    };
    let destination: AccountId = parse_account_id(
        &take_string(&mut fields, "destination")?,
        "grant destination account",
    )?;
    let object_value = fields
        .remove("object")
        .ok_or_else(|| json::Error::missing_field("object"))?;
    ensure_no_extra_fields(&fields)?;
    let mut permission_fields = match object_value {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for permission fields, found {other:?}"
            )));
        }
    };
    match permission_fields.get("name") {
        Some(Value::String(_)) => {}
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected string for permission name, found {other:?}"
            )));
        }
        None => return Err(json::Error::missing_field("name")),
    }
    permission_fields
        .entry("payload".to_owned())
        .or_insert(Value::Null);
    ensure_only_keys(&permission_fields, &["name", "payload"])?;
    let permission: Permission = norito::json::value::from_value(Value::Object(permission_fields))?;
    let instruction = InstructionBox::from(Grant::account_permission(permission, destination));
    Ok(Some(instruction))
}
fn try_decode_set_asset_definition_alias(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    let asset_definition_id = match fields.remove("asset_definition_id") {
        Some(Value::String(value)) => AssetDefinitionId::from_str(&value).map_err(|err| {
            json::Error::Message(format!(
                "invalid SetAssetDefinitionAlias.asset_definition_id `{value}`: {err}"
            ))
        })?,
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected string for SetAssetDefinitionAlias.asset_definition_id, found {other:?}"
            )));
        }
        None => {
            return Err(json::Error::Message(
                "missing SetAssetDefinitionAlias.asset_definition_id".to_string(),
            ));
        }
    };
    let alias = match fields.remove("alias") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.parse().map_err(|err| {
            json::Error::Message(format!(
                "invalid SetAssetDefinitionAlias.alias `{value}`: {err}"
            ))
        })?),
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected string or null for SetAssetDefinitionAlias.alias, found {other:?}"
            )));
        }
    };
    let lease_expiry_ms = match fields.remove("lease_expiry_ms") {
        None | Some(Value::Null) => None,
        Some(Value::Number(Number::U64(value))) => Some(value),
        Some(Value::Number(Number::U128(value))) => Some(u64::try_from(value).map_err(|_| {
            json::Error::Message(format!(
                "invalid SetAssetDefinitionAlias.lease_expiry_ms: {value}"
            ))
        })?),
        Some(Value::Number(Number::I64(value))) if value >= 0 => Some(value.cast_unsigned()),
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected unsigned integer or null for SetAssetDefinitionAlias.lease_expiry_ms, found {other:?}"
            )));
        }
    };
    if !fields.is_empty() {
        return Err(json::Error::Message(format!(
            "unexpected SetAssetDefinitionAlias fields: {}",
            fields.keys().cloned().collect::<Vec<_>>().join(",")
        )));
    }
    let instruction = match alias {
        Some(alias) => SetAssetDefinitionAlias::bind(asset_definition_id, alias, lease_expiry_ms),
        None => SetAssetDefinitionAlias::clear(asset_definition_id),
    };
    Ok(Some(InstructionBox::from(instruction)))
}
fn try_decode_ensure_alias(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let fields = object_fields(inner, "EnsureAlias")?;
    ensure_only_keys(&fields, &["intent", "acquisition", "quote_guard"])?;
    for required in ["intent", "acquisition", "quote_guard"] {
        if !fields.contains_key(required) {
            return Err(json::Error::missing_field(required));
        }
    }
    let ensure: EnsureAlias = norito::json::value::from_value(Value::Object(fields))?;
    Ok(Some(InstructionBox::from(ensure)))
}
fn try_decode_custom(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = match inner {
        Value::Object(map) => map,
        _ => return Ok(None),
    };
    let payload = fields
        .remove("payload")
        .ok_or_else(|| json::Error::missing_field("payload"))?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(CustomInstruction::new(
        iroha_primitives::json::Json::new(payload),
    ))))
}
fn try_decode_register_citizen(inner: Value) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "RegisterCitizen")?;
    let owner = parse_account_id(&take_string(&mut fields, "owner")?, "RegisterCitizen owner")?;
    let amount = Quantity::try_from_numeric(parse_numeric(
        fields
            .remove("amount")
            .ok_or_else(|| json::Error::missing_field("amount"))?,
    )?)
    .map_err(|error| json::Error::Message(format!("invalid RegisterCitizen amount: {error}")))?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(RegisterCitizen {
        owner,
        amount,
    })))
}
fn try_decode_register_public_lane_validator(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = match inner {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for RegisterPublicLaneValidator fields, found {other:?}"
            )));
        }
    };
    let lane_value = fields
        .remove("lane_id")
        .ok_or_else(|| json::Error::missing_field("lane_id"))?;
    let lane_id = LaneId::from(parse_u32(lane_value, "lane_id")?);
    let validator_str = take_string(&mut fields, "validator")?;
    let validator: AccountId = parse_account_id(&validator_str, "validator")?;
    let peer_id_str = take_string(&mut fields, "peer_id")?;
    let peer_id: PeerId = peer_id_str.parse().map_err(|_| {
        json::Error::Message(format!(
            "invalid peer id for RegisterPublicLaneValidator: {peer_id_str}"
        ))
    })?;
    let stake_account_str = take_string(&mut fields, "stake_account")?;
    let stake_account: AccountId = parse_account_id(&stake_account_str, "stake_account")?;
    let stake_value = fields
        .remove("initial_stake")
        .ok_or_else(|| json::Error::missing_field("initial_stake"))?;
    let initial_stake =
        Quantity::try_from_numeric(parse_numeric(stake_value)?).map_err(|error| {
            json::Error::Message(format!("invalid initial stake quantity: {error}"))
        })?;
    let metadata_value = fields.remove("metadata");
    let metadata = match metadata_value {
        Some(Value::Null) | None => Metadata::default(),
        Some(value) => norito::json::value::from_value(value)?,
    };
    let monetary_plan = norito::json::value::from_value(
        fields
            .remove("monetary_plan")
            .ok_or_else(|| json::Error::missing_field("monetary_plan"))?,
    )?;
    ensure_no_extra_fields(&fields)?;
    let register = RegisterPublicLaneValidator::new(
        lane_id,
        validator,
        peer_id,
        stake_account,
        initial_stake,
        metadata,
        monetary_plan,
    );
    Ok(Some(InstructionBox::from(register)))
}
fn try_decode_activate_public_lane_validator(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = match inner {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for ActivatePublicLaneValidator fields, found {other:?}"
            )));
        }
    };
    let lane_value = fields
        .remove("lane_id")
        .ok_or_else(|| json::Error::missing_field("lane_id"))?;
    let lane_id = LaneId::from(parse_u32(lane_value, "lane_id")?);
    let validator_str = take_string(&mut fields, "validator")?;
    let validator: AccountId = parse_account_id(&validator_str, "validator")?;
    ensure_no_extra_fields(&fields)?;
    let activate = ActivatePublicLaneValidator::new(lane_id, validator);
    Ok(Some(InstructionBox::from(activate)))
}
fn object_fields(inner: Value, instruction: &str) -> Result<BTreeMap<String, Value>, json::Error> {
    match inner {
        Value::Object(fields) => Ok(fields),
        other => Err(json::Error::Message(format!(
            "expected object for {instruction} fields, found {other:?}"
        ))),
    }
}
fn take_typed<T>(
    fields: &mut BTreeMap<String, Value>,
    field: &'static str,
) -> Result<T, json::Error>
where
    T: norito::json::JsonDeserialize,
{
    norito::json::value::from_value(
        fields
            .remove(field)
            .ok_or_else(|| json::Error::missing_field(field))?,
    )
}
fn try_decode_create_fee_sponsor_program(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "CreateFeeSponsorProgram")?;
    let program = take_typed::<FeeSponsorProgram>(&mut fields, "program")?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(CreateFeeSponsorProgram {
        program,
    })))
}
fn try_decode_stage_fee_sponsor_program_revision(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "StageFeeSponsorProgramRevision")?;
    let revision = take_typed::<FeeSponsorProgramRevision>(&mut fields, "revision")?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(StageFeeSponsorProgramRevision {
        revision,
    })))
}
fn try_decode_enroll_fee_sponsor_beneficiary(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "EnrollFeeSponsorBeneficiary")?;
    let program_id = take_typed::<FeeSponsorProgramId>(&mut fields, "program_id")?;
    let beneficiary = parse_account_id(
        &take_string(&mut fields, "beneficiary")?,
        "fee sponsor beneficiary",
    )?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(EnrollFeeSponsorBeneficiary {
        program_id,
        beneficiary,
    })))
}
fn try_decode_fund_fee_sponsor_program(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "FundFeeSponsorProgram")?;
    let program_id = take_typed::<FeeSponsorProgramId>(&mut fields, "program_id")?;
    let asset_definition_id =
        AssetDefinitionId::from_str(&take_string(&mut fields, "asset_definition_id")?)
            .map_err(|error| json::Error::Message(format!("invalid sponsor asset: {error}")))?;
    let amount = Quantity::try_from_numeric(parse_numeric(
        fields
            .remove("amount")
            .ok_or_else(|| json::Error::missing_field("amount"))?,
    )?)
    .map_err(|error| json::Error::Message(format!("invalid sponsor amount: {error}")))?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(FundFeeSponsorProgram {
        program_id,
        asset_definition_id,
        amount,
    })))
}
fn try_decode_activate_fee_sponsor_program_revision(
    inner: Value,
) -> Result<Option<InstructionBox>, json::Error> {
    let mut fields = object_fields(inner, "ActivateFeeSponsorProgramRevision")?;
    let program_id = take_typed::<FeeSponsorProgramId>(&mut fields, "program_id")?;
    let revision = parse_u64(
        fields
            .remove("revision")
            .ok_or_else(|| json::Error::missing_field("revision"))?,
        "fee sponsor revision",
    )?;
    let activate_at_height = parse_u64(
        fields
            .remove("activate_at_height")
            .ok_or_else(|| json::Error::missing_field("activate_at_height"))?,
        "fee sponsor activation height",
    )?;
    ensure_no_extra_fields(&fields)?;
    Ok(Some(InstructionBox::from(
        ActivateFeeSponsorProgramRevision {
            program_id,
            revision,
            activate_at_height,
        },
    )))
}
fn take_string(
    fields: &mut BTreeMap<String, Value>,
    field: &'static str,
) -> Result<String, json::Error> {
    match fields.remove(field) {
        Some(Value::String(s)) => Ok(s),
        Some(other) => Err(json::Error::Message(format!(
            "expected string for `{field}`, found {other:?}"
        ))),
        None => Err(json::Error::missing_field(field)),
    }
}
fn ensure_no_extra_fields(fields: &BTreeMap<String, Value>) -> Result<(), json::Error> {
    if let Some(field) = fields.keys().next().cloned() {
        return Err(json::Error::UnknownField { field });
    }
    Ok(())
}
fn ensure_only_keys(fields: &BTreeMap<String, Value>, allowed: &[&str]) -> Result<(), json::Error> {
    for key in fields.keys() {
        if !allowed.iter().any(|allowed_key| key == allowed_key) {
            return Err(json::Error::UnknownField { field: key.clone() });
        }
    }
    Ok(())
}
fn parse_id<T>(value: &str, label: &'static str) -> Result<T, json::Error>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|err| json::Error::Message(format!("invalid {label}: {err}")))
}
fn parse_account_id(value: &str, label: &'static str) -> Result<AccountId, json::Error> {
    <AccountId as json::JsonObjectKeyOwned>::from_json_key_text(value).map_err(|error| {
        if error.is_decode_resource_limit() {
            error
        } else {
            json::Error::Message(format!("invalid {label}: {error}"))
        }
    })
}
fn parse_domain_id(value: &str, label: &'static str) -> Result<DomainId, json::Error> {
    DomainId::parse_fully_qualified(value)
        .map_err(|err| json::Error::Message(format!("invalid {label}: {err}")))
}
fn parse_u32(value: Value, label: &'static str) -> Result<u32, json::Error> {
    match value {
        Value::String(s) => s
            .parse::<u32>()
            .map_err(|err| json::Error::Message(format!("invalid {label}: {err}"))),
        Value::Number(Number::U64(v)) => {
            u32::try_from(v).map_err(|_| json::Error::Message(format!("invalid {label}: {v}")))
        }
        Value::Number(Number::U128(v)) => {
            u32::try_from(v).map_err(|_| json::Error::Message(format!("invalid {label}: {v}")))
        }
        Value::Number(Number::I64(v)) => {
            u32::try_from(v).map_err(|_| json::Error::Message(format!("invalid {label}: {v}")))
        }
        other => Err(json::Error::Message(format!(
            "expected numeric {label} value, found {other:?}"
        ))),
    }
}
fn parse_u64(value: Value, label: &'static str) -> Result<u64, json::Error> {
    match value {
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|err| json::Error::Message(format!("invalid {label}: {err}"))),
        Value::Number(Number::U64(value)) => Ok(value),
        Value::Number(Number::U128(value)) => u64::try_from(value)
            .map_err(|_| json::Error::Message(format!("invalid {label}: {value}"))),
        Value::Number(Number::I64(value)) => u64::try_from(value)
            .map_err(|_| json::Error::Message(format!("invalid {label}: {value}"))),
        other => Err(json::Error::Message(format!(
            "expected numeric {label} value, found {other:?}"
        ))),
    }
}
fn parse_account_alias(
    value: Value,
    label: &'static str,
) -> Result<iroha_data_model::account::rekey::AccountAlias, json::Error> {
    let mut fields = match value {
        Value::Object(map) => map,
        other => {
            return Err(json::Error::Message(format!(
                "expected object for {label}, found {other:?}"
            )));
        }
    };
    let alias_label = match fields.remove("label") {
        Some(Value::String(value)) => value
            .parse()
            .map_err(|_| json::Error::Message(format!("invalid {label}.label `{value}`")))?,
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected string for {label}.label, found {other:?}"
            )));
        }
        None => return Err(json::Error::Message(format!("missing {label}.label"))),
    };
    let domain = match fields.remove("domain") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.parse().map_err(|err| {
            json::Error::Message(format!("invalid {label}.domain `{value}`: {err}"))
        })?),
        Some(other) => {
            return Err(json::Error::Message(format!(
                "expected string or null for {label}.domain, found {other:?}"
            )));
        }
    };
    let dataspace = match fields.remove("dataspace") {
        Some(value) => iroha_model_base::topology::DataSpaceId::new(u64::from(parse_u32(
            value,
            "account alias dataspace",
        )?)),
        None => return Err(json::Error::Message(format!("missing {label}.dataspace"))),
    };
    ensure_no_extra_fields(&fields)?;
    Ok(iroha_data_model::account::rekey::AccountAlias::new(
        alias_label,
        domain,
        dataspace,
    ))
}
fn parse_numeric(value: Value) -> Result<Numeric, json::Error> {
    match value {
        Value::String(s) => s
            .parse::<Numeric>()
            .map_err(|err| json::Error::Message(err.to_string())),
        Value::Number(number) => {
            let repr = match number {
                Number::I64(v) => v.to_string(),
                Number::U64(v) => v.to_string(),
                Number::U128(v) => v.to_string(),
                Number::F64(v) => v.to_string(),
            };
            repr.parse::<Numeric>()
                .map_err(|err| json::Error::Message(err.to_string()))
        }
        other => Err(json::Error::Message(format!(
            "expected numeric value as string or number, found {other:?}"
        ))),
    }
}
fn account_literal(account: &AccountId) -> Option<String> {
    account.canonical_i105().ok()
}
fn asset_literal(asset: &AssetId) -> String {
    asset.canonical_literal()
}
#[allow(clippy::too_many_lines)]
fn instruction_to_value(instruction: &InstructionBox) -> Option<Value> {
    use norito::json::Map;
    fn wrap(kind: &str, variant: &str, value: Value) -> Value {
        let mut variant_map = Map::new();
        variant_map.insert(variant.to_string(), value);
        let mut outer = Map::new();
        outer.insert(kind.to_string(), Value::Object(variant_map));
        Value::Object(outer)
    }
    if let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() {
        return match register {
            RegisterBox::Domain(domain) => norito::json::value::to_value(domain.object())
                .ok()
                .map(|value| wrap("Register", "Domain", value)),
            RegisterBox::Account(account) => norito::json::value::to_value(account.object())
                .ok()
                .map(|value| wrap("Register", "Account", value)),
            RegisterBox::AssetDefinition(asset_definition) => {
                norito::json::value::to_value(asset_definition.object())
                    .ok()
                    .map(|value| wrap("Register", "AssetDefinition", value))
            }
            RegisterBox::Role(role) => norito::json::value::to_value(role.object())
                .ok()
                .map(|value| wrap("Register", "Role", value)),
            _ => None,
        };
    }
    if let Some(unregister) = instruction.as_any().downcast_ref::<UnregisterBox>() {
        return match unregister {
            UnregisterBox::Role(role) => {
                let mut fields = Map::new();
                fields.insert(
                    "object".to_string(),
                    Value::String(role.object().to_string()),
                );
                Some(wrap("Unregister", "Role", Value::Object(fields)))
            }
            _ => None,
        };
    }
    if let Some(mint) = instruction.as_any().downcast_ref::<MintBox>() {
        return match mint {
            MintBox::Asset(mint_asset) => {
                let mut fields = Map::new();
                fields.insert(
                    "object".to_string(),
                    Value::String(mint_asset.object().to_string()),
                );
                let destination = asset_literal(mint_asset.destination());
                fields.insert("destination".to_string(), Value::String(destination));
                Some(wrap("Mint", "Asset", Value::Object(fields)))
            }
            _ => None,
        };
    }
    if let Some(transfer) = instruction.as_any().downcast_ref::<TransferBox>() {
        return match transfer {
            TransferBox::AssetDefinition(tr) => {
                let mut fields = Map::new();
                let source = account_literal(tr.source())?;
                fields.insert("source".to_string(), Value::String(source));
                fields.insert("object".to_string(), Value::String(tr.object().to_string()));
                let destination = account_literal(tr.destination())?;
                fields.insert("destination".to_string(), Value::String(destination));
                Some(wrap("Transfer", "AssetDefinition", Value::Object(fields)))
            }
            TransferBox::Domain(tr) => {
                let mut fields = Map::new();
                let source = account_literal(tr.source())?;
                fields.insert("source".to_string(), Value::String(source));
                fields.insert("object".to_string(), Value::String(tr.object().to_string()));
                let destination = account_literal(tr.destination())?;
                fields.insert("destination".to_string(), Value::String(destination));
                Some(wrap("Transfer", "Domain", Value::Object(fields)))
            }
            _ => None,
        };
    }
    if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() {
        return norito::json::value::to_value(set_parameter.inner())
            .ok()
            .map(|parameter| {
                let mut inner = Map::new();
                inner.insert("parameter".to_string(), parameter);
                let mut outer = Map::new();
                outer.insert("SetParameter".to_string(), Value::Object(inner));
                Value::Object(outer)
            });
    }
    if let Some(set_asset_definition_alias) = instruction
        .as_any()
        .downcast_ref::<SetAssetDefinitionAlias>()
    {
        let mut fields = Map::new();
        fields.insert(
            "asset_definition_id".to_string(),
            Value::String(set_asset_definition_alias.asset_definition_id().to_string()),
        );
        fields.insert(
            "alias".to_string(),
            set_asset_definition_alias
                .alias()
                .as_ref()
                .map_or(Value::Null, |alias| Value::String(alias.to_string())),
        );
        fields.insert(
            "lease_expiry_ms".to_string(),
            set_asset_definition_alias
                .lease_expiry_ms()
                .as_ref()
                .map_or(Value::Null, |value| Value::Number(Number::U64(*value))),
        );
        let mut outer = Map::new();
        outer.insert("SetAssetDefinitionAlias".to_string(), Value::Object(fields));
        return Some(Value::Object(outer));
    }
    if let Some(ensure) = instruction.as_any().downcast_ref::<EnsureAlias>() {
        let fields = norito::json::value::to_value(ensure).ok()?;
        let mut outer = Map::new();
        outer.insert("EnsureAlias".to_string(), fields);
        return Some(Value::Object(outer));
    }
    if let Some(custom) = instruction.as_any().downcast_ref::<CustomInstruction>() {
        let payload = norito::json::parse_value(custom.payload().get()).ok()?;
        let mut inner = Map::new();
        inner.insert("payload".to_string(), payload);
        let mut outer = Map::new();
        outer.insert("Custom".to_string(), Value::Object(inner));
        return Some(Value::Object(outer));
    }
    if let Some(citizen) = instruction.as_any().downcast_ref::<RegisterCitizen>() {
        let mut fields = Map::new();
        fields.insert(
            "owner".to_string(),
            Value::String(account_literal(&citizen.owner)?),
        );
        fields.insert(
            "amount".to_string(),
            Value::String(citizen.amount.to_string()),
        );
        let mut outer = Map::new();
        outer.insert("RegisterCitizen".to_string(), Value::Object(fields));
        return Some(Value::Object(outer));
    }
    if let Some(grant) = instruction.as_any().downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(grant_perm) => {
                let permission = norito::json::value::to_value(grant_perm.object()).ok()?;
                let mut fields = Map::new();
                fields.insert("object".to_string(), permission);
                let destination = account_literal(grant_perm.destination())?;
                fields.insert("destination".to_string(), Value::String(destination));
                Some(wrap("Grant", "Permission", Value::Object(fields)))
            }
            _ => None,
        };
    }
    if let Some(register) = instruction
        .as_any()
        .downcast_ref::<RegisterPublicLaneValidator>()
    {
        let mut fields = Map::new();
        fields.insert(
            "lane_id".to_string(),
            Value::Number(Number::U64(u64::from(register.lane_id().as_u32()))),
        );
        let validator = account_literal(register.validator())?;
        fields.insert("validator".to_string(), Value::String(validator));
        fields.insert(
            "peer_id".to_string(),
            Value::String(register.peer_id().to_string()),
        );
        let stake_account = account_literal(register.stake_account())?;
        fields.insert("stake_account".to_string(), Value::String(stake_account));
        fields.insert(
            "initial_stake".to_string(),
            Value::String(register.initial_stake().to_string()),
        );
        let metadata = norito::json::value::to_value(register.metadata()).ok()?;
        fields.insert("metadata".to_string(), metadata);
        fields.insert(
            "monetary_plan".to_string(),
            norito::json::value::to_value(register.monetary_plan()).ok()?,
        );
        let mut outer = Map::new();
        outer.insert(
            "RegisterPublicLaneValidator".to_string(),
            Value::Object(fields),
        );
        return Some(Value::Object(outer));
    }
    if let Some(activate) = instruction
        .as_any()
        .downcast_ref::<ActivatePublicLaneValidator>()
    {
        let mut fields = Map::new();
        fields.insert(
            "lane_id".to_string(),
            Value::Number(Number::U64(u64::from(activate.lane_id().as_u32()))),
        );
        let validator = account_literal(activate.validator())?;
        fields.insert("validator".to_string(), Value::String(validator));
        let mut outer = Map::new();
        outer.insert(
            "ActivatePublicLaneValidator".to_string(),
            Value::Object(fields),
        );
        return Some(Value::Object(outer));
    }
    if let Some(create) = instruction
        .as_any()
        .downcast_ref::<CreateFeeSponsorProgram>()
    {
        let mut fields = Map::new();
        fields.insert(
            "program".to_owned(),
            norito::json::value::to_value(create.program()).ok()?,
        );
        let mut outer = Map::new();
        outer.insert("CreateFeeSponsorProgram".to_owned(), Value::Object(fields));
        return Some(Value::Object(outer));
    }
    if let Some(stage) = instruction
        .as_any()
        .downcast_ref::<StageFeeSponsorProgramRevision>()
    {
        let mut fields = Map::new();
        fields.insert(
            "revision".to_owned(),
            norito::json::value::to_value(stage.revision()).ok()?,
        );
        let mut outer = Map::new();
        outer.insert(
            "StageFeeSponsorProgramRevision".to_owned(),
            Value::Object(fields),
        );
        return Some(Value::Object(outer));
    }
    if let Some(enroll) = instruction
        .as_any()
        .downcast_ref::<EnrollFeeSponsorBeneficiary>()
    {
        let mut fields = Map::new();
        fields.insert(
            "program_id".to_owned(),
            norito::json::value::to_value(enroll.program_id()).ok()?,
        );
        fields.insert(
            "beneficiary".to_owned(),
            Value::String(account_literal(enroll.beneficiary())?),
        );
        let mut outer = Map::new();
        outer.insert(
            "EnrollFeeSponsorBeneficiary".to_owned(),
            Value::Object(fields),
        );
        return Some(Value::Object(outer));
    }
    if let Some(fund) = instruction.as_any().downcast_ref::<FundFeeSponsorProgram>() {
        let mut fields = Map::new();
        fields.insert(
            "program_id".to_owned(),
            norito::json::value::to_value(fund.program_id()).ok()?,
        );
        fields.insert(
            "asset_definition_id".to_owned(),
            Value::String(fund.asset_definition_id().canonical_address()),
        );
        fields.insert(
            "amount".to_owned(),
            Value::String(fund.amount().to_string()),
        );
        let mut outer = Map::new();
        outer.insert("FundFeeSponsorProgram".to_owned(), Value::Object(fields));
        return Some(Value::Object(outer));
    }
    if let Some(activate) = instruction
        .as_any()
        .downcast_ref::<ActivateFeeSponsorProgramRevision>()
    {
        let mut fields = Map::new();
        fields.insert(
            "program_id".to_owned(),
            norito::json::value::to_value(activate.program_id()).ok()?,
        );
        fields.insert(
            "revision".to_owned(),
            Value::Number(Number::U64(*activate.revision())),
        );
        fields.insert(
            "activate_at_height".to_owned(),
            Value::Number(Number::U64(*activate.activate_at_height())),
        );
        let mut outer = Map::new();
        outer.insert(
            "ActivateFeeSponsorProgramRevision".to_owned(),
            Value::Object(fields),
        );
        return Some(Value::Object(outer));
    }
    None
}
/// Parse genesis instructions from a JSON value.
///
/// # Errors
/// Returns an error when the provided value cannot be rendered to JSON or when
/// the resulting stream fails to deserialize into genesis instructions.
pub fn from_value(value: &Value) -> Result<Vec<InstructionBox>, json::Error> {
    let json = json::to_json(value)?;
    let mut parser = Parser::new(&json);
    let instructions = deserialize(&mut parser)?;
    parser.skip_ws();
    if !parser.eof() {
        let (byte, line, col) = pos_from_offset(parser.input(), parser.position());
        return Err(json::Error::TrailingCharacters { byte, line, col });
    }
    Ok(instructions)
}
fn pos_from_offset(s: &str, pos: usize) -> (usize, usize, usize) {
    let bytes = s.as_bytes();
    let mut line = 1usize;
    let mut col = 1usize;
    let mut i = 0usize;
    while i < pos && i < bytes.len() {
        if bytes[i] == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        i += 1;
    }
    (pos, line, col)
}
#[cfg(test)]
mod tests;
