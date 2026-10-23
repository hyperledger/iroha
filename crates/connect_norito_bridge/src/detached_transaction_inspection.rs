//! Typed instruction reviews derived only from canonical native scaffolds.
use super::*;
use iroha_data_model::{
    escrow::{ConditionalEscrowCondition, ConditionalEscrowPredicate, ConditionalEscrowValue},
    isi::{
        asset_fi::{SetAssetFiLinkV1, TransferToLinkedFiV1},
        escrow::OpenConditionalEscrow,
        transfer::{BatchMode, TransferAssetBatch},
    },
};

pub(super) fn instruction_json(instruction: &InstructionBox) -> BridgeResult<JsonValue> {
    if let Some(batch) = instruction.as_any().downcast_ref::<TransferAssetBatch>() {
        return Ok(batch_json(batch));
    }
    if let Some(escrow) = instruction.as_any().downcast_ref::<OpenConditionalEscrow>() {
        return Ok(escrow_json(escrow));
    }
    if let Some(link) = instruction.as_any().downcast_ref::<SetAssetFiLinkV1>() {
        return Ok(fi_link_json(link));
    }
    if let Some(transfer) = instruction.as_any().downcast_ref::<TransferToLinkedFiV1>() {
        return Ok(fi_link_transfer_json(transfer));
    }
    detached_asset_transfer_json(instruction)
}

// These five fields are the entire instruction. FI/reference/display facts are
// deliberately absent: inspecting bytes does not authenticate current link state
// or establish the complete historical relationship used by execution.
fn fi_link_transfer_json(instruction: &TransferToLinkedFiV1) -> JsonValue {
    ::norito::json!({
        "kind": "asset_fi_link_transfer",
        "asset_definition_id": (instruction.asset_definition_id.to_string()),
        "account_id": (instruction.account_id.to_string()),
        "amount": (instruction.amount.to_string()),
        "expected_link_revision": (instruction.expected_link_revision),
        "expected_policy_revision": (instruction.expected_policy_revision),
    })
}

fn fi_link_json(instruction: &SetAssetFiLinkV1) -> JsonValue {
    let link = &instruction.link;
    let controller = link.controller.as_ref().map_or(JsonValue::Null, |address| {
        JsonValue::from(address.to_string())
    });
    ::norito::json!({
        "kind": "asset_fi_link_set",
        "asset_definition_id": (link.asset_definition_id.to_string()),
        "account_id": (link.account_id.to_string()),
        "fi_account_id": (link.fi_account_id.to_string()),
        "reference_digest": (hex::encode(link.reference_digest)),
        "fi_revision": (link.fi_revision),
        "attestation_revision": (link.attestation_revision),
        "revision": (link.revision),
        "enabled": (link.enabled),
        "controller": controller,
        "waterfall": (link.waterfall),
        "reverse_waterfall": (link.reverse_waterfall),
        "expected_policy_revision": (instruction.expected_policy_revision),
    })
}

fn batch_json(batch: &TransferAssetBatch) -> JsonValue {
    let entries = batch
        .entries()
        .iter()
        .map(|leg| {
            ::norito::json!({
                "leg_id": (leg.leg_id()),
                "source_account_id": (leg.from().to_string()),
                "destination_account_id": (leg.to().to_string()),
                "asset_definition_id": (leg.asset_definition().to_string()),
                "amount": (leg.amount().to_string()),
            })
        })
        .collect::<Vec<_>>();
    ::norito::json!({
        "kind": "asset_transfer_batch",
        "mode": (match batch.mode() {
            BatchMode::Atomic => "atomic",
            BatchMode::Independent => "independent",
        }),
        "entries": entries,
    })
}

fn value_json(value: &ConditionalEscrowValue) -> JsonValue {
    match value {
        ConditionalEscrowValue::Bool(value) => {
            ::norito::json!({"kind": "bool", "value": (*value)})
        }
        ConditionalEscrowValue::Text(value) => {
            ::norito::json!({"kind": "text", "value": value})
        }
        ConditionalEscrowValue::Quantity(value) => {
            ::norito::json!({"kind": "quantity", "value": (value.to_string())})
        }
    }
}

fn predicate_json(predicate: &ConditionalEscrowPredicate) -> JsonValue {
    match predicate {
        ConditionalEscrowPredicate::Equals(value) => {
            ::norito::json!({"kind": "equals", "value": (value_json(value))})
        }
        ConditionalEscrowPredicate::QuantityAtMost(value) => {
            ::norito::json!({"kind": "quantity_at_most", "value": (value.to_string())})
        }
    }
}

fn condition_json(condition: &ConditionalEscrowCondition) -> JsonValue {
    match condition {
        ConditionalEscrowCondition::Oracle(condition) => ::norito::json!({
            "kind": "oracle",
            "id": (condition.id.to_string()),
            "attestor": (condition.attestor.to_string()),
            "sequence": (condition.sequence.get()),
            "predicate": (predicate_json(&condition.predicate)),
        }),
        ConditionalEscrowCondition::Within(condition) => ::norito::json!({
            "kind": "within",
            "id": (condition.id.to_string()),
            "duration_ms": (condition.duration_ms.get()),
        }),
    }
}

fn escrow_json(escrow: &OpenConditionalEscrow) -> JsonValue {
    ::norito::json!({
        "kind": "conditional_escrow_open",
        "escrow_id": (escrow.escrow_id.as_hash().to_string()),
        "asset_definition_id": (escrow.asset_definition.to_string()),
        "beneficiary": (escrow.beneficiary.to_string()),
        "amount": (escrow.amount.to_string()),
        "conditions": (escrow.conditions.iter().map(condition_json).collect::<Vec<_>>()),
        "expires_at_ms": (escrow.expires_at_ms),
        "evidence_hashes": (escrow.evidence_hashes.iter().map(ToString::to_string).collect::<Vec<_>>()),
    })
}
