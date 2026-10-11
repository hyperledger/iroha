//! Emit native transfer, metadata and trigger instruction frames for SDK parity.

use std::fmt::Write as _;

use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
use iroha_data_model::{
    account::{AccountId, address::ChainDiscriminantGuard},
    isi::{
        Burn, CustomInstruction, ExecuteTrigger, InstructionBox, Mint, RemoveKeyValue,
        SetAssetKeyValue, SetKeyValue, Transfer, decode_instruction_from_pair,
        frame_instruction_payload, framed_instruction_payload,
    },
    prelude::{AssetDefinitionId, AssetId, NftId},
    trigger::TriggerId,
};
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use norito::{json, json::Value};

// Fixture v1 fixes bare payloads to Norito v1 COMPACT_LEN (0x02). Framed
// instruction bytes independently carry their native schema and layout headers.
const LAYOUT_FLAGS: u8 = 0x02;

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("write into String");
    }
    result
}

fn case(name: &str, instruction: &InstructionBox, enum_family: bool) -> Value {
    let (wire_id, frame) = framed_instruction_payload(instruction).expect("registered instruction");
    let decoded = decode_instruction_from_pair(wire_id, &frame).expect("native instruction decode");
    assert_eq!(decoded, *instruction);
    let instruction_box = norito::to_bytes(instruction).expect("native InstructionBox frame");
    let decoded_box: InstructionBox =
        norito::decode_from_bytes(&instruction_box).expect("native InstructionBox decode");
    assert_eq!(decoded_box, *instruction);
    let header = norito::core::Header::read(frame.as_slice()).expect("native frame header");
    assert_eq!(header.flags, LAYOUT_FLAGS);
    if enum_family {
        // Reproduce the managed flattening defect while retaining a valid native
        // schema, declared flags and checksum; rejection must come from fields.
        let payload = &frame
            [frame.len() - usize::try_from(header.length).expect("bounded native frame length")..];
        let (length, prefix) =
            norito::core::read_len_from_slice_with_flags(&payload[4..], LAYOUT_FLAGS).unwrap();
        let fields = &payload[4 + prefix..];
        assert_eq!(length, fields.len());
        let mut flattened = payload[..4].to_vec();
        flattened.extend_from_slice(fields);
        let bad = frame_instruction_payload(wire_id, &flattened).unwrap();
        assert!(decode_instruction_from_pair(wire_id, &bad).is_err());
    }
    json!({
        "name": name,
        "wire_id": wire_id,
        "framed_instruction_hex": (hex(&frame)),
        "instruction_box_payload_hex": (hex(&norito::codec::encode_adaptive(instruction))),
        "instruction_box_frame_hex": (hex(&instruction_box)),
    })
}

fn fixture() -> Value {
    assert_eq!(norito::core::default_encode_flags(), LAYOUT_FLAGS);
    let _guard = ChainDiscriminantGuard::enter(753);
    // Public disposable fixture inputs, never wallet or deployment credentials.
    let source = AccountId::new(
        KeyPair::from_private_key(PrivateKey::from_bytes(Algorithm::Ed25519, &[0x31; 32]).unwrap())
            .unwrap()
            .public_key()
            .clone(),
    );
    let destination = AccountId::new(
        KeyPair::from_private_key(PrivateKey::from_bytes(Algorithm::Ed25519, &[0x32; 32]).unwrap())
            .unwrap()
            .public_key()
            .clone(),
    );
    let domain = DomainId::parse_fully_qualified("xn--bcher-kva.universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
    let nft = NftId::new(domain, "dragon".parse().unwrap());
    let trigger: TriggerId = "settlement_window".parse().unwrap();
    let instructions: [(&str, InstructionBox); 12] = [
        (
            "TransferAssetDefinition",
            Transfer::asset_definition(source.clone(), definition.clone(), destination.clone())
                .into(),
        ),
        (
            "TransferNft",
            Transfer::nft(source.clone(), nft.clone(), destination.clone()).into(),
        ),
        (
            "SetAccountKeyValue",
            SetKeyValue::account(source.clone(), "memo".parse().unwrap(), "fixture metadata")
                .into(),
        ),
        (
            "RemoveAccountKeyValue",
            RemoveKeyValue::account(source.clone(), "memo".parse().unwrap()).into(),
        ),
        (
            "SetAssetDefinitionKeyValue",
            SetKeyValue::asset_definition(
                definition.clone(),
                "memo".parse().unwrap(),
                "fixture metadata",
            )
            .into(),
        ),
        (
            "RemoveAssetDefinitionKeyValue",
            RemoveKeyValue::asset_definition(definition.clone(), "memo".parse().unwrap()).into(),
        ),
        (
            "SetNftKeyValue",
            SetKeyValue::nft(nft.clone(), "memo".parse().unwrap(), "fixture metadata").into(),
        ),
        (
            "RemoveNftKeyValue",
            RemoveKeyValue::nft(nft.clone(), "memo".parse().unwrap()).into(),
        ),
        (
            "SetTriggerKeyValue",
            SetKeyValue::trigger(trigger.clone(), "memo".parse().unwrap(), "fixture metadata")
                .into(),
        ),
        (
            "RemoveTriggerKeyValue",
            RemoveKeyValue::trigger(trigger.clone(), "memo".parse().unwrap()).into(),
        ),
        (
            "MintTriggerRepetitions",
            Mint::trigger_repetitions(7, trigger.clone()).into(),
        ),
        (
            "BurnTriggerRepetitions",
            Burn::trigger_repetitions(3, trigger.clone()).into(),
        ),
    ];
    let mut cases: Vec<_> = instructions
        .into_iter()
        .map(|(name, instruction)| case(name, &instruction, true))
        .collect();
    // This direct instruction shares TriggerId encoding with four enum variants.
    cases.push(case(
        "ExecuteTrigger",
        &ExecuteTrigger::new(trigger.clone())
            .with_args(json!({"force": true}))
            .into(),
        false,
    ));
    cases.push(case(
        "SetAssetKeyValue",
        &SetAssetKeyValue::new(
            AssetId::new(definition.clone(), source.clone()),
            "memo".parse().unwrap(),
            "fixture metadata",
        )
        .into(),
        false,
    ));
    cases.push(case(
        "CustomInstruction",
        &CustomInstruction::new(json!({"force": true})).into(),
        false,
    ));
    let mut metadata = Metadata::default();
    let json_values: Vec<_> = [
        Value::Null,
        json!({"z": true, "a": "text"}),
        Value::String("fixture metadata".to_owned()),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, value)| {
        let instruction =
            SetKeyValue::account(source.clone(), "memo".parse().unwrap(), value.clone());
        let json = instruction.value();
        metadata.insert(format!("key_{index}").parse().unwrap(), value.clone());
        json!({"value": value, "payload_hex": (hex(&norito::codec::encode_adaptive(json)))})
    })
    .collect();
    json!({
        "fixture_version": 1,
        "norito_layout_version": 1,
        "norito_layout_flags": LAYOUT_FLAGS,
        "generator": "iroha_data_model/examples/typed_transaction_fixture.rs",
        "authority": (source.to_string()),
        "destination": (destination.to_string()),
        "asset_definition_id": (definition.to_string()),
        "nft_id": (nft.to_string()),
        "trigger_id": (trigger.to_string()),
        "metadata_key": "memo",
        "metadata_value": "fixture metadata",
        "cases": cases,
        "json_values": json_values,
        "metadata_payload_hex": (hex(&norito::codec::encode_adaptive(&metadata))),
    })
}

fn main() {
    println!(
        "{}",
        json::to_json_pretty(&fixture()).expect("render native fixture")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_native_instruction_pairs_and_boxes_roundtrip() {
        let generated = fixture();
        assert_eq!(
            generated.get("cases").unwrap().as_array().unwrap().len(),
            15
        );
    }
    #[test]
    fn declared_layout_matches_native_default() {
        assert_eq!(LAYOUT_FLAGS, norito::core::default_encode_flags());
        assert_eq!(LAYOUT_FLAGS, 0x02);
    }
    #[test]
    fn native_generation_is_deterministic() {
        assert_eq!(fixture(), fixture());
    }
}
