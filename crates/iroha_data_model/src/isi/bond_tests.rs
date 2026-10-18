//! Codec, JSON and registry tests for the bond instruction family.
use super::*;
use crate::{
    bond::tests::{account, annual_terms, definition},
    isi::test_support::{assert_registry_decodes, assert_slice_roundtrip},
};
use norito::codec::{Decode, Encode};

fn bond() -> BondId {
    definition("bond")
}

fn instructions() -> Vec<BondInstructionBox> {
    vec![
        RegisterBond::new(bond(), annual_terms()).into(),
        RecordBondCashflow::new(bond(), 0).into(),
        FundBondCashflow::new(bond(), 0, AssetId::new(definition("eur"), account(2))).into(),
        ClaimBondCashflow::new(bond(), 0, account(10)).into(),
        CloseBondCashflow::new(bond(), 0).into(),
        CallBond::new(bond(), 1_799_971_200_000).into(),
        DeclareBondDefault::new(bond(), 1, [5; 32]).into(),
        ReplaceBondPayingAgent::new(bond(), account(3)).into(),
        RetireBondTreasuryUnits::new(bond(), 250_u32).into(),
    ]
}

#[test]
fn bond_instruction_box_roundtrips_through_every_codec_path() {
    for instruction in instructions() {
        let bytes = instruction.encode();
        assert_eq!(
            BondInstructionBox::decode(&mut bytes.as_slice()).expect("decode box"),
            instruction
        );
        assert_slice_roundtrip(instruction.clone());
        assert_eq!(instruction.bond(), &bond());
    }
    assert_slice_roundtrip(RegisterBond::new(bond(), annual_terms()));
    assert_slice_roundtrip(RecordBondCashflow::new(bond(), 3));
    assert_slice_roundtrip(FundBondCashflow::new(
        bond(),
        3,
        AssetId::new(definition("eur"), account(1)),
    ));
    assert_slice_roundtrip(ClaimBondCashflow::new(bond(), 3, account(11)));
    assert_slice_roundtrip(CloseBondCashflow::new(bond(), 3));
    assert_slice_roundtrip(CallBond::new(bond(), 42));
    assert_slice_roundtrip(DeclareBondDefault::new(bond(), 3, [1; 32]));
    assert_slice_roundtrip(ReplaceBondPayingAgent::new(bond(), account(12)));
    assert_slice_roundtrip(RetireBondTreasuryUnits::new(bond(), 7_u32));
}

#[test]
fn bond_registry_decodes_only_the_stable_box_id() {
    let registry = crate::isi::registry::default();
    for instruction in instructions() {
        assert_registry_decodes(&registry, BondInstructionBox::WIRE_ID, instruction);
    }
    for name in [
        std::any::type_name::<RegisterBond>(),
        std::any::type_name::<RecordBondCashflow>(),
        std::any::type_name::<FundBondCashflow>(),
        std::any::type_name::<ClaimBondCashflow>(),
        std::any::type_name::<CloseBondCashflow>(),
        std::any::type_name::<CallBond>(),
        std::any::type_name::<DeclareBondDefault>(),
        std::any::type_name::<ReplaceBondPayingAgent>(),
        std::any::type_name::<RetireBondTreasuryUnits>(),
        std::any::type_name::<BondInstructionBox>(),
    ] {
        assert!(!registry.contains(name), "{name} must remain boxed-only");
    }
    assert_eq!(BondInstructionBox::WIRE_ID, "iroha.bond");
}

#[test]
fn leaf_instructions_box_into_the_bond_family() {
    let instruction = InstructionBox::from(RecordBondCashflow::new(bond(), 2));
    let boxed = instruction
        .as_any()
        .downcast_ref::<BondInstructionBox>()
        .expect("leaf instructions are carried by the bond box");
    assert_eq!(
        boxed,
        &BondInstructionBox::RecordCashflow(RecordBondCashflow::new(bond(), 2))
    );
}

#[test]
fn bond_instruction_json_is_strict_and_roundtrips() {
    let default = DeclareBondDefault::new(bond(), 1, [0xab; 32]);
    let text = norito::json::to_json(&default).expect("default JSON");
    assert!(text.contains(&format!(r#""evidence_sha256":"{}""#, "ab".repeat(32))));
    assert_eq!(
        norito::json::from_str::<DeclareBondDefault>(&text).expect("decode"),
        default
    );
    let register = RegisterBond::new(bond(), annual_terms());
    let text = norito::json::to_json(&register).expect("register JSON");
    assert_eq!(
        norito::json::from_str::<RegisterBond>(&text).expect("decode register"),
        register
    );
    let retire = RetireBondTreasuryUnits::new(bond(), 250_u32);
    let text = norito::json::to_json(&retire).expect("retire JSON");
    assert!(text.contains(r#""quantity":"250""#), "{text}");
    assert_eq!(
        norito::json::from_str::<RetireBondTreasuryUnits>(&text).expect("decode retire"),
        retire
    );
    let claim = ClaimBondCashflow::new(bond(), 0, account(10));
    let text = norito::json::to_json(&claim).expect("claim JSON");
    assert!(
        norito::json::from_str::<ClaimBondCashflow>(&text.replacen('{', r#"{"x":0,"#, 1)).is_err()
    );
    assert_eq!(
        norito::json::from_str::<ClaimBondCashflow>(&text).expect("decode claim"),
        claim
    );
}

#[test]
fn bond_instruction_display_names_the_operation() {
    let rendered: Vec<String> = instructions().iter().map(ToString::to_string).collect();
    for (text, prefix) in rendered.iter().zip([
        "BOND_REGISTER",
        "BOND_RECORD",
        "BOND_FUND",
        "BOND_CLAIM",
        "BOND_CLOSE",
        "BOND_CALL",
        "BOND_DEFAULT",
        "BOND_REPLACE_PAYING_AGENT",
        "BOND_RETIRE_TREASURY",
    ]) {
        assert!(text.starts_with(prefix), "{text}");
    }
}

#[test]
fn unknown_bond_box_tag_is_rejected() {
    let mut bytes = BondInstructionBox::from(CloseBondCashflow::new(bond(), 0)).encode();
    bytes[..4].copy_from_slice(&9_u32.to_le_bytes());
    assert!(
        <BondInstructionBox as norito::core::DecodeFromSlice>::decode_from_slice(&bytes).is_err()
    );
}
