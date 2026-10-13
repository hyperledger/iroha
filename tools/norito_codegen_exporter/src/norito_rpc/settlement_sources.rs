//! Typed semantic sources for payer-scoped bilateral settlement wire fixtures.

use super::*;
use iroha_data_model::isi::{
    DvpIsi, PvpIsi, SettlementAtomicity, SettlementExecutionOrder, SettlementId,
    SettlementInstructionBox, SettlementLeg, SettlementPlan,
};

const ALICE: &str = "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53";
const BOB: &str = "sorauﾛ1P58ﾊt2MaｺxhpﾄｽﾅｲｼKヰkDﾑｱjｴｴ9GFﾉﾌkrｽRzﾑﾌxKBMEBH";
const BOND: &str = "7cgpbDVabB1g8uax9JkhGckEHwfe";
const USD: &str = "4eaant86faGEgeH21U4qTTfpvwSb";
const EUR: &str = "5n4HJrqdiJkuFTa2Kmx2DvXnBkos";

pub(super) fn instruction(fixture_name: &str) -> Result<SettlementInstructionBox> {
    let alice = parse_account_id(ALICE)?;
    let bob = parse_account_id(BOB)?;
    let leg = |asset: &str, quantity: u32, from: &AccountId, to: &AccountId| {
        Ok::<_, eyre::Report>(SettlementLeg {
            asset_definition_id: asset.parse().context("invalid settlement source asset")?,
            quantity: quantity.into(),
            from: from.clone(),
            to: to.clone(),
            metadata: Metadata::default(),
        })
    };
    match fixture_name {
        "settlement_dvp_atomic" => Ok(SettlementInstructionBox::Dvp(DvpIsi::new(
            SettlementId::new(alice.clone(), "dvp_trade_1".parse()?),
            leg(BOND, 1_000, &alice, &bob)?,
            leg(USD, 1_005, &bob, &alice)?,
            SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
        ))),
        "settlement_pvp_net" => Ok(SettlementInstructionBox::Pvp(PvpIsi::new(
            SettlementId::new(alice.clone(), "pvp_fx_1".parse()?),
            leg(USD, 1_000, &alice, &bob)?,
            leg(EUR, 920, &bob, &alice)?,
            SettlementPlan::new(
                SettlementExecutionOrder::PaymentThenDelivery,
                SettlementAtomicity::AllOrNothing,
            ),
        ))),
        _ => bail!("fixture '{fixture_name}' has no bilateral settlement semantic source"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bilateral_sources_bind_original_payer_reference_and_complete_terms() {
        for (name, reference, first_asset, first_quantity, second_asset, second_quantity, order) in [
            (
                "settlement_dvp_atomic",
                "dvp_trade_1",
                BOND,
                1_000_u32,
                USD,
                1_005_u32,
                SettlementExecutionOrder::DeliveryThenPayment,
            ),
            (
                "settlement_pvp_net",
                "pvp_fx_1",
                USD,
                1_000_u32,
                EUR,
                920_u32,
                SettlementExecutionOrder::PaymentThenDelivery,
            ),
        ] {
            let source = instruction(name).expect("typed bilateral source");
            let (id, first, second, plan, metadata) = match &source {
                SettlementInstructionBox::Dvp(value) => (
                    value.settlement_id(),
                    value.delivery_leg(),
                    value.payment_leg(),
                    value.plan(),
                    value.metadata(),
                ),
                SettlementInstructionBox::Pvp(value) => (
                    value.settlement_id(),
                    value.primary_leg(),
                    value.counter_leg(),
                    value.plan(),
                    value.metadata(),
                ),
                _ => panic!("bilateral source required"),
            };
            assert_eq!(id.owner(), &parse_account_id(ALICE).unwrap());
            assert_eq!(id.reference().as_ref(), reference);
            assert_eq!(first.asset_definition_id.to_string(), first_asset);
            assert_eq!(first.quantity, first_quantity.into());
            assert_eq!(first.from.to_string(), ALICE);
            assert_eq!(first.to.to_string(), BOB);
            assert_eq!(second.asset_definition_id.to_string(), second_asset);
            assert_eq!(second.quantity, second_quantity.into());
            assert_eq!(second.from.to_string(), BOB);
            assert_eq!(second.to.to_string(), ALICE);
            assert_eq!(plan.order(), order);
            assert_eq!(plan.atomicity(), SettlementAtomicity::AllOrNothing);
            assert_eq!(metadata, &Metadata::default());
            assert_eq!(first.metadata, Metadata::default());
            assert_eq!(second.metadata, Metadata::default());
            let boxed: InstructionBox = source.into();
            let payload = Instruction::dyn_encode(&*boxed);
            let framed = frame_instruction_payload("iroha.settlement", &payload).unwrap();
            let decoded = decode_instruction_from_pair("iroha.settlement", &framed).unwrap();
            assert_eq!(Instruction::dyn_encode(&*decoded), payload);
        }
        assert!(instruction("unowned_settlement").is_err());
    }

    #[test]
    fn bilateral_sources_require_exact_wire_and_slot_without_decoding_retired_bytes() {
        for name in ["settlement_dvp_atomic", "settlement_pvp_net"] {
            let slot = InstructionSourceSlot::Instructions(0);
            validate_semantic_instruction_observations(name, &[(slot, "iroha.settlement")])
                .expect("exact owned shape");
            for observed in [
                vec![],
                vec![(slot, "iroha.transfer")],
                vec![(InstructionSourceSlot::Batch(0), "iroha.settlement")],
                vec![(slot, "iroha.settlement"), (slot, "iroha.settlement")],
            ] {
                assert!(validate_semantic_instruction_observations(name, &observed).is_err());
            }
            let raw = RawInstruction {
                wire_name: "iroha.settlement".into(),
                payload_base64: "retired bytes must never be decoded".into(),
            };
            let built = build_fixture_instruction(name, slot, &raw).unwrap();
            let expected: InstructionBox = instruction(name).unwrap().into();
            assert_eq!(
                Instruction::dyn_encode(&*built),
                Instruction::dyn_encode(&*expected)
            );
            assert!(
                build_fixture_instruction(name, InstructionSourceSlot::Instructions(1), &raw)
                    .is_err()
            );
            let wrong_wire = RawInstruction {
                wire_name: "iroha.transfer".into(),
                ..raw
            };
            assert!(build_fixture_instruction(name, slot, &wrong_wire).is_err());
        }
    }
}
