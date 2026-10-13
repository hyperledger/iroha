//! Consensus namespace controls across every native settlement receipt writer.

use super::*;

#[test]
fn settlement_namespace_bilateral_writers_reject_nonparticipating_owners() {
    for pvp in [false, true] {
        let (state, delivery, payment) = settlement_state();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"foreign namespace"));
        let id = SettlementId::new(CARPENTER_ID.clone(), "shared_reference".parse().unwrap());
        let first = SettlementLeg::new(delivery.clone(), 1_u32, ALICE_ID.clone(), BOB_ID.clone());
        let second = SettlementLeg::new(payment.clone(), 100_u32, BOB_ID.clone(), ALICE_ID.clone());
        let events = stx.world.internal_event_buf.len();
        let transcripts = stx.pending_transfer_transcript_count_for_testing();
        let result = if pvp {
            let instruction = PvpIsi::new(id.clone(), first, second, SettlementPlan::default());
            grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
            instruction.execute(&ALICE_ID, &mut stx)
        } else {
            let instruction = DvpIsi::new(id.clone(), first, second, SettlementPlan::default());
            grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
            instruction.execute(&ALICE_ID, &mut stx)
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("settlement id owner")
        );
        assert!(stx.world.settlement_receipts.get(&id).is_none());
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(delivery, ALICE_ID.clone())),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(payment, BOB_ID.clone())),
            Quantity::from(1_000_u32)
        );
        assert_eq!(stx.world.internal_event_buf.len(), events);
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts
        );
    }
}

#[test]
fn settlement_namespace_authorized_debit_owners_can_reuse_the_same_reference() {
    let (state, delivery, payment) = settlement_state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"two owner namespaces"));
    for owner in [ALICE_ID.clone(), BOB_ID.clone()] {
        let id = SettlementId::new(owner, "same_reference".parse().unwrap());
        let instruction = DvpIsi::new(
            id.clone(),
            SettlementLeg::new(delivery.clone(), 1_u32, ALICE_ID.clone(), BOB_ID.clone()),
            SettlementLeg::new(payment.clone(), 100_u32, BOB_ID.clone(), ALICE_ID.clone()),
            SettlementPlan::default(),
        );
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        instruction.execute(&ALICE_ID, &mut stx).unwrap();
        assert!(stx.world.settlement_receipts.get(&id).is_some());
    }
    assert_eq!(stx.world.settlement_receipts.len(), 2);
    assert_eq!(
        asset_balance_or_zero(&stx, &AssetId::new(delivery, ALICE_ID.clone())),
        Quantity::from(8_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &AssetId::new(payment, BOB_ID.clone())),
        Quantity::from(800_u32)
    );
}

#[test]
fn settlement_namespace_fx_requires_actual_payer_not_reserve_owner() {
    let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"fx payer namespace"));
    let mut instruction = fx_settlement(&policy, "fx_reference", 10);
    instruction.settlement_id.owner = policy.owner;
    let events = stx.world.internal_event_buf.len();
    let transcripts = stx.pending_transfer_transcript_count_for_testing();
    assert!(
        instruction
            .execute(&ALICE_ID, &mut stx)
            .unwrap_err()
            .to_string()
            .contains("settlement id owner")
    );
    assert_eq!(stx.world.settlement_receipts.len(), 0);
    assert_eq!(stx.world.internal_event_buf.len(), events);
    assert_eq!(
        stx.pending_transfer_transcript_count_for_testing(),
        transcripts
    );
}
