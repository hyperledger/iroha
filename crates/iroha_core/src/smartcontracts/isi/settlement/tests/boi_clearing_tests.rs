//! Actual native settlement against the BOI WHO-03/04/05 economic vectors.
//! Standing BOI mandates and its replay-to-original-receipt adapter are separate policy.
use super::*;

#[test]
fn boi_wholesale_vectors_preserve_gross_funding_balances_and_once_only_receipts() {
    for (amount, succeeds, expected_a, expected_b) in [
        (75_000_u32, true, 925_000_u32, 575_000_u32), // WHO-03
        (1_000_001, false, 1_000_000, 500_000),       // WHO-04
        (25_000, true, 975_000, 525_000),             // WHO-05
    ] {
        let (state, sources, _) = atomic_state_in_scope_with_source_delta_limit(
            2,
            AssetBalanceScope::Global,
            AssetBalancePolicy::Global,
            16,
            Quantity::from(1_000_000_u32),
        );
        let source = sources[0].source.clone();
        let destination = sources[1].source.clone();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let replay_carrier = Hash::new(b"boi-wholesale-replay");
        block.admit_fastpq_source_for_testing(replay_carrier);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"atomic-fixture-carrier"));
        // Establish the exact catalog FI-B starting balance via a native monetary operation.
        Burn::asset_quantity(Quantity::from(500_000_u32), destination.clone())
            .execute(destination.account(), &mut stx)
            .expect("prepare original FI-B balance");
        let instruction = atomic_instruction(
            &stx,
            vec![AtomicSettlementMovement {
                source: source.clone(),
                recipient: destination.account().clone(),
                quantity: Quantity::from(amount),
            }],
        );
        install_atomic_consents(&mut stx, &CARPENTER_ID, &instruction, None);
        let before = atomic_observable_state(&stx);
        let outcome = instruction.clone().execute(&CARPENTER_ID, &mut stx);
        if succeeds {
            outcome.expect("gross-funded BOI clearing vector");
            let receipt = stx
                .world
                .settlement_receipts
                .get(instruction.settlement_id())
                .expect("native final business receipt");
            assert_eq!(receipt.authority, *CARPENTER_ID);
            assert_eq!(receipt.details.movements().count(), 1);
            assert!(
                matches!(&receipt.details, SettlementDetails::Atomic(details)
                if details.intent_hash == instruction.intent_hash().unwrap()
                    && details.movements == instruction.movements.resolve().unwrap()
                    && details.escrow_ids.is_empty())
            );
            let settled = atomic_observable_state(&stx);
            stx.tx_call_hash = Some(replay_carrier);
            assert!(instruction.execute(&CARPENTER_ID, &mut stx).is_err());
            assert_eq!(atomic_observable_state(&stx), settled);
        } else {
            assert!(matches!(
                outcome,
                Err(InstructionExecutionError::Math(
                    MathError::NotEnoughQuantity
                ))
            ));
            assert_eq!(atomic_observable_state(&stx), before);
        }
        assert_eq!(
            asset_balance_or_zero(&stx, &source),
            Quantity::from(expected_a)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &destination),
            Quantity::from(expected_b)
        );
    }
}
