//! Native executed charges retained in their exact consensus result leaves.
//! Component execution is real; these tests grant no finality or release authority.

use super::*;
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    block::consensus::NexusFeeSettlementV1,
    nexus::FeeDebitSource,
    transaction::{FeeChargeKind, FeeChargeLimit},
};
use iroha_primitives::numeric::Quantity;

fn priced(row_bytes: u64, callback_bytes: Option<usize>) -> (State, AssetDefinitionId) {
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    (
        fixture_with_fee_asset(row_bytes, callback_bytes, Some(asset.clone())),
        asset,
    )
}
fn payment(asset: &AssetDefinitionId) -> FeePaymentIntent {
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(1_u32),
        )],
        None,
    )
}
fn balance(block: &StateBlock<'_>, asset: &AssetDefinitionId) -> Quantity {
    block
        .world
        .assets()
        .get(&AssetId::of(asset.clone(), ALICE_ID.clone()))
        .map_or_else(Quantity::zero, |value| value.0.clone())
}

#[test]
fn success_and_business_rejection_publish_only_their_actual_charge_once() {
    let _guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    for reject in [false, true] {
        let (state, asset) = priced(65_536, None);
        let body = if reject {
            vec![Unregister::trigger("missing_fee_receipt_trigger".parse().unwrap()).into()]
        } else {
            vec![Log::new(Level::INFO, "actual paid receipt".to_owned()).into()]
        };
        let source = carrier(&state, vec![input(&state, body, payment(&asset), false)]);
        let original = source.network_entrypoint_at(0).unwrap();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        execute(&mut block, &source).unwrap();
        let result = &network_row(&block, 0).result;
        assert_eq!(result.is_err(), reject);
        let receipt = result
            .nexus_fee_receipt()
            .expect("actual charge in exact result");
        receipt.validate_for_network_input(original, 2).unwrap();
        assert_eq!(receipt.fee_amount, Quantity::from(1_u32));
        assert_eq!(receipt.fee_asset_id, asset);
        assert_eq!(
            receipt.debit_source,
            FeeDebitSource::Account(ALICE_ID.clone())
        );
        assert_eq!(receipt.settlement, NexusFeeSettlementV1::Burn);
        assert_eq!(
            receipt.dataspace_id,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL
        );
        assert_eq!(receipt.lane_id, iroha_model_base::topology::LaneId::SINGLE);
        assert_eq!(balance(&block, &asset), Quantity::from(9_u32));
        assert_eq!(
            block
                .world
                .asset_definition(&asset)
                .unwrap()
                .total_quantity(),
            &Quantity::from(9_u32)
        );
        assert!(execute(&mut block, &source).is_err());
        assert_eq!(balance(&block, &asset), Quantity::from(9_u32));
    }
}

#[test]
fn healthy_output_overflow_discards_the_unpaid_receipt_and_actual_burn() {
    let _guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let (state, asset) = priced(16_384, Some(32_768));
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![ExecuteTrigger::new("network_callback".parse().unwrap()).into()],
            payment(&asset),
            false,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).unwrap();
    assert!(retained(&block).rows[0].is_output_limit_rejection());
    assert!(network_row(&block, 0).result.nexus_fee_receipt().is_none());
    assert_eq!(balance(&block, &asset), Quantity::from(10_u32));
    assert_eq!(
        block
            .world
            .asset_definition(&asset)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}

#[test]
fn failed_charge_has_no_fee_receipt_or_balance_supply_effect() {
    let _guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let (mut state, asset) = priced(65_536, None);
    // Sign a valid nonzero cap, then reject it against the actual configured fee.
    {
        let mut fees = state.nexus_snapshot().fees;
        fees.base_fee = Quantity::from(2_u32);
        {
            let mut parameters = state.world.parameters.block();
            parameters
                .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                    fees.clone()
                        .into_custom_parameter()
                        .expect("explicit fixture policy"),
                ))
                .expect("valid fixture monetary projection");
            parameters.commit();
        }
    }
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![Log::new(Level::INFO, "unfunded signed limit".to_owned()).into()],
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset.clone(),
                    Quantity::from(1_u32),
                )],
                None,
            ),
            false,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).unwrap();
    assert!(network_row(&block, 0).result.is_err());
    assert!(network_row(&block, 0).result.nexus_fee_receipt().is_none());
    assert_eq!(balance(&block, &asset), Quantity::from(10_u32));
    assert_eq!(
        block
            .world
            .asset_definition(&asset)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}
