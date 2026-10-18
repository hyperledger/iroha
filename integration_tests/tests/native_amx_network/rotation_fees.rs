//! Actual rotation fee history, complete authenticated balances and burn accounting.
//!
//! Global staking custody remains owned by the ceremony's specialized receipts.
//! This audit authenticates every fee and complete final fee inventory, reconciles
//! supply, and additionally reconstructs each bank's exact fee-account balances.

use super::*;
use iroha_data_model::{
    Identifiable,
    asset::{Asset, AssetValue},
    block::consensus::NexusFeeSettlementV1,
    isi::{Burn, BurnBox, Mint, MintBox, TransferBox},
    nexus::FeeDebitSource,
    query::{
        asset::{FindAssetDefinitionById, FindAssets},
        builder::QueryBuilderExt,
        parameters::Pagination,
    },
    sumeragi_finality::authenticate_signed_genesis_v1,
    transaction::{Executable, FeeChargeKind, TransactionEntrypoint},
};
use std::collections::BTreeMap;

type Balances = BTreeMap<AssetId, Quantity>;

// The delayed bank has genesis, one approval, the original Prepare, two funding
// transfers, three authenticated handoffs, the original Settle and one paid
// rejection. Each signed carrier can add at most one block; no other bank work
// is authorized by this scenario. The healthy bank requires fewer carriers.
const MAX_BANK_HISTORY_HEIGHT: u64 = 1 + 1 + 1 + 2 + 3 + 1 + 1;

fn mint(instruction: &InstructionBox) -> Option<&Mint<Quantity, Asset>> {
    instruction
        .as_any()
        .downcast_ref::<Mint<Quantity, Asset>>()
        .or_else(|| match instruction.as_any().downcast_ref::<MintBox>() {
            Some(MintBox::Asset(value)) => Some(value),
            _ => None,
        })
}

fn burn(instruction: &InstructionBox) -> Option<&Burn<Quantity, Asset>> {
    instruction
        .as_any()
        .downcast_ref::<Burn<Quantity, Asset>>()
        .or_else(|| match instruction.as_any().downcast_ref::<BurnBox>() {
            Some(BurnBox::Asset(value)) => Some(value),
            _ => None,
        })
}

fn transfer(instruction: &InstructionBox) -> Option<&Transfer<Asset, Quantity, Account>> {
    instruction
        .as_any()
        .downcast_ref::<Transfer<Asset, Quantity, Account>>()
        .or_else(
            || match instruction.as_any().downcast_ref::<TransferBox>() {
                Some(TransferBox::Asset(value)) => Some(value),
                _ => None,
            },
        )
}

fn add(balances: &mut Balances, asset: AssetId, amount: &Quantity) -> Result<()> {
    let value = balances.entry(asset).or_insert_with(Quantity::zero);
    *value = value.checked_add(amount)?;
    Ok(())
}

fn subtract(balances: &mut Balances, asset: &AssetId, amount: &Quantity) -> Result<()> {
    let value = balances
        .get_mut(asset)
        .ok_or_else(|| eyre!("fee history debits an unfunded exact bucket"))?;
    *value = value.checked_sub(amount)?;
    Ok(())
}

fn move_funding(balances: &mut Balances, value: &Transfer<Asset, Quantity, Account>) -> Result<()> {
    let destination = AssetId::with_scope(
        value.source.definition().clone(),
        value.destination.clone(),
        value.source.scope().clone(),
    );
    // Calculate both results before publishing either side, including self-transfer.
    let mut next = balances.clone();
    subtract(&mut next, &value.source, &value.object)?;
    add(&mut next, destination, &value.object)?;
    *balances = next;
    Ok(())
}

fn refuse_supply_mutation(instructions: &[InstructionBox]) -> Result<()> {
    for instruction in instructions {
        ensure!(
            mint(instruction).is_none() && burn(instruction).is_none(),
            "rotation workload must not mint or explicitly burn any asset after genesis"
        );
    }
    Ok(())
}

fn genesis_funding(root: &amx::Root) -> Result<(Quantity, Balances)> {
    let selected = authenticate_signed_genesis_v1(&root.genesis_wire, &root.pins)?;
    let mut supply = Quantity::zero();
    let mut balances = Balances::new();
    for signed in selected.block().external_transactions() {
        let Executable::Instructions(instructions) = signed.instructions() else {
            return Err(eyre!(
                "rotation genesis funding must use explicit original instructions"
            ));
        };
        for instruction in instructions {
            if let Some(value) = mint(instruction)
                .filter(|value| value.destination.definition() == &amx::fee_asset())
            {
                supply = supply.checked_add(&value.object)?;
                add(&mut balances, value.destination.clone(), &value.object)?;
            }
            ensure!(
                !burn(instruction)
                    .is_some_and(|value| value.destination.definition() == &amx::fee_asset()),
                "unexpected fee-asset burn in rotation genesis"
            );
            // Bank genesis is a direct monetary fixture. Global staking may move
            // balances internally, but cannot change the sum of the signed mints.
            if root.index != 0 {
                if let Some(value) = transfer(instruction)
                    .filter(|value| value.source.definition() == &amx::fee_asset())
                {
                    move_funding(&mut balances, value)?;
                }
            }
        }
    }
    ensure!(!supply.is_zero(), "signed original fee funding is absent");
    Ok((supply, balances))
}

pub(super) fn audit(
    root: &amx::Root,
    height: u64,
    runtime: &tokio::runtime::Runtime,
) -> Result<()> {
    let maximum = if root.index == 0 {
        ROTATION_HISTORY_BOUND
    } else {
        MAX_BANK_HISTORY_HEIGHT
    };
    ensure!(
        (2..=maximum).contains(&height),
        "fee history exceeds its actual workload bound"
    );
    let (initial_supply, mut bank_balances) = genesis_funding(root)?;
    runtime.block_on(async {
        let cut = amx::fees::world_cut(root).await?;
        ensure!(cut.attestation.body.finality_proof.block_header.height().get() == height,
            "rotation fee audit must retain its exact quiescent cut");
        let mut verifier = root.verifier()?;
        let mut burned = Quantity::zero();
        let mut charged_carriers = 0_u64;
        let mut tip = None;
        for next in verifier.authenticated_height().unwrap_or(0) + 1..=height {
            let proof = if next == height {
                cut.attestation.body.finality_proof.clone()
            } else {
                root.client(&amx::genesis_key(root.index)).client()
                    .get_sumeragi_finality_proof_async(NonZeroU64::new(next).unwrap(), root.scope).await?
            };
            let block = verifier.verify(&proof)?;
            if next > 1 {
                for (index, input) in block.block().network_entrypoints().enumerate() {
                    let TransactionEntrypoint::External(signed) = input else {
                        return Err(eyre!("rotation fee audit encountered an unexpected network input"));
                    };
                    let Executable::Instructions(instructions) = signed.instructions() else {
                        return Err(eyre!("rotation monetary workload must retain exact native instructions"));
                    };
                    refuse_supply_mutation(instructions.as_ref())?;
                    ensure!(!signed.fee_payment_intent().charge_limits().is_empty()
                        && signed.fee_payment_intent().charge_limits().iter().all(|limit| limit.kind == FeeChargeKind::Nexus),
                        "every rotation carrier must explicitly authorize its Nexus-only fee");
                    let original = amx::proofs::evidence(block.block(), index.try_into()?)?;
                    block.verify_transaction_execution(&root.network.network_id(), &original)?;
                    let fee = original.output.result().nexus_fee_receipt()
                        .ok_or_else(|| eyre!("rotation carrier has no authenticated fee outcome at {next}"))?;
                    fee.validate_for_network_input(&original.entrypoint, next).map_err(|error| eyre!(error))?;
                    ensure!(fee.fee_asset_id == amx::fee_asset()
                        && fee.dataspace_id == root.scope.dataspace_id()
                        && fee.settlement == NexusFeeSettlementV1::Burn
                        && !fee.fee_amount.is_zero()
                        && fee.debit_source == FeeDebitSource::Account(signed.authority().clone()),
                        "actual rotation fee differs from its authority, root, asset or burn contract");
                    burned = burned.checked_add(&fee.fee_amount)?;
                    charged_carriers = charged_carriers.checked_add(1).ok_or_else(|| eyre!("fee carrier count overflow"))?;
                    if root.index != 0 {
                        // Only successful funding transfers affect the bank's fee
                        // principal; rejected carriers still pay their actual fee.
                        if original.output.result().is_ok() {
                            for instruction in instructions {
                                if let Some(value) = transfer(instruction).filter(|value| value.source.definition() == &amx::fee_asset()) {
                                    move_funding(&mut bank_balances, value)?;
                                }
                            }
                        }
                        let bucket = AssetId::with_scope(amx::fee_asset(), signed.authority().clone(),
                            AssetBalanceScope::Dataspace(root.scope.dataspace_id()));
                        subtract(&mut bank_balances, &bucket, &fee.fee_amount)?;
                    }
                }
            }
            tip = Some(block);
        }
        ensure!(charged_carriers > 0 && !burned.is_zero());
        let tip = tip.ok_or_else(|| eyre!("rotation has no authenticated final cut"))?;
        let world = cut.world_snapshot.authenticate(&tip)?;
        ensure!(world.schema_hash() == iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?);
        // The authenticated complete table itself supplies the read bound. The
        // extra row detects inconsistent query pagination; no failed query or
        // missing response is interpreted as balance absence.
        let count = cut.world_snapshot.entries.iter().filter(|entry| entry.field_id == "world.assets").count();
        let limit = NonZeroU64::new(u64::try_from(count)?.checked_add(1).ok_or_else(|| eyre!("asset row count overflow"))?).unwrap();
        let client = root.client(&amx::genesis_key(root.index));
        let (assets, definition) = iroha_test_network::read_on_dedicated_thread(move || -> Result<_> {
            let assets = client.client().query(FindAssets::new())
                .with_pagination(Pagination { limit: Some(limit), offset: 0 }).execute_all()?;
            let definition = client.client().query_single(FindAssetDefinitionById::new(amx::fee_asset()))?;
            Ok((assets, definition))
        }).await?;
        ensure!(assets.len() == count, "asset response differs from exact certified complete table count");
        world.verify_asset_keys_complete(&assets.iter().map(|asset| asset.id().clone()).collect::<Vec<_>>())?;
        let mut fee_balances = Balances::new();
        for asset in assets {
            world.verify_table_value("world.assets", asset.id(), &AssetValue::new(asset.value().clone()))?;
            if asset.id().definition() == &amx::fee_asset() {
                ensure!(fee_balances.insert(asset.id().clone(), asset.value().clone()).is_none());
            }
        }
        world.verify_table_value("world.asset_definitions", &amx::fee_asset(), &definition)?;
        let expected_supply = initial_supply.checked_sub(&burned)?;
        let actual_sum = fee_balances.values().try_fold(Quantity::zero(), |sum, value| sum.checked_add(value))?;
        ensure!(definition.total_quantity() == &expected_supply && actual_sum == expected_supply,
            "all original carrier burns must reconcile both authenticated supply and the complete fee-asset inventory");
        if root.index != 0 {
            bank_balances.retain(|_, amount| !amount.is_zero());
            ensure!(fee_balances == bank_balances,
                "every bank fee balance must equal actual genesis funding and successful transfers less every charged carrier");
        }
        Ok(())
    })
}

#[test]
fn bank_fee_history_accounts_exact_funding_and_refuses_missing_or_excess_debits() {
    let source = AssetId::with_scope(
        amx::fee_asset(),
        amx::account(&amx::payer(1)),
        AssetBalanceScope::Dataspace(amx::DATASPACES[1]),
    );
    let recipient = amx::account(&amx::relay(2));
    let destination =
        AssetId::with_scope(amx::fee_asset(), recipient.clone(), source.scope().clone());
    let mut balances = Balances::from([(source.clone(), Quantity::from(100_u32))]);
    move_funding(
        &mut balances,
        &Transfer::asset_quantity(source.clone(), 40_u32, recipient),
    )
    .unwrap();
    subtract(&mut balances, &source, &Quantity::from(2_u32)).unwrap();
    subtract(&mut balances, &destination, &Quantity::from(40_u32)).unwrap();
    assert_eq!(balances[&source], Quantity::from(58_u32));
    assert_eq!(balances[&destination], Quantity::zero());
    let original = balances.clone();
    assert!(subtract(&mut balances, &destination, &Quantity::one()).is_err());
    assert_eq!(balances, original);
    let absent = AssetId::of(amx::fee_asset(), amx::account(&amx::payer(0)));
    assert!(subtract(&mut balances, &absent, &Quantity::one()).is_err());
    assert_eq!(balances, original);
}

#[test]
fn rotation_fee_inventory_refuses_post_genesis_fee_supply_changes() {
    let asset = AssetId::of(amx::fee_asset(), amx::account(&amx::genesis_key(0)));
    assert!(refuse_supply_mutation(&[Mint::asset_quantity(1_u32, asset.clone()).into()]).is_err());
    assert!(refuse_supply_mutation(&[Burn::asset_quantity(1_u32, asset.clone()).into()]).is_err());
    let other = AssetId::of(customer_asset(), customer());
    assert!(refuse_supply_mutation(&[Mint::asset_quantity(1_u32, other.clone()).into()]).is_err());
    assert!(refuse_supply_mutation(&[Burn::asset_quantity(1_u32, other).into()]).is_err());
    refuse_supply_mutation(&[
        Transfer::asset_quantity(asset, 1_u32, amx::account(&amx::relay(0))).into(),
    ])
    .unwrap();
}
