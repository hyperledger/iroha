use eyre::Result;
use iroha_client::{client, data_model::prelude::*};
use iroha_data_model::asset::AssetValue;
use test_network::*;

use crate::integration::new_account_with_random_public_key;

#[test]
fn must_execute_both_triggers() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_650).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose_1".parse()?,
        Action::new(
            [instruction.clone()],
            Repeats::Indefinitely,
            account_id.clone(),
            TriggeringEventFilterBox::Data(DataEventFilter::Account(
                AccountEventFilter::new().only_events(AccountEventSet::Created),
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose_2".parse()?,
        Action::new(
            [instruction],
            Repeats::Indefinitely,
            account_id,
            TriggeringEventFilterBox::Data(DataEventFilter::Domain(
                DomainEventFilter::new().only_events(DomainEventSet::Created),
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(Register::account(new_account_with_random_public_key(
        "bunny@wonderland".parse()?,
    )))?;
    test_client.submit_blocking(Register::domain(Domain::new("neverland".parse()?)))?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(numeric!(2)).unwrap());

    Ok(())
}

#[test]
fn domain_scoped_trigger_must_be_executed_only_on_events_in_its_domain() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_655).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let create_neverland_domain: InstructionBox =
        Register::domain(Domain::new("neverland".parse()?)).into();

    let account_id: AccountId = "sapporo@neverland".parse()?;
    let create_sapporo_account =
        Register::account(new_account_with_random_public_key(account_id.clone())).into();

    let asset_definition_id: AssetDefinitionId = "sakura#neverland".parse()?;
    let create_sakura_asset_definition =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();

    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let create_sakura_asset = Register::asset(Asset::new(asset_id.clone(), 0_u32)).into();

    test_client.submit_all_blocking([
        create_neverland_domain,
        create_sapporo_account,
        create_sakura_asset_definition,
        create_sakura_asset,
    ])?;

    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let register_trigger = Register::trigger(Trigger::new(
        "mint_sakura$neverland".parse()?,
        Action::new(
            [Mint::asset_numeric(1u32, asset_id.clone())],
            Repeats::Indefinitely,
            account_id,
            TriggeringEventFilterBox::Data(DataEventFilter::Account(
                AccountEventFilter::new().only_events(AccountEventSet::Created),
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(Register::account(new_account_with_random_public_key(
        "asahi@wonderland".parse()?,
    )))?;

    test_client.submit_blocking(Register::account(new_account_with_random_public_key(
        "asahi@neverland".parse()?,
    )))?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

fn get_asset_value(client: &client::Client, asset_id: AssetId) -> Numeric {
    let asset = client.request(client::asset::by_id(asset_id)).unwrap();

    let AssetValue::Numeric(val) = *asset.value() else {
        panic!("Expected u32 asset value")
    };

    val
}
