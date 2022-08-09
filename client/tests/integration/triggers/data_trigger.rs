#![allow(clippy::restriction)]

use eyre::Result;
use iroha_client::client;
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn must_execute_both_triggers() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_rose_1".parse()?,
        Action::new(
            Executable::from(vec![instruction.clone().into()]),
            Repeats::Indefinitely,
            account_id.clone(),
            FilterBox::Data(BySome(DataEntityFilter::ByAccount(BySome(
                AccountFilter::new(AcceptAll, BySome(AccountEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_rose_2".parse()?,
        Action::new(
            Executable::from(vec![instruction.into()]),
            Repeats::Indefinitely,
            account_id,
            FilterBox::Data(BySome(DataEntityFilter::ByDomain(BySome(
                DomainFilter::new(AcceptAll, BySome(DomainEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(RegisterBox::new(Account::new(
        "bunny@wonderland".parse()?,
        [],
    )))?;
    test_client.submit_blocking(RegisterBox::new(Domain::new("neverland".parse()?)))?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 2);

    Ok(())
}

#[test]
fn domain_scoped_trigger_must_be_executed_only_on_events_in_its_domain() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new()
        .with_query_judge(Box::new(AllowAll::new()))
        .start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let create_neverland_domain = RegisterBox::new(Domain::new("neverland".parse()?));

    let account_id: AccountId = "sapporo@neverland".parse()?;
    let create_sapporo_account = RegisterBox::new(Account::new(account_id.clone(), []));

    let asset_definition_id: AssetDefinitionId = "sakura#neverland".parse()?;
    let create_sakura_asset_definition =
        RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));

    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let create_sakura_asset =
        RegisterBox::new(Asset::new(asset_id.clone(), AssetValue::Quantity(0)));

    test_client.submit_all_blocking(vec![
        create_neverland_domain.into(),
        create_sapporo_account.into(),
        create_sakura_asset_definition.into(),
        create_sakura_asset.into(),
    ])?;

    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let register_trigger = RegisterBox::new(Trigger::new(
        "mint_sakura$neverland".parse()?,
        Action::new(
            Executable::from(vec![MintBox::new(1_u32, asset_id.clone()).into()]),
            Repeats::Indefinitely,
            account_id,
            FilterBox::Data(BySome(DataEntityFilter::ByAccount(BySome(
                AccountFilter::new(AcceptAll, BySome(AccountEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(RegisterBox::new(Account::new(
        "asahi@wonderland".parse()?,
        [],
    )))?;

    test_client.submit_blocking(RegisterBox::new(Account::new(
        "asahi@neverland".parse()?,
        [],
    )))?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

fn get_asset_value(client: &mut client::Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}
