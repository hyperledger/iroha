use eyre::Result;
use iroha_client::{client, data_model::prelude::*};
use test_network::*;

#[test]
fn must_execute_both_triggers() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_650).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let prev_value = get_asset_value(&test_client, asset_id.clone())?;

    let instruction = MintExpr::new(1_u32, asset_id.clone());
    let register_trigger = RegisterExpr::new(Trigger::new(
        "mint_rose_1".parse()?,
        Action::new(
            [instruction.clone()],
            Repeats::Indefinitely,
            account_id.clone(),
            TriggeringFilterBox::Data(BySome(DataEntityFilter::ByAccount(BySome(
                AccountFilter::new(AcceptAll, BySome(AccountEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let register_trigger = RegisterExpr::new(Trigger::new(
        "mint_rose_2".parse()?,
        Action::new(
            [instruction],
            Repeats::Indefinitely,
            account_id,
            TriggeringFilterBox::Data(BySome(DataEntityFilter::ByDomain(BySome(
                DomainFilter::new(AcceptAll, BySome(DomainEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(RegisterExpr::new(Account::new(
        "bunny@wonderland".parse()?,
        [],
    )))?;
    test_client.submit_blocking(RegisterExpr::new(Domain::new("neverland".parse()?)))?;

    let new_value = get_asset_value(&test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 2);

    Ok(())
}

#[test]
fn domain_scoped_trigger_must_be_executed_only_on_events_in_its_domain() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_655).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let create_neverland_domain = RegisterExpr::new(Domain::new("neverland".parse()?));

    let account_id: AccountId = "sapporo@neverland".parse()?;
    let create_sapporo_account = RegisterExpr::new(Account::new(account_id.clone(), []));

    let asset_definition_id: AssetDefinitionId = "sakura#neverland".parse()?;
    let create_sakura_asset_definition =
        RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));

    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let create_sakura_asset =
        RegisterExpr::new(Asset::new(asset_id.clone(), AssetValue::Quantity(0)));

    test_client.submit_all_blocking([
        create_neverland_domain,
        create_sapporo_account,
        create_sakura_asset_definition,
        create_sakura_asset,
    ])?;

    let prev_value = get_asset_value(&test_client, asset_id.clone())?;

    let register_trigger = RegisterExpr::new(Trigger::new(
        "mint_sakura$neverland".parse()?,
        Action::new(
            [MintExpr::new(1_u32, asset_id.clone())],
            Repeats::Indefinitely,
            account_id,
            TriggeringFilterBox::Data(BySome(DataEntityFilter::ByAccount(BySome(
                AccountFilter::new(AcceptAll, BySome(AccountEventFilter::ByCreated)),
            )))),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    test_client.submit_blocking(RegisterExpr::new(Account::new(
        "asahi@wonderland".parse()?,
        [],
    )))?;

    test_client.submit_blocking(RegisterExpr::new(Account::new(
        "asahi@neverland".parse()?,
        [],
    )))?;

    let new_value = get_asset_value(&test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

fn get_asset_value(client: &client::Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}
