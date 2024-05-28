use eyre::Result;
use iroha_client::data_model::prelude::*;
use iroha_data_model::transaction::error::TransactionRejectionReason;
use serde_json::json;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID, BOB_ID};

#[test]
fn domain_owner_domain_permissions() -> Result<()> {
    let chain_id = ChainId::from("0");

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_080).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let kingdom_id: DomainId = "kingdom".parse()?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = "coin#kingdom".parse()?;
    let coin = AssetDefinition::numeric(coin_id.clone());

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    test_client.submit_blocking(Register::domain(kingdom))?;

    let bob = Account::new(bob_id.clone());
    test_client.submit_blocking(Register::account(bob))?;

    // Asset definitions can't be registered by "bob@kingdom" by default
    let transaction = TransactionBuilder::new(chain_id.clone(), bob_id.clone())
        .with_instructions([Register::asset_definition(coin.clone())])
        .sign(&bob_keypair);
    let err = test_client
        .submit_transaction_blocking(&transaction)
        .expect_err("Tx should fail due to permissions");

    let rejection_reason = err
        .downcast_ref::<TransactionRejectionReason>()
        .unwrap_or_else(|| panic!("Error {err} is not TransactionRejectionReason"));

    assert!(matches!(
        rejection_reason,
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
    ));

    // "alice@wonderland" owns the domain and can register AssetDefinitions by default as domain owner
    test_client.submit_blocking(Register::asset_definition(coin.clone()))?;
    test_client.submit_blocking(Unregister::asset_definition(coin_id))?;

    // Granting a respective token also allows "bob@kingdom" to do so
    let token = Permission::new(
        "CanRegisterAssetDefinitionInDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    let transaction = TransactionBuilder::new(chain_id, bob_id.clone())
        .with_instructions([Register::asset_definition(coin)])
        .sign(&bob_keypair);
    test_client.submit_transaction_blocking(&transaction)?;
    test_client.submit_blocking(Revoke::permission(token, bob_id.clone()))?;

    // check that "alice@wonderland" as owner of domain can edit metadata in her domain
    let key: Name = "key".parse()?;
    let value: Name = "value".parse()?;
    test_client.submit_blocking(SetKeyValue::domain(kingdom_id.clone(), key.clone(), value))?;
    test_client.submit_blocking(RemoveKeyValue::domain(kingdom_id.clone(), key))?;

    // check that "alice@wonderland" as owner of domain can grant and revoke domain related permission tokens
    let token = Permission::new(
        "CanUnregisterDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    test_client.submit_blocking(Revoke::permission(token, bob_id))?;

    // check that "alice@wonderland" as owner of domain can unregister her domain
    test_client.submit_blocking(Unregister::domain(kingdom_id))?;

    Ok(())
}

#[test]
fn domain_owner_account_permissions() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_075).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let kingdom_id: DomainId = "kingdom".parse()?;
    let (mad_hatter_id, _mad_hatter_keypair) = gen_account_in("kingdom");

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id);
    test_client.submit_blocking(Register::domain(kingdom))?;

    let mad_hatter = Account::new(mad_hatter_id.clone());
    test_client.submit_blocking(Register::account(mad_hatter))?;

    // check that "alice@wonderland" as owner of domain can edit metadata of account in her domain
    let key: Name = "key".parse()?;
    let value: Name = "value".parse()?;
    test_client.submit_blocking(SetKeyValue::account(
        mad_hatter_id.clone(),
        key.clone(),
        value,
    ))?;
    test_client.submit_blocking(RemoveKeyValue::account(mad_hatter_id.clone(), key))?;

    // check that "alice@wonderland" as owner of domain can grant and revoke account related permission tokens in her domain
    let bob_id = BOB_ID.clone();
    let token = Permission::new(
        "CanUnregisterAccount".parse().unwrap(),
        json!({ "account_id": mad_hatter_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    test_client.submit_blocking(Revoke::permission(token, bob_id))?;

    // check that "alice@wonderland" as owner of domain can unregister accounts in her domain
    test_client.submit_blocking(Unregister::account(mad_hatter_id))?;

    Ok(())
}

#[test]
fn domain_owner_asset_definition_permissions() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_085).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let chain_id = ChainId::from("0");
    let kingdom_id: DomainId = "kingdom".parse()?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let (rabbit_id, _rabbit_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = "coin#kingdom".parse()?;

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    test_client.submit_blocking(Register::domain(kingdom))?;

    let bob = Account::new(bob_id.clone());
    test_client.submit_blocking(Register::account(bob))?;

    let rabbit = Account::new(rabbit_id.clone());
    test_client.submit_blocking(Register::account(rabbit))?;

    // Grant permission to register asset definitions to "bob@kingdom"
    let token = Permission::new(
        "CanRegisterAssetDefinitionInDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    test_client.submit_blocking(Grant::permission(token, bob_id.clone()))?;

    // register asset definitions by "bob@kingdom" so he is owner of it
    let coin = AssetDefinition::numeric(coin_id.clone());
    let transaction = TransactionBuilder::new(chain_id, bob_id.clone())
        .with_instructions([Register::asset_definition(coin)])
        .sign(&bob_keypair);
    test_client.submit_transaction_blocking(&transaction)?;

    // check that "alice@wonderland" as owner of domain can transfer asset definitions in her domain
    test_client.submit_blocking(Transfer::asset_definition(
        bob_id.clone(),
        coin_id.clone(),
        rabbit_id,
    ))?;

    // check that "alice@wonderland" as owner of domain can edit metadata of asset definition in her domain
    let key: Name = "key".parse()?;
    let value: Name = "value".parse()?;
    test_client.submit_blocking(SetKeyValue::asset_definition(
        coin_id.clone(),
        key.clone(),
        value,
    ))?;
    test_client.submit_blocking(RemoveKeyValue::asset_definition(coin_id.clone(), key))?;

    // check that "alice@wonderland" as owner of domain can grant and revoke asset definition related permission tokens in her domain
    let token = Permission::new(
        "CanUnregisterAssetDefinition".parse().unwrap(),
        json!({ "asset_definition_id": coin_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    test_client.submit_blocking(Revoke::permission(token, bob_id))?;

    // check that "alice@wonderland" as owner of domain can unregister asset definitions in her domain
    test_client.submit_blocking(Unregister::asset_definition(coin_id))?;

    Ok(())
}

#[test]
fn domain_owner_asset_permissions() -> Result<()> {
    let chain_id = ChainId::from("0");

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_090).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = "kingdom".parse()?;
    let (bob_id, bob_keypair) = gen_account_in("kingdom");
    let coin_id: AssetDefinitionId = "coin#kingdom".parse()?;
    let store_id: AssetDefinitionId = "store#kingdom".parse()?;

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    test_client.submit_blocking(Register::domain(kingdom))?;

    let bob = Account::new(bob_id.clone());
    test_client.submit_blocking(Register::account(bob))?;

    // Grant permission to register asset definitions to "bob@kingdom"
    let token = Permission::new(
        "CanRegisterAssetDefinitionInDomain".parse().unwrap(),
        json!({ "domain_id": kingdom_id }),
    );
    test_client.submit_blocking(Grant::permission(token, bob_id.clone()))?;

    // register asset definitions by "bob@kingdom" so he is owner of it
    let coin = AssetDefinition::numeric(coin_id.clone());
    let store = AssetDefinition::store(store_id.clone());
    let transaction = TransactionBuilder::new(chain_id, bob_id.clone())
        .with_instructions([
            Register::asset_definition(coin),
            Register::asset_definition(store),
        ])
        .sign(&bob_keypair);
    test_client.submit_transaction_blocking(&transaction)?;

    // check that "alice@wonderland" as owner of domain can register and unregister assets in her domain
    let bob_coin_id = AssetId::new(coin_id, bob_id.clone());
    let bob_coin = Asset::new(bob_coin_id.clone(), 30_u32);
    test_client.submit_blocking(Register::asset(bob_coin))?;
    test_client.submit_blocking(Unregister::asset(bob_coin_id.clone()))?;

    // check that "alice@wonderland" as owner of domain can burn, mint and transfer assets in her domain
    test_client.submit_blocking(Mint::asset_numeric(10u32, bob_coin_id.clone()))?;
    test_client.submit_blocking(Burn::asset_numeric(5u32, bob_coin_id.clone()))?;
    test_client.submit_blocking(Transfer::asset_numeric(bob_coin_id, 5u32, alice_id))?;

    // check that "alice@wonderland" as owner of domain can edit metadata of store asset in her domain
    let key: Name = "key".parse()?;
    let value: Name = "value".parse()?;
    let bob_store_id = AssetId::new(store_id, bob_id.clone());
    test_client.submit_blocking(SetKeyValue::asset(bob_store_id.clone(), key.clone(), value))?;
    test_client.submit_blocking(RemoveKeyValue::asset(bob_store_id.clone(), key))?;

    // check that "alice@wonderland" as owner of domain can grant and revoke asset related permission tokens in her domain
    let token = Permission::new(
        "CanUnregisterUserAsset".parse().unwrap(),
        json!({ "asset_id": bob_store_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    test_client.submit_blocking(Revoke::permission(token, bob_id))?;

    Ok(())
}

#[test]
fn domain_owner_trigger_permissions() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_095).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = "kingdom".parse()?;
    let (bob_id, _bob_keypair) = gen_account_in("kingdom");

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id);
    test_client.submit_blocking(Register::domain(kingdom))?;

    let bob = Account::new(bob_id.clone());
    test_client.submit_blocking(Register::account(bob))?;

    let asset_definition_id = "rose#wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, alice_id.clone());
    let trigger_id: TriggerId = "trigger$kingdom".parse()?;

    let trigger_instructions = vec![Mint::asset_numeric(1u32, asset_id)];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::from(2_u32),
            bob_id.clone(),
            ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // check that "alice@wonderland" as owner of domain can edit repetitions of triggers in her domain
    test_client.submit_blocking(Mint::trigger_repetitions(1_u32, trigger_id.clone()))?;
    test_client.submit_blocking(Burn::trigger_repetitions(1_u32, trigger_id.clone()))?;

    // check that "alice@wonderland" as owner of domain can call triggers in her domain
    let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
    let _result = test_client.submit_blocking(execute_trigger)?;

    // check that "alice@wonderland" as owner of domain can grant and revoke trigger related permission tokens in her domain
    let token = Permission::new(
        "CanUnregisterUserTrigger".parse().unwrap(),
        json!({ "account_id": bob_id }),
    );
    test_client.submit_blocking(Grant::permission(token.clone(), bob_id.clone()))?;
    test_client.submit_blocking(Revoke::permission(token, bob_id))?;

    // check that "alice@wonderland" as owner of domain can unregister triggers in her domain
    test_client.submit_blocking(Unregister::trigger(trigger_id))?;

    Ok(())
}

#[ignore = "migrated to client cli python tests"]
#[test]
fn domain_owner_transfer() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_100).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let kingdom_id: DomainId = "kingdom".parse()?;
    let (bob_id, _bob_keypair) = gen_account_in("kingdom");

    // "alice@wonderland" is owner of "kingdom" domain
    let kingdom = Domain::new(kingdom_id.clone());
    test_client.submit_blocking(Register::domain(kingdom))?;

    let bob = Account::new(bob_id.clone());
    test_client.submit_blocking(Register::account(bob))?;

    let domain = test_client.request(FindDomainById::new(kingdom_id.clone()))?;
    assert_eq!(domain.owned_by(), &alice_id);

    test_client
        .submit_blocking(Transfer::domain(
            alice_id,
            kingdom_id.clone(),
            bob_id.clone(),
        ))
        .expect("Failed to submit transaction");

    let domain = test_client.request(FindDomainById::new(kingdom_id))?;
    assert_eq!(domain.owned_by(), &bob_id);

    Ok(())
}
