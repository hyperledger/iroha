#![allow(clippy::restriction)]

use std::thread;

use eyre::Result;
use iroha_client::client::asset;
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use test_network::*;

use crate::integration::Configuration;

#[test]
fn find_asset_register_tx_returns_the_right_hash() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_690).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();
    thread::sleep(pipeline_time * 2);

    let domain_id: DomainId = "domain".parse()?;
    let create_domain = RegisterBox::new(Domain::new(domain_id.clone()));
    test_client.submit_blocking(create_domain)?;

    let account_id: AccountId = "account@domain".parse()?;
    let (public_key, _) = KeyPair::generate()?.into();
    let account = Account::new(account_id, [public_key]);
    let create_account = RegisterBox::new(account);
    test_client.submit_blocking(create_account)?;

    let asset_definition_id_1 = AssetDefinitionId::new("xor".parse()?, domain_id.clone());
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id_1.clone()));
    let asset_reg_tx_hash_1 = test_client.submit_blocking(create_asset)?;

    let asset_definition_id_2 = AssetDefinitionId::new("val".parse()?, domain_id);
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id_2.clone()));
    let asset_reg_tx_hash_2 = test_client.submit_blocking(create_asset)?;

    let query_result_1 =
        test_client.request(asset::register_tx_by_definition_id(asset_definition_id_1))?;
    let query_result_2 =
        test_client.request(asset::register_tx_by_definition_id(asset_definition_id_2))?;

    assert_eq!(query_result_1, asset_reg_tx_hash_1.into());
    assert_eq!(query_result_2, asset_reg_tx_hash_2.into());

    Ok(())
}
