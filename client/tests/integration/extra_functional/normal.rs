use iroha::{
    client,
    data_model::{asset::AssetDefinitionId, parameter::BlockParameter, prelude::*},
};
use nonzero_ext::nonzero;
use test_network::*;

#[test]
fn tranasctions_should_be_applied() {
    let (_rt, network, iroha) = NetworkBuilder::new(4, Some(11_300)).create_with_runtime();
    wait_for_genesis_committed(&network.clients(), 0);
    iroha
        .submit_blocking(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )))
        .unwrap();

    let domain_id = "and".parse::<DomainId>().unwrap();
    let account_id = "ed01201F803CB23B1AAFB958368DF2F67CB78A2D1DFB47FFFC3133718F165F54DFF677@and"
        .parse::<AccountId>()
        .unwrap();
    let asset_definition_id = "MAY#and".parse::<AssetDefinitionId>().unwrap();
    let asset_id =
        "MAY##ed01201F803CB23B1AAFB958368DF2F67CB78A2D1DFB47FFFC3133718F165F54DFF677@and"
            .parse()
            .unwrap();

    let create_domain = Register::domain(Domain::new(domain_id));
    iroha.submit_blocking(create_domain).unwrap();

    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    iroha.submit_blocking(create_asset).unwrap();

    let create_account = Register::account(Account::new(account_id.clone()));
    iroha.submit_blocking(create_account).unwrap();

    let mint_asset = Mint::asset_numeric(
        numeric!(57_787_013_353_273_097_936_105_299_296),
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    iroha.submit_blocking(mint_asset).unwrap();

    let mint_asset =
        Mint::asset_numeric(numeric!(1), AssetId::new(asset_definition_id, account_id));
    iroha.submit_blocking(mint_asset).unwrap();

    iroha
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();
}
