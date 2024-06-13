use std::num::NonZeroU32;

use iroha::client::{self, Client};
use iroha_config::parameters::actual::Root as Config;
use iroha_data_model::{asset::AssetDefinitionId, prelude::*};
use test_network::*;
use tokio::runtime::Runtime;

#[test]
fn tranasctions_should_be_applied() {
    let rt = Runtime::test();
    let (network, iroha) = rt.block_on(async {
        let mut configuration = Config::test();
        configuration.chain_wide.max_transactions_in_block = NonZeroU32::new(1).unwrap();
        let network = Network::new_with_offline_peers(Some(configuration), 4, 0, Some(11_300))
            .await
            .unwrap();
        let iroha = Client::test(&network.genesis.api_address);

        (network, iroha)
    });
    wait_for_genesis_committed(&network.clients(), 0);

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

    iroha.request(client::asset::by_id(asset_id)).unwrap();
}
