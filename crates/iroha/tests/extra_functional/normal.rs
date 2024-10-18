use eyre::Result;
use iroha::{
    client,
    data_model::{asset::AssetDefinitionId, parameter::BlockParameter, prelude::*},
};
use iroha_test_network::*;
use nonzero_ext::nonzero;

#[test]
fn transactions_should_be_applied() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().with_peers(4).start_blocking()?;
    let iroha = network.client();
    iroha.submit_blocking(SetParameter::new(Parameter::Block(
        BlockParameter::MaxTransactions(nonzero!(1_u64)),
    )))?;

    let domain_id = "and".parse::<DomainId>()?;
    let account_id = "ed01201F803CB23B1AAFB958368DF2F67CB78A2D1DFB47FFFC3133718F165F54DFF677@and"
        .parse::<AccountId>()?;
    let asset_definition_id = "MAY#and".parse::<AssetDefinitionId>()?;
    let asset_id =
        "MAY##ed01201F803CB23B1AAFB958368DF2F67CB78A2D1DFB47FFFC3133718F165F54DFF677@and"
            .parse()?;

    let create_domain = Register::domain(Domain::new(domain_id));
    iroha.submit_blocking(create_domain)?;

    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    iroha.submit_blocking(create_asset)?;

    let create_account = Register::account(Account::new(account_id.clone()));
    iroha.submit_blocking(create_account)?;

    let mint_asset = Mint::asset_numeric(
        numeric!(57_787_013_353_273_097_936_105_299_296),
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    iroha.submit_blocking(mint_asset)?;

    let mint_asset =
        Mint::asset_numeric(numeric!(1), AssetId::new(asset_definition_id, account_id));
    iroha.submit_blocking(mint_asset)?;

    iroha
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()?;

    Ok(())
}
