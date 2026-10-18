//! Account query coverage for Torii.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::collections::HashSet;
#[test]
fn find_accounts_with_asset() -> Result<()> {
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
        super::query_network_builder(),
        stringify!(find_accounts_with_asset),
    )
    .unwrap() else {
        return Ok(());
    };
    let test_client = super::query_client(&network);
    let result: Result<()> = (|| {
        // Registering new asset definition
        let definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            "test_coin".parse().expect("Valid"),
        );
        let asset_definition = {
            let __asset_definition_id = definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "test_coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        };
        test_client.submit(
            Register::asset_definition(asset_definition.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        // Checking results before all
        let received_asset_definition = test_client
            .client()
            .query(FindAssetDefinitions::new())
            .execute_all()?
            .into_iter()
            .find(|asset_definition| asset_definition.id() == &definition_id)
            .expect("asset definition should exist");
        assert_eq!(received_asset_definition.id(), asset_definition.id());
        let accounts: [AccountId; 5] = [
            ALICE_ID.clone(),
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
        ];
        // Registering accounts
        let register_accounts = accounts
            .iter()
            .skip(1) // Alice has already been registered in genesis
            .cloned()
            .map(|account_id| Register::account(Account::new(account_id.clone())))
            .collect::<Vec<_>>();
        test_client.submit_all(
            register_accounts,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let mint_asset = accounts
            .iter()
            .cloned()
            .map(|account_id| AssetId::new(definition_id.clone(), account_id))
            .map(|asset_id| Mint::asset_quantity(1u32, asset_id))
            .collect::<Vec<_>>();
        test_client.submit_all(
            mint_asset,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let accounts = HashSet::from(accounts);
        // Checking results
        let received_asset_definition = test_client
            .client()
            .query(FindAssetDefinitions::new())
            .execute_all()?
            .into_iter()
            .find(|asset_definition| asset_definition.id() == &definition_id)
            .expect("asset definition should exist");
        assert_eq!(received_asset_definition.id(), asset_definition.id());
        assert_eq!(received_asset_definition.spec(), NumericSpec::default());
        let found_accounts = test_client
            .client()
            .query(FindAccountsWithAsset::new(definition_id))
            .execute_all()?;
        let found_ids = found_accounts
            .into_iter()
            .map(|account| account.id().clone())
            .collect::<HashSet<_>>();
        assert_eq!(found_ids, accounts);
        Ok(())
    })();
    if sandbox::handle_result(result, stringify!(find_accounts_with_asset))?.is_none() {
        return Ok(());
    }
    Ok(())
}
