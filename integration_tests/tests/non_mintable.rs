//! Integration tests covering single-mint asset semantics.
use eyre::{Result, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{isi::InstructionBox, prelude::*},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use std::time::{Duration, Instant};
fn wait_for_asset_value(
    client: &Client,
    asset_id: &AssetId,
    expected_value: &Quantity,
    context: &str,
) -> Result<Asset> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "asset was not queried".to_owned();
    while Instant::now() < deadline {
        match client
            .client()
            .query_single(FindAssetById::new(asset_id.clone()))
        {
            Ok(asset) => {
                last_observed = format!("value={:?}", asset.value());
                if asset.value() == expected_value {
                    return Ok(asset);
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(eyre!(
        "timed out waiting for asset after {context}; asset_id={asset_id}; expected_value={expected_value:?}; last_observed={last_observed}"
    ))
}
#[test]
fn non_mintable_asset_minting_rules() -> Result<()> {
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new().with_block_cadence(std::time::Duration::from_secs(2)),
        stringify!(non_mintable_asset_minting_rules),
    )?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let account_id = ALICE_ID.clone();
    // Case 1: mintable once can be minted once, but not twice.
    {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            "xor_once".parse().expect("Valid"),
        );
        let create_asset = Register::asset_definition(
            {
                let __asset_definition_id = asset_definition_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id,
                    "xor_once".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            }
            .mintable_once(),
        );
        let metadata = Metadata::default();
        let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
        let mint = Mint::asset_quantity(200_u32, asset_id.clone());
        let instructions: [InstructionBox; 2] = [create_asset.into(), mint.clone().into()];
        let tx = {
            let account = test_client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    instructions,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    metadata,
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        test_client.submit_transaction_and_wait(&tx)?;
        wait_for_asset_value(
            &test_client,
            &asset_id,
            &Quantity::from(200_u32),
            "first mint",
        )?;
        assert!(
            test_client
                .submit_all(
                    [mint],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err()
        );
    }
    // Case 2: if registered with non-zero value, it cannot be minted again.
    {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("Valid"),
            "xor_seeded".parse().expect("Valid"),
        );
        let create_asset = Register::asset_definition(
            {
                let __asset_definition_id = asset_definition_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id,
                    "xor_seeded".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            }
            .mintable_once(),
        );
        let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
        let register_asset = Mint::asset_quantity(1_u32, asset_id.clone());
        test_client.submit_all::<InstructionBox>(
            [create_asset.into(), register_asset.clone().into()],
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        wait_for_asset_value(&test_client, &asset_id, &Quantity::one(), "seeded mint")?;
        assert!(
            test_client
                .submit(
                    register_asset,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err()
        );
        let mint = Mint::asset_quantity(1u32, asset_id);
        assert!(
            test_client
                .submit(
                    mint,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None)
                )
                .is_err()
        );
    }
    Ok(())
}
