//! Tests for transferring assets between accounts.
use integration_tests::{sandbox, sync::sync_after_submission};
use iroha::{
    blocking::Client,
    data_model::{
        Registered,
        account::{Account, AccountId},
        asset::{Asset, AssetDefinition},
        isi::InstructionBox,
        prelude::*,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::time::{Duration, Instant};
fn start_default(
    context: &'static str,
) -> Option<(sandbox::SerializedNetwork, tokio::runtime::Runtime)> {
    sandbox::start_network_blocking_or_skip(NetworkBuilder::new(), context).unwrap()
}
#[test]
// This test suite is also covered at the UI level in the iroha_cli tests
// in test_tranfer_assets.py
fn simulate_transfer_quantity() {
    let starting_amount = Quantity::from(200_u32);
    let amount_to_transfer = Quantity::from(20_u32);
    simulate_transfer(
        "simulate_transfer_quantity",
        starting_amount,
        &amount_to_transfer,
        |id, name| {
            AssetDefinition::numeric(
                id,
                name,
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        },
        Mint::asset_quantity,
        Transfer::asset_quantity,
    )
}
fn wait_for_asset_value(
    client: &Client,
    asset_definition_id: &AssetDefinitionId,
    account_id: &AccountId,
    expected_value: &Quantity,
    context: &str,
) {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "assets were not queried".to_owned();
    while Instant::now() < deadline {
        match client.client().query(FindAssets::new()).execute_all() {
            Ok(assets) => {
                let mut matching_values = Vec::new();
                for asset in assets {
                    if asset.id().definition() == asset_definition_id
                        && asset.id().account() == account_id
                    {
                        matching_values.push(asset.value().clone());
                    }
                }
                let present = matching_values.iter().any(|value| value == expected_value);
                last_observed = format!("matching_values={matching_values:?}");
                if present {
                    return;
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "timed out waiting for transferred asset after {context}; expected_value={expected_value:?}; last_observed={last_observed}"
    );
}
fn simulate_transfer(
    context: &'static str,
    starting_amount: Quantity,
    amount_to_transfer: &Quantity,
    asset_definition_ctr: impl FnOnce(
        AssetDefinitionId,
        String,
    ) -> <AssetDefinition as Registered>::With,
    mint_ctr: impl FnOnce(Quantity, AssetId) -> Mint<Quantity, Asset>,
    transfer_ctr: impl FnOnce(AssetId, Quantity, AccountId) -> Transfer<Asset, Quantity, Account>,
) {
    let Some((network, rt)) = start_default(context) else {
        return;
    };
    let iroha = network.client();
    let mut status = iroha.status().get().expect("failed to read initial status");
    let mut last_non_empty_height = status.blocks_non_empty;
    let (alice_id, mouse_id) = generate_two_ids();
    let create_mouse = create_mouse(mouse_id.clone());
    let (asset_definition_id, asset_definition_name) = asset_definition_id_for(context);
    let create_asset = Register::asset_definition(asset_definition_ctr(
        asset_definition_id.clone(),
        asset_definition_name,
    ));
    let mint_asset = mint_ctr(
        starting_amount,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );
    let instructions: [InstructionBox; 3] = [
        // create_alice.into(), We don't need to register Alice, because she is created in genesis
        create_mouse.into(),
        create_asset.into(),
        mint_asset.into(),
    ];
    iroha
        .submit_all(
            instructions,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("Failed to prepare state.");
    status = sync_after_submission(
        &network,
        &rt,
        &iroha,
        last_non_empty_height,
        "prepare transfer asset state",
    )
    .expect("failed to synchronize after transfer asset state preparation");
    last_non_empty_height = status.blocks_non_empty;
    //When
    let transfer_asset = transfer_ctr(
        AssetId::new(asset_definition_id.clone(), alice_id),
        amount_to_transfer.clone(),
        mouse_id.clone(),
    );
    iroha
        .submit(
            transfer_asset,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("Failed to transfer asset.");
    let _status = sync_after_submission(
        &network,
        &rt,
        &iroha,
        last_non_empty_height,
        "transfer asset",
    )
    .expect("failed to synchronize after asset transfer");
    let expected_value = amount_to_transfer.clone();
    wait_for_asset_value(
        &iroha,
        &asset_definition_id,
        &mouse_id,
        &expected_value,
        "asset transfer",
    );
}
fn generate_two_ids() -> (AccountId, AccountId) {
    let alice_id = ALICE_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    (alice_id, mouse_id)
}
fn create_mouse(mouse_id: AccountId) -> Register<Account> {
    Register::account(Account::new(mouse_id.clone()))
}
fn asset_definition_id_for(context: &str) -> (AssetDefinitionId, String) {
    let name = format!("camomile_{context}");
    let id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id should be valid"),
        name.parse().expect("asset name should be valid"),
    );
    (id, name)
}
#[test]
fn should_fail_if_asset_not_found() {
    let context = "should_fail_if_asset_not_found";
    let Some((network, _rt)) = start_default(context) else {
        return;
    };
    let iroha = network.client();
    let (alice_id, mouse_id) = generate_two_ids();
    let (asset_definition_id, asset_definition_name) = asset_definition_id_for(context);
    let create_asset_definition = Register::asset_definition(AssetDefinition::numeric(
        asset_definition_id.clone(),
        asset_definition_name,
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    ));
    let asset_id = AssetId::new(asset_definition_id.clone(), alice_id);
    let transfer_asset = Transfer::asset_quantity(asset_id.clone(), 20_u32, mouse_id.clone());
    let instructions: [InstructionBox; 2] = [create_asset_definition.into(), transfer_asset.into()];
    let result = iroha.submit_all(
        instructions,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .chain()
            .any(|e| e.to_string() == format!("Failed to find asset: `{asset_id}`"))
    );
}
