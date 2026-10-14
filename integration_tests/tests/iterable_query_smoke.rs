//! Torii iterable queries smoke test: ensure genesis assets are discoverable
//! and batching works end-to-end via the HTTP `/query` path.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_model_base::domain::DomainId;
// use iroha_data_model::query::builder::QueryBuilderExt as _; // not used in this smoke test
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::ALICE_ID;
use reqwest::Client as HttpClient;
#[test]
fn find_genesis_assets_via_torii_iterable() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(find_genesis_assets_via_torii_iterable),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    // Execute a simple iterable query; default fetch size is fine for smoke test.
    let assets = client.client().query(FindAssets::new()).execute_all()?;
    assert!(
        !assets.is_empty(),
        "expected at least one asset from genesis"
    );
    // Verify the well-known genesis asset exists with expected quantity.
    let asset_id = AssetId::new(
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        ),
        ALICE_ID.clone(),
    );
    let rose = assets
        .into_iter()
        .find(|a| a.id() == &asset_id)
        .expect("genesis rose asset not found");
    assert_eq!(*rose.value(), Quantity::from(13_u32));
    let http = HttpClient::new();
    let peer = match network.peers().first() {
        Some(p) => p,
        None => return Ok(()),
    };
    // GET /v1/accounts?limit=1 should return genesis accounts (non-empty items, accurate total)
    let accounts_url = format!(
        "{}/v1/accounts?limit=1&include_total=true",
        peer.torii_url()
    );
    let accounts_body = rt.block_on(async {
        http.get(&accounts_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    })?;
    let accounts_json: norito::json::Value = norito::json::from_str(&accounts_body)?;
    let accounts_total = accounts_json
        .get("total")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or_default();
    let account_items = accounts_json
        .get("items")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        accounts_total > 0,
        "expected non-zero accounts total via HTTP"
    );
    assert!(
        !account_items.is_empty(),
        "expected accounts payload via HTTP"
    );
    // GET /v1/accounts/{alice}/assets?limit=1 should list genesis balances
    let alice_assets_url = format!(
        "{}/v1/accounts/{}/assets?limit=1&include_total=true",
        peer.torii_url(),
        &*ALICE_ID
    );
    let alice_assets_body = rt.block_on(async {
        http.get(&alice_assets_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    })?;
    let alice_assets_json: norito::json::Value = norito::json::from_str(&alice_assets_body)?;
    let alice_total = alice_assets_json
        .get("total")
        .and_then(norito::json::Value::as_u64)
        .unwrap_or_default();
    let alice_items = alice_assets_json
        .get("items")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(alice_total > 0, "expected Alice assets via HTTP");
    assert!(
        !alice_items.is_empty(),
        "expected Alice asset list via HTTP"
    );
    Ok(())
}
