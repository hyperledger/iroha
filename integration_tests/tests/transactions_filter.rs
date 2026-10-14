//! JSON filter DSL server-side predicates test for transactions endpoint.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_network::NetworkBuilder;
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn post_transactions_query_filters_by_authority_and_timestamp() -> Result<()> {
    // Start network and submit a simple tx as Alice
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new(),
        stringify!(post_transactions_query_filters_by_authority_and_timestamp),
    )
    .await?
    else {
        return Ok(());
    };
    let client = network.client();
    let alice_id_str = format!("{}", *iroha_test_samples::ALICE_ID);
    // Submit a tx (registering a dummy asset def) to ensure at least one Alice-authored tx exists
    tokio::task::spawn_blocking({
        let client = client.clone();
        move || {
            let _ = client.submit(
                Register::asset_definition({
                    let __asset_definition_id = AssetDefinitionId::derive_from_components(
                        DomainId::try_new("wonderland", "universal").unwrap(),
                        "txfilter".parse().unwrap(),
                    );
                    AssetDefinition::numeric(
                        __asset_definition_id.clone(),
                        "txfilter".to_owned(),
                        iroha_data_model::asset::AssetBalancePolicy::Global,
                        None,
                    )
                }),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            );
        }
    })
    .await?;
    network.ensure_blocks(2).await?;
    // Build filter: authority == ALICE_ID (canonical encoded literal) AND timestamp_ms >= 0
    let eq_filter = norito::json::object([
        (
            "op",
            norito::json::to_value(&"eq").expect("serialize eq op"),
        ),
        (
            "args",
            norito::json::array([
                norito::json::to_value(&"authority").expect("serialize authority key"),
                norito::json::to_value(&alice_id_str).expect("serialize authority value"),
            ])
            .expect("serialize eq args"),
        ),
    ])
    .expect("serialize eq filter");
    let gte_filter = norito::json::object([
        (
            "op",
            norito::json::to_value(&"gte").expect("serialize gte op"),
        ),
        (
            "args",
            norito::json::array([
                norito::json::to_value(&"timestamp_ms").expect("serialize timestamp key"),
                norito::json::to_value(&0).expect("serialize timestamp value"),
            ])
            .expect("serialize gte args"),
        ),
    ])
    .expect("serialize gte filter");
    let filter = norito::json::object([
        (
            "op",
            norito::json::to_value(&"and").expect("serialize and op"),
        ),
        (
            "args",
            norito::json::array([eq_filter, gte_filter]).expect("serialize filter args"),
        ),
    ])
    .expect("serialize filter envelope");
    let env = norito::json::object([
        ("filter", filter),
        (
            "limit",
            norito::json::to_value(&100).expect("serialize limit"),
        ),
    ])
    .expect("serialize request envelope");
    // POST to the endpoint
    let url = client
        .client()
        .endpoint()
        .join(&format!("/v1/accounts/{alice_id_str}/transactions/query"))
        .unwrap();
    let http = integration_tests::http::client();
    let resp = http
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(norito::json::to_json(&env).unwrap())
        .send()
        .await?;
    assert!(resp.status().is_success());
    let txt = resp.text().await?;
    let body: norito::json::Value = norito::json::from_str(&txt)?;
    let items = match &body {
        norito::json::Value::Object(m) => m
            .get("items")
            .and_then(|v| match v {
                norito::json::Value::Array(a) => Some(a.clone()),
                _ => None,
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    assert!(!items.is_empty(), "expected some transactions for Alice");
    for it in items {
        let auth: String = match it {
            norito::json::Value::Object(m) => m
                .get("authority")
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string)
                .unwrap_or_default(),
            _ => String::new(),
        };
        assert_eq!(auth, alice_id_str);
    }
    Ok(())
}
